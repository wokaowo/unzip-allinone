package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

const (
	defaultScanDepth = 5
	maxScanDepth     = 12
	// maxNestedDepth bounds recursive extraction of archives found inside an
	// extracted archive (e.g. a WIM whose payload is a 001/002 split set).
	maxNestedDepth = 5
)

var supportedSingleExtensions = map[string]struct{}{
	".zip": {},
	".7z":  {},
	".wim": {},
	".esd": {},
	".swm": {},
}

type app struct {
	sevenZip string
	jobs     *jobStore
}

type directoryEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type directoryResponse struct {
	Path   string           `json:"path"`
	Parent string           `json:"parent,omitempty"`
	Dirs   []directoryEntry `json:"dirs"`
}

type scanRequest struct {
	Root          string `json:"root"`
	Depth         int    `json:"depth"`
	IncludeHidden bool   `json:"includeHidden"`
}

type archiveInfo struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Path            string `json:"path"`
	Directory       string `json:"directory"`
	RelativeFile    string `json:"relativeFile"`
	RelativeDir     string `json:"relativeDir"`
	Format          string `json:"format"`
	DefaultPassword string `json:"defaultPassword"`
	PartCount       int    `json:"partCount"`
	TotalBytes      int64  `json:"totalBytes"`
}

type scanResponse struct {
	Root          string        `json:"root"`
	Depth         int           `json:"depth"`
	IncludeHidden bool          `json:"includeHidden"`
	Archives      []archiveInfo `json:"archives"`
}

type extractRequest struct {
	Root           string           `json:"root"`
	DeleteOriginal bool             `json:"deleteOriginal"`
	ConflictPolicy string           `json:"conflictPolicy"`
	Archives       []archiveExtract `json:"archives"`
}

type archiveExtract struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Password string `json:"password"`
}

type extractResponse struct {
	JobID string `json:"jobId"`
}

type jobStore struct {
	mu   sync.Mutex
	jobs map[string]*job
}

type job struct {
	id     string
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	events []jobEvent
	// latest holds the most recent event per archive id (and "" for job-level).
	// Used so reconnecting clients can rebuild state without replaying thousands of progress ticks.
	latest   map[string]jobEvent
	done     bool
	subs     map[chan jobEvent]struct{}
	started  time.Time
	finished time.Time
	root     string
	total    int
}

type jobEvent struct {
	Type           string `json:"type"`
	JobID          string `json:"jobId"`
	Status         string `json:"status,omitempty"`
	Message        string `json:"message,omitempty"`
	ArchiveID      string `json:"archiveId,omitempty"`
	ArchiveName    string `json:"archiveName,omitempty"`
	Path           string `json:"path,omitempty"`
	Index          int    `json:"index,omitempty"`
	Total          int    `json:"total,omitempty"`
	Percent        int    `json:"percent,omitempty"`
	Error          string `json:"error,omitempty"`
	SuccessCount   int    `json:"successCount,omitempty"`
	FailedCount    int    `json:"failedCount,omitempty"`
	WarningCount   int    `json:"warningCount,omitempty"`
	DeleteOriginal bool   `json:"deleteOriginal,omitempty"`
	ConflictPolicy string `json:"conflictPolicy,omitempty"`
	// Phase marks which stage of a two-phase extraction the progress refers to:
	// "outer" for the container archive, "nested" for split volumes inside it.
	Phase string `json:"phase,omitempty"`
	// PasswordDecoded is set on archive start when slang substitution changed the password.
	PasswordDecoded string `json:"passwordDecoded,omitempty"`
	// BytesDone/BytesTotal/SpeedBps let the UI show throughput and a real ETA
	// instead of guessing from percent alone.
	BytesDone  int64   `json:"bytesDone,omitempty"`
	BytesTotal int64   `json:"bytesTotal,omitempty"`
	SpeedBps   float64 `json:"speedBps,omitempty"`
	Current    string  `json:"current,omitempty"`
	Running    int     `json:"running,omitempty"`
	Finished   int     `json:"finished,omitempty"`
}

type jobSnapshot struct {
	ID       string     `json:"id"`
	Done     bool       `json:"done"`
	Root     string     `json:"root,omitempty"`
	Total    int        `json:"total"`
	Started  time.Time  `json:"started"`
	Finished *time.Time `json:"finished,omitempty"`
	Status   string     `json:"status"`
	Message  string     `json:"message,omitempty"`
	// Events is a compact rebuild: job event + latest per-archive event (not full history).
	Events []jobEvent `json:"events"`
}

type jobListResponse struct {
	Jobs []jobSnapshot `json:"jobs"`
}

func main() {
	sevenZip, err := find7za()
	if err != nil {
		log.Fatalf("7za not found: %v", err)
	}

	a := &app{
		sevenZip: sevenZip,
		jobs:     &jobStore{jobs: map[string]*job{}},
	}

	staticFS := mustStaticSubtree()
	fileServer := http.FileServer(http.FS(staticFS))

	mux := http.NewServeMux()
	// no-cache so UI updates ship immediately after binary upgrade
	mux.Handle("/", noCache(fileServer))
	mux.HandleFunc("/api/dirs", a.handleDirs)
	mux.HandleFunc("/api/scan", a.handleScan)
	mux.HandleFunc("/api/extract", a.handleExtract)
	mux.HandleFunc("/api/jobs", a.handleJobs)
	mux.HandleFunc("/api/jobs/", a.handleJob)
	mux.HandleFunc("/api/decode-password", a.handleDecodePassword)

	addr := "0.0.0.0:42547"
	log.Printf("unzip-allinone listening on http://%s", addr)
	log.Printf("using 7za at %s", sevenZip)
	log.Fatal(http.ListenAndServe(addr, withSecurityHeaders(mux)))
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(w, r)
	})
}

func mustStaticSubtree() fs.FS {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	return sub
}

func find7za() (string, error) {
	// Prefer the full 7z binary: the standalone 7za build cannot read WIM/ESD
	// images, and 7z is a strict superset for the formats we support.
	for _, name := range []string{"7z", "7za"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", errors.New("install p7zip so 7z or 7za is available in PATH")
}

func (a *app) handleDirs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = home
		} else {
			path, _ = os.Getwd()
		}
	}
	abs, err := cleanAbs(path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	entries, err := os.ReadDir(abs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var dirs []directoryEntry
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		dirs = append(dirs, directoryEntry{
			Name: entry.Name(),
			Path: filepath.Join(abs, entry.Name()),
		})
	}
	sort.Slice(dirs, func(i, j int) bool {
		return strings.ToLower(dirs[i].Name) < strings.ToLower(dirs[j].Name)
	})

	parent := filepath.Dir(abs)
	if parent == abs {
		parent = ""
	}
	writeJSON(w, directoryResponse{Path: abs, Parent: parent, Dirs: dirs})
}

func (a *app) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	root, err := cleanAbs(req.Root)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	depth := normalizeScanDepth(req.Depth)
	archives, err := scanArchives(root, depth, req.IncludeHidden)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, scanResponse{
		Root:          root,
		Depth:         depth,
		IncludeHidden: req.IncludeHidden,
		Archives:      archives,
	})
}

func (a *app) handleExtract(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req extractRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	root, err := cleanAbs(req.Root)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.ConflictPolicy, err = normalizeConflictPolicy(req.ConflictPolicy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Archives) == 0 {
		writeError(w, http.StatusBadRequest, "select at least one archive")
		return
	}

	for i := range req.Archives {
		req.Archives[i].Path, err = cleanAbs(req.Archives[i].Path)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !isInside(root, req.Archives[i].Path) {
			writeError(w, http.StatusBadRequest, "archive is outside selected root")
			return
		}
		if !isSupportedArchive(req.Archives[i].Path) {
			writeError(w, http.StatusBadRequest, "archive must be a supported .zip, .7z, .wim, .esd, .swm, or .001 file")
			return
		}
	}

	j := newJob()
	j.root = root
	j.total = len(req.Archives)
	a.jobs.add(j)
	go a.runExtractJob(j, root, req)
	writeJSON(w, extractResponse{JobID: j.id})
}

func (a *app) handleJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	activeOnly := r.URL.Query().Get("active") == "1" || r.URL.Query().Get("active") == "true"
	writeJSON(w, jobListResponse{Jobs: a.jobs.list(activeOnly)})
}

func (a *app) handleDecodePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	decoded := decodePasswordSlang(req.Password)
	writeJSON(w, map[string]any{
		"password": req.Password,
		"decoded":  decoded,
		"changed":  decoded != req.Password,
	})
}

func (a *app) handleJob(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	j := a.jobs.get(parts[0])
	if j == nil {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	// GET /api/jobs/{id} — snapshot for page refresh resume
	if r.Method == http.MethodGet && len(parts) == 1 {
		writeJSON(w, j.snapshot())
		return
	}
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method == http.MethodGet && parts[1] == "events" {
		streamJobEvents(w, r, j)
		return
	}
	if r.Method == http.MethodGet && parts[1] == "ws" {
		streamJobWebSocket(w, r, j)
		return
	}
	if r.Method == http.MethodPost && parts[1] == "cancel" {
		j.cancel()
		writeJSON(w, map[string]string{"status": "cancelling"})
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func scanArchives(root string, depth int, includeHidden bool) ([]archiveInfo, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}

	var archives []archiveInfo
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if d.IsDir() {
			if dirDepth(root, path) > depth {
				return filepath.SkipDir
			}
			// Never descend into our own staging dirs (a crashed run may leave one).
			if strings.HasPrefix(d.Name(), stagingPrefix) {
				return filepath.SkipDir
			}
			if !includeHidden && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !includeHidden && strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		if !isSupportedArchive(path) || dirDepth(root, filepath.Dir(path)) > depth {
			return nil
		}
		archive, err := buildArchiveInfo(root, path)
		if err != nil {
			return err
		}
		archives = append(archives, archive)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(archives, func(i, j int) bool {
		return archives[i].RelativeFile < archives[j].RelativeFile
	})
	return archives, nil
}

func buildArchiveInfo(root, path string) (archiveInfo, error) {
	dir := filepath.Dir(path)
	relFile, err := filepath.Rel(root, path)
	if err != nil {
		return archiveInfo{}, err
	}
	relDir, err := filepath.Rel(root, dir)
	if err != nil {
		return archiveInfo{}, err
	}
	if relDir == "." {
		relDir = filepath.Base(root)
	}
	parts, total := discoverParts(path)
	return archiveInfo{
		ID:              archiveID(path),
		Name:            filepath.Base(path),
		Path:            path,
		Directory:       dir,
		RelativeFile:    filepath.ToSlash(relFile),
		RelativeDir:     filepath.ToSlash(relDir),
		Format:          archiveFormat(path),
		DefaultPassword: defaultPassword(root, dir),
		PartCount:       len(parts),
		TotalBytes:      total,
	}, nil
}

func discoverParts(firstPart string) ([]string, int64) {
	if !isSplitArchive(firstPart) {
		return []string{firstPart}, fileSize(firstPart)
	}
	dir := filepath.Dir(firstPart)
	name := filepath.Base(firstPart)
	var re *regexp.Regexp
	if strings.EqualFold(name, "001") {
		re = regexp.MustCompile(`^\d{3}$`)
	} else {
		prefix := strings.TrimSuffix(name, filepath.Ext(name))
		re = regexp.MustCompile(`(?i)^` + regexp.QuoteMeta(prefix) + `\.\d{3}$`)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{firstPart}, fileSize(firstPart)
	}
	var parts []string
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || !re.MatchString(entry.Name()) {
			continue
		}
		p := filepath.Join(dir, entry.Name())
		parts = append(parts, p)
		total += fileSize(p)
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return []string{firstPart}, fileSize(firstPart)
	}
	return parts, total
}

func defaultPassword(root, dir string) string {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." {
		return filepath.Base(root)
	}
	parts := strings.Split(filepath.Clean(rel), string(os.PathSeparator))
	if len(parts) == 0 || parts[0] == "." || parts[0] == "" {
		return filepath.Base(root)
	}
	return parts[0]
}

func (a *app) runExtractJob(j *job, root string, req extractRequest) {
	total := len(req.Archives)
	workers := extractWorkers(total)
	j.publish(jobEvent{
		Type:           "job",
		JobID:          j.id,
		Status:         "running",
		Message:        fmt.Sprintf("任务已开始，同时处理 %d 个", workers),
		Total:          total,
		DeleteOriginal: req.DeleteOriginal,
		ConflictPolicy: req.ConflictPolicy,
	})
	defer j.close()

	results := make(chan extractOutcome, total)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var progressMu sync.Mutex
	bytesDone := map[string]int64{}
	active := map[string]string{}
	var bytesTotal int64
	finished := 0

	publishOverall := func() {
		progressMu.Lock()
		var done int64
		for _, n := range bytesDone {
			done += n
		}
		names := make([]string, 0, len(active))
		for _, name := range active {
			names = append(names, name)
		}
		running := len(active)
		doneCount := finished
		progressMu.Unlock()
		sort.Strings(names)
		current := ""
		if len(names) == 1 {
			current = names[0]
		} else if len(names) > 1 {
			current = fmt.Sprintf("%s 等 %d 个", names[0], len(names))
		}
		elapsed := time.Since(j.started).Seconds()
		speed := 0.0
		if elapsed > 0.4 && done > 0 {
			speed = float64(done) / elapsed
		}
		evt := jobEvent{
			Type:           "job",
			JobID:          j.id,
			Status:         "running",
			Message:        overallMessage(current, running, doneCount, total),
			Total:          total,
			Current:        current,
			Running:        running,
			Finished:       doneCount,
			BytesDone:      done,
			BytesTotal:     bytesTotal,
			SpeedBps:       speed,
			DeleteOriginal: req.DeleteOriginal,
			ConflictPolicy: req.ConflictPolicy,
		}
		if bytesTotal > 0 {
			evt.Percent = int(done * 100 / bytesTotal)
			if evt.Percent > 99 && doneCount < total {
				evt.Percent = 99
			}
		}
		j.publish(evt)
	}

	for i, archive := range req.Archives {
		select {
		case <-j.ctx.Done():
			wg.Wait()
			close(results)
			a.finishExtractJob(j, req, total, collectOutcomes(results))
			return
		default:
		}

		info, err := buildArchiveInfo(root, archive.Path)
		if err != nil {
			results <- extractOutcome{status: "failed"}
			j.publish(jobEvent{Type: "archive", JobID: j.id, Status: "failed", ArchiveID: archive.ID, Path: archive.Path, Error: err.Error(), Index: i + 1, Total: total})
			continue
		}
		progressMu.Lock()
		bytesTotal += info.TotalBytes
		progressMu.Unlock()

		wg.Add(1)
		go func(i int, archive archiveExtract, info archiveInfo) {
			defer wg.Done()
			select {
			case <-j.ctx.Done():
				results <- extractOutcome{status: "cancelled"}
				j.publish(jobEvent{
					Type: "archive", JobID: j.id, Status: "cancelled", ArchiveID: info.ID,
					ArchiveName: info.Name, Path: info.Path, Index: i + 1, Total: total, Message: "已取消",
				})
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			passwordRaw := strings.TrimSpace(archive.Password)
			if passwordRaw == "" {
				passwordRaw = info.DefaultPassword
			}
			password := decodePasswordSlang(passwordRaw)
			base := jobEvent{
				Type: "archive", JobID: j.id, ArchiveID: info.ID, ArchiveName: info.Name,
				Path: info.Path, Index: i + 1, Total: total, BytesTotal: info.TotalBytes,
			}
			startMsg := "正在解压 " + info.RelativeFile
			startEvt := withEvent(base, "running", 0, startMsg, "")
			if password != passwordRaw {
				startEvt.PasswordDecoded = password
				startEvt.Message = startMsg + "（密码黑话已转换）"
			}
			j.publish(startEvt)
			progressMu.Lock()
			active[info.ID] = info.Name
			progressMu.Unlock()
			defer func() {
				progressMu.Lock()
				delete(active, info.ID)
				finished++
				progressMu.Unlock()
				publishOverall()
			}()

			stats, err := a.extractOne(j, base, info, password, req.ConflictPolicy, req.DeleteOriginal, func(pct int) {
				if info.TotalBytes <= 0 {
					return
				}
				done := info.TotalBytes * int64(pct) / 100
				progressMu.Lock()
				bytesDone[info.ID] = done
				progressMu.Unlock()
			})
			if err != nil {
				progressMu.Lock()
				bytesDone[info.ID] = 0
				progressMu.Unlock()
				if errors.Is(err, context.Canceled) || j.ctx.Err() != nil {
					results <- extractOutcome{status: "cancelled"}
					j.publish(withEvent(base, "cancelled", 0, "已取消", ""))
					return
				}
				results <- extractOutcome{status: "failed"}
				j.publish(withEvent(base, "failed", 0, "", err.Error()))
				return
			}
			progressMu.Lock()
			bytesDone[info.ID] = info.TotalBytes
			progressMu.Unlock()

			message := "解压完成"
			warning := ""
			if req.DeleteOriginal {
				if err := a.verifyArchive(j.ctx, info, password); err != nil {
					warning = "解压完成，但校验未通过，已保留原始压缩包: " + err.Error()
				} else if deleted, err := deleteArchiveParts(info.Path); err != nil {
					warning = "解压完成，但删除原始分卷失败: " + err.Error()
				} else {
					message = "解压完成，已删除 " + strconv.Itoa(deleted) + " 个原始分卷"
				}
			}
			if len(stats.NestedWarnings) > 0 {
				nested := "嵌套分卷告警：" + strings.Join(stats.NestedWarnings, "；")
				if warning != "" {
					warning += "；" + nested
				} else {
					warning = nested
				}
			}
			if warning != "" {
				results <- extractOutcome{status: "warning"}
				j.publish(withEvent(base, "warning", 100, warning, ""))
				return
			}
			results <- extractOutcome{status: "done"}
			j.publish(withEvent(base, "done", 100, message, ""))
		}(i, archive, info)
	}

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-j.ctx.Done():
				return
			case <-ticker.C:
				if j.isDone() {
					return
				}
				publishOverall()
			}
		}
	}()

	wg.Wait()
	close(results)
	a.finishExtractJob(j, req, total, collectOutcomes(results))
}

func (a *app) finishExtractJob(j *job, req extractRequest, total int, counts outcomeCounts) {
	cancelled := j.ctx.Err() != nil || counts.cancelled > 0
	status := jobOutcome(counts.success, counts.failed, cancelled)
	j.publish(jobEvent{
		Type:           "job",
		JobID:          j.id,
		Status:         status,
		Percent:        100,
		Message:        buildJobSummary(total, counts.success, counts.failed, counts.warning, cancelled),
		Total:          total,
		SuccessCount:   counts.success,
		FailedCount:    counts.failed,
		WarningCount:   counts.warning,
		Finished:       counts.success + counts.failed + counts.warning,
		DeleteOriginal: req.DeleteOriginal,
		ConflictPolicy: req.ConflictPolicy,
	})
}

type extractOutcome struct {
	status string
}

type outcomeCounts struct {
	success, failed, warning, cancelled int
}

func collectOutcomes(results <-chan extractOutcome) outcomeCounts {
	var c outcomeCounts
	for item := range results {
		switch item.status {
		case "done":
			c.success++
		case "warning":
			c.success++
			c.warning++
		case "failed":
			c.failed++
		case "cancelled":
			c.cancelled++
		}
	}
	return c
}

func extractWorkers(total int) int {
	if total < 1 {
		return 1
	}
	// Two concurrent 7z processes is the practical ceiling on a single disk.
	// More just thrashes the drive and makes every bar look stuck.
	if total == 1 {
		return 1
	}
	return 2
}

func overallMessage(current string, running, finished, total int) string {
	if current != "" {
		return fmt.Sprintf("正在处理 %s（%d/%d）", current, finished, total)
	}
	if running > 1 {
		return fmt.Sprintf("%d 个同时解压中", running)
	}
	return fmt.Sprintf("已完成 %d / %d", finished, total)
}

// archiveListing summarizes the entries 7-Zip reports for an archive. It is used
// to decide whether an extraction will have a second phase (a 001/002 split set
// stored inside), so the progress bar can be split across both phases up front.
type archiveListing struct {
	HasNested   bool
	NestedBytes int64
}

// inspectArchive fails fast on a wrong password or an unreadable archive and,
// on success, returns a summary of its contents. "l -slt" only reads the header,
// so this costs milliseconds even for multi-GB archives and — unlike "x" — writes
// nothing to disk. Running it first means a bad password never gets the chance
// to spill partial output.
func (a *app) inspectArchive(ctx context.Context, info archiveInfo, password string) (archiveListing, error) {
	cmd := exec.CommandContext(ctx, a.sevenZip, "l", "-slt", "-p"+password, info.Path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return archiveListing{}, context.Canceled
		}
		if line := first7zProblemLine(string(out)); line != "" {
			return archiveListing{}, errors.New(humanize7zLine(line))
		}
		return archiveListing{}, fmt.Errorf("无法读取压缩包：%s。常见原因：密码错误、分卷缺失或文件损坏", err)
	}
	return parseArchiveListing(string(out)), nil
}

// checkArchivePassword is inspectArchive when only the pass/fail result matters.
func (a *app) checkArchivePassword(ctx context.Context, info archiveInfo, password string) error {
	_, err := a.inspectArchive(ctx, info, password)
	return err
}

var (
	plainPartRe    = regexp.MustCompile(`^\d{3}$`)
	prefixedPartRe = regexp.MustCompile(`\.\d{3}$`)
)

// parseArchiveListing scans "7z l -slt" output for 001/002 volume parts. It
// reports whether at least one split set is present and the combined size of all
// part files, which is what the nested extraction phase is weighted by.
func parseArchiveListing(out string) archiveListing {
	var listing archiveListing
	var name string
	var size int64
	var hasSize, isFolder, isArchiveBlock bool

	flush := func() {
		if name != "" && !isArchiveBlock && !isFolder {
			base := filepath.Base(name)
			if base == "001" || strings.HasSuffix(strings.ToLower(base), ".001") {
				listing.HasNested = true
			}
			if plainPartRe.MatchString(base) || prefixedPartRe.MatchString(base) {
				if hasSize {
					listing.NestedBytes += size
				}
			}
		}
		name, size, hasSize, isFolder, isArchiveBlock = "", 0, false, false, false
	}

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.Trim(line, "-") == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "Path = "):
			flush()
			name = strings.TrimSpace(strings.TrimPrefix(line, "Path = "))
		case strings.HasPrefix(line, "Size = "):
			size, _ = strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "Size = ")), 10, 64)
			hasSize = true
		case strings.HasPrefix(line, "Folder = "):
			isFolder = strings.TrimSpace(strings.TrimPrefix(line, "Folder = ")) == "+"
		case strings.HasPrefix(line, "Attributes = "):
			// 7-Zip marks directories with a leading "D" (e.g. "D drwxr-xr-x").
			isFolder = strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(line, "Attributes = ")), "D")
		case strings.HasPrefix(line, "Type = "):
			isArchiveBlock = true
		}
	}
	flush()
	return listing
}

// verifyArchive runs a full integrity test. Used before deleting originals.
func (a *app) verifyArchive(ctx context.Context, info archiveInfo, password string) error {
	cmd := exec.CommandContext(ctx, a.sevenZip, "t", "-p"+password, info.Path)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return context.Canceled
	}
	if line := first7zProblemLine(string(out)); line != "" {
		return errors.New(humanize7zLine(line))
	}
	return errors.New("完整性校验失败")
}

func first7zProblemLine(output string) string {
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.Contains(strings.ToLower(line), "everything is ok") {
			continue
		}
		if shouldSurface7zLine(line) {
			return line
		}
	}
	return ""
}

// stagingPrefix marks temporary extraction directories. Scans skip these so a
// crashed run's leftovers never show up as archives to extract.
const stagingPrefix = ".unzip-allinone-tmp-"

type commitStats struct {
	Written  int
	Skipped  int
	Renamed  int
	Replaced int
	// NestedWarnings holds non-fatal messages from recursively extracting
	// archives found inside the extracted payload.
	NestedWarnings []string
}

// commitStaged moves everything from staging into target, applying policy to
// each conflicting file. Directories are merged rather than replaced so an
// archive adding files to an existing folder does not wipe it.
func commitStaged(staging, target, policy string) (commitStats, error) {
	var stats commitStats
	entries, err := os.ReadDir(staging)
	if err != nil {
		return stats, err
	}
	for _, entry := range entries {
		if err := commitEntry(filepath.Join(staging, entry.Name()), filepath.Join(target, entry.Name()), policy, &stats); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

func commitEntry(src, dst, policy string, stats *commitStats) error {
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return err
	}
	dstInfo, dstErr := os.Lstat(dst)
	exists := dstErr == nil

	// Merge directory into existing directory, recursing so the policy applies
	// per file rather than to the whole tree.
	if exists && srcInfo.IsDir() && dstInfo.IsDir() {
		children, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := commitEntry(filepath.Join(src, child.Name()), filepath.Join(dst, child.Name()), policy, stats); err != nil {
				return err
			}
		}
		return nil
	}

	if exists {
		switch policy {
		case "skip":
			stats.Skipped++
			return nil
		case "rename":
			unique, err := uniquePath(dst)
			if err != nil {
				return err
			}
			dst = unique
			stats.Renamed++
		default: // overwrite
			if err := os.RemoveAll(dst); err != nil {
				return err
			}
			stats.Replaced++
		}
	} else {
		stats.Written++
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		// Rename fails across filesystems; fall back to a copy.
		if copyErr := copyPath(src, dst); copyErr != nil {
			return copyErr
		}
	}
	return nil
}

// uniquePath returns dst with " (2)", " (3)", … inserted before the extension
// until the name is free, matching how desktop file managers de-duplicate.
func uniquePath(dst string) (string, error) {
	ext := filepath.Ext(dst)
	stem := strings.TrimSuffix(dst, ext)
	for i := 2; i < 10000; i++ {
		candidate := fmt.Sprintf("%s (%d)%s", stem, i, ext)
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("无法为 %s 生成不重复的文件名", filepath.Base(dst))
}

func copyPath(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		children, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := copyPath(filepath.Join(src, child.Name()), filepath.Join(dst, child.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		linkTarget, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(linkTarget, dst)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// extractOne unpacks one archive into a staging directory and only then commits
// the result into the target directory.
//
// Staging is what makes extraction safe. 7-Zip writes decoded bytes to disk
// *before* it discovers a wrong password or a CRC failure, so extracting
// straight into the target left full-size garbage files behind on failure. With
// the default "skip existing" policy a later retry with the correct password
// then skipped that garbage and the job still reported success — silent
// corruption, and unrecoverable once "delete original" was on. Staging also
// means a cancelled job leaves nothing behind.
func (a *app) extractOne(j *job, base jobEvent, info archiveInfo, password, conflictPolicy string, deleteOriginal bool, onPercent ...func(int)) (commitStats, error) {
	reportPercent := func(int) {}
	if len(onPercent) > 0 && onPercent[0] != nil {
		reportPercent = onPercent[0]
	}
	// Reading the listing is the first, potentially slow step for a large WIM.
	// Surface it so the row is not frozen on "解压中" while the header is parsed.
	analyzeEvt := withEvent(base, "running", 0, "正在分析压缩包结构…", "")
	analyzeEvt.Phase = "analyze"
	j.publish(analyzeEvt)

	// The listing fails fast on a wrong password or a broken archive. It also
	// reveals whether a second phase (nested 001/002 volumes) is coming, so the
	// progress bar can be split across both phases up front.
	listing, err := a.inspectArchive(j.ctx, info, password)
	if err != nil {
		return commitStats{}, err
	}

	staging, err := os.MkdirTemp(info.Directory, stagingPrefix+"*")
	if err != nil {
		return commitStats{}, fmt.Errorf("无法创建临时解压目录: %w", err)
	}
	// Always clear staging: on success commitStaged has already moved everything
	// out, on any failure or cancellation this is what discards the garbage.
	defer os.RemoveAll(staging)

	// Phase 1: the outer archive (e.g. the WIM) fills the first slice of the bar.
	outerEnd := 100
	if listing.HasNested {
		if listing.NestedBytes > 0 {
			outerEnd = phaseBoundary(info.TotalBytes, listing.NestedBytes)
		} else {
			// Nested content is present but its size is unknown; split evenly.
			outerEnd = 50
		}
	}
	if err := a.run7z(j, info, password, staging, func(p int, msg string) {
		mapped := p * outerEnd / 100
		evt := withEvent(base, "running", mapped, msg, "")
		evt.Phase = "outer"
		evt.BytesTotal = info.TotalBytes
		if info.TotalBytes > 0 {
			evt.BytesDone = info.TotalBytes * int64(mapped) / 100
		}
		j.publish(evt)
		reportPercent(mapped)
	}); err != nil {
		return commitStats{}, err
	}

	// Phase 2: a WIM (or other container) can hold a 001/002 split set. Extract
	// those in the same task so the user gets the real payload without a second
	// scan, mapping their progress onto the remaining slice of the bar.
	tracker := &nestedTracker{j: j, base: base, start: outerEnd, end: 100, onPercent: reportPercent}
	if listing.HasNested {
		// Clean handoff so the row clearly shows the outer phase finished before
		// the nested volumes start filling the rest of the bar.
		evt := withEvent(base, "running", outerEnd, "外层解压完成，开始解压嵌套分卷", "")
		evt.Phase = "outer"
		j.publish(evt)
	}
	warnings, nestedErr := a.extractNested(j, password, staging, deleteOriginal, map[string]bool{}, 0, tracker)
	// A cancelled nested level must abort before committing, or a half-expanded
	// payload would be written into the target directory.
	if nestedErr != nil {
		return commitStats{}, nestedErr
	}
	tracker.finish()

	// Moving the staged tree into place can be slow for very large payloads
	// (especially when it crosses filesystems and falls back to a copy).
	commitEvt := withEvent(base, "running", 100, "正在写入目标目录…", "")
	commitEvt.Phase = "commit"
	j.publish(commitEvt)
	reportPercent(100)

	stats, err := commitStaged(staging, info.Directory, conflictPolicy)
	stats.NestedWarnings = warnings
	return stats, err
}

// phaseBoundary returns the percent at which the outer extraction hands over to
// the nested phase, weighted by bytes so the bar advances at a roughly even pace.
func phaseBoundary(outerBytes, nestedBytes int64) int {
	total := outerBytes + nestedBytes
	if total <= 0 || nestedBytes <= 0 {
		return 100
	}
	pct := int(float64(outerBytes) / float64(total) * 100)
	if pct < 10 {
		pct = 10
	}
	if pct > 90 {
		pct = 90
	}
	return pct
}

// nestedTracker folds the progress of every nested volume set into the single
// progress bar of the outer archive, so the row keeps advancing instead of
// sitting at 100% while the split payload is still being expanded. Work is
// weighted by bytes so one large volume set does not finish instantly next to a
// small one.
type nestedTracker struct {
	j          *job
	base       jobEvent
	start      int
	end        int
	totalBytes int64
	doneBytes  int64
	curBytes   int64
	last       int
	onPercent  func(int)
}

// addBytes registers upcoming work so the denominator is stable before a set
// starts reporting progress.
func (n *nestedTracker) addBytes(b int64) {
	if b > 0 {
		n.totalBytes += b
	}
}

// beginSet marks the set whose progress ticks are about to arrive.
func (n *nestedTracker) beginSet(b int64) {
	n.curBytes = b
	if b > 0 && n.totalBytes < n.doneBytes+b {
		n.totalBytes = n.doneBytes + b
	}
}

func (n *nestedTracker) progress(inner int, _ string) {
	if n.totalBytes <= 0 {
		return
	}
	if inner < 0 {
		inner = 0
	}
	if inner > 100 {
		inner = 100
	}
	done := n.doneBytes + int64(inner)*n.curBytes/100
	frac := float64(done) / float64(n.totalBytes)
	if frac > 1 {
		frac = 1
	}
	pct := n.start + int(frac*float64(n.end-n.start))
	msg := fmt.Sprintf("正在解压嵌套分卷（%d%%）", inner)
	n.publish(pct, msg)
}

func (n *nestedTracker) completeSet() {
	n.doneBytes += n.curBytes
	n.curBytes = 0
}

func (n *nestedTracker) finish() {
	if n.end <= n.start {
		return
	}
	msg := "解压完成"
	if n.totalBytes > 0 {
		msg = "嵌套分卷解压完成"
	}
	n.publish(n.end, msg)
}

func (n *nestedTracker) publish(pct int, msg string) {
	if pct > n.end {
		pct = n.end
	}
	if pct < n.last {
		pct = n.last
	}
	n.last = pct
	evt := withEvent(n.base, "running", pct, msg, "")
	evt.Phase = "nested"
	n.j.publish(evt)
	if n.onPercent != nil {
		n.onPercent(pct)
	}
}

// extractNested walks an extracted payload and recursively expands any 001/002
// split archives found inside it. Failures are non-fatal: the outer archive has
// already been extracted, so a bad nested set is reported as a warning instead
// of failing the whole task. Only cancellation is returned as an error.
func (a *app) extractNested(j *job, password, dir string, deleteOriginal bool, processed map[string]bool, depth int, tracker *nestedTracker) ([]string, error) {
	if depth >= maxNestedDepth {
		return nil, nil
	}

	// Reserve every set found at this level (and register its size) before
	// extracting any of them, so a sibling set is not mistaken for a newly-born
	// nested set in the recursion below and the progress denominator is stable.
	type set struct {
		first string
		bytes int64
	}
	var pending []set
	for _, first := range findSplitArchives(dir) {
		key := filepath.Clean(first)
		if processed[key] {
			continue
		}
		processed[key] = true
		_, bytes := discoverParts(first)
		pending = append(pending, set{first: first, bytes: bytes})
	}
	if len(pending) == 0 {
		return nil, nil
	}
	for _, s := range pending {
		tracker.addBytes(s.bytes)
	}

	var warnings []string
	for _, s := range pending {
		if j.ctx.Err() != nil {
			return warnings, context.Canceled
		}
		info, err := buildArchiveInfo(dir, s.first)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("无法解析嵌套分卷 %s：%v", filepath.Base(s.first), err))
			tracker.beginSet(s.bytes)
			tracker.completeSet()
			continue
		}
		if err := a.checkArchivePassword(j.ctx, info, password); err != nil {
			if errors.Is(err, context.Canceled) {
				return warnings, context.Canceled
			}
			warnings = append(warnings, fmt.Sprintf("嵌套分卷 %s 无法读取：%v", info.Name, err))
			tracker.beginSet(s.bytes)
			tracker.completeSet()
			continue
		}
		tracker.beginSet(s.bytes)
		if err := a.run7z(j, info, password, dir, tracker.progress); err != nil {
			if errors.Is(err, context.Canceled) {
				return warnings, context.Canceled
			}
			warnings = append(warnings, fmt.Sprintf("嵌套分卷 %s 解压失败：%v", info.Name, err))
			tracker.completeSet()
			continue
		}
		if deleteOriginal {
			if err := a.verifyArchive(j.ctx, info, password); err != nil {
				if errors.Is(err, context.Canceled) {
					return warnings, context.Canceled
				}
				warnings = append(warnings, fmt.Sprintf("嵌套分卷 %s 解压完成，但校验未通过，已保留原始分卷：%v", info.Name, err))
			} else if _, err := deleteArchiveParts(info.Path); err != nil {
				warnings = append(warnings, fmt.Sprintf("嵌套分卷 %s 解压完成，但删除原始分卷失败：%v", info.Name, err))
			}
		}
		tracker.completeSet()
		deeper, err := a.extractNested(j, password, dir, deleteOriginal, processed, depth+1, tracker)
		warnings = append(warnings, deeper...)
		if err != nil {
			return warnings, err
		}
	}
	return warnings, nil
}

// findSplitArchives returns the first part of every 001/002 split set in dir,
// searching subdirectories too. Only the leading part matches isSplitArchive, so
// each set is reported once.
func findSplitArchives(dir string) []string {
	var firsts []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), stagingPrefix) {
			return nil
		}
		if isSplitArchive(path) {
			firsts = append(firsts, path)
		}
		return nil
	})
	sort.Strings(firsts)
	return firsts
}

func (a *app) run7z(j *job, info archiveInfo, password, outDir string, report func(percent int, message string)) error {
	// -bsp1: progress on stdout; -bso1/-bse1: messages on stdout/stderr.
	// p7zip refreshes progress with backspace (\x08), not only \r — see scan7zOutput.
	// -aoa is safe here because outDir is a freshly created empty staging dir;
	// the user's conflict policy is applied later by commitStaged.
	// -p is passed via argv only as a fallback; see passwordStdin below.
	args := []string{"x", "-y", "-bsp1", "-bso1", "-bse1", "-aoa", "-p" + password, "-o" + outDir, info.Path}
	cmd := exec.CommandContext(j.ctx, a.sevenZip, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	if report == nil {
		report = func(int, string) {}
	}

	var wg sync.WaitGroup
	// Larger buffers so short bursts of progress/log lines are less likely to drop.
	progress := make(chan int, 64)
	logs := make(chan string, 64)
	readStream := func(r io.Reader) {
		defer wg.Done()
		scan7zOutput(r, progress, logs)
	}
	wg.Add(2)
	go readStream(stdout)
	go readStream(stderr)

	done := make(chan error, 1)
	go func() {
		wg.Wait()
		done <- cmd.Wait()
		close(progress)
		close(logs)
	}()

	last := -1
	lastMsg := ""
	started := time.Now()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	reportProgress := func(p int, msg string) {
		if msg == "" {
			msg = fmt.Sprintf("解压中 %d%%", p)
		}
		if p == last && msg == lastMsg {
			return
		}
		last = p
		lastMsg = msg
		report(p, msg)
	}

	for {
		select {
		case <-j.ctx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			<-done
			return context.Canceled
		case p, ok := <-progress:
			if ok {
				reportProgress(p, fmt.Sprintf("解压中 %d%%", p))
			}
		case line, ok := <-logs:
			if ok && shouldSurface7zLine(line) {
				reportProgress(maxInt(last, 0), humanize7zLine(line))
			}
		case <-ticker.C:
			// Before the first percent, keep the row alive so the UI does not look frozen.
			if last < 0 {
				waited := int(time.Since(started).Seconds())
				if waited < 1 {
					waited = 1
				}
				reportProgress(0, fmt.Sprintf("正在读取压缩包… %ds", waited))
				continue
			}
			reportProgress(last, fmt.Sprintf("解压中 %d%%", last))
		case err := <-done:
			for p := range progress {
				reportProgress(p, fmt.Sprintf("解压中 %d%%", p))
			}
			if err != nil {
				return classify7zError(err, last)
			}
			return nil
		}
	}
}

func scan7zOutput(r io.Reader, progress chan<- int, logs chan<- string) {
	reader := bufio.NewReader(r)
	var token strings.Builder
	flush := func() {
		if token.Len() == 0 {
			return
		}
		consume7zToken(token.String(), progress, logs)
		token.Reset()
	}
	for {
		b, err := reader.ReadByte()
		if err != nil {
			flush()
			return
		}
		// p7zip uses \r and \b (backspace) for in-place progress redraws.
		if b == '\r' || b == '\n' || b == 0x08 {
			flush()
			continue
		}
		// Ignore other control chars that can glue tokens together.
		if b < 0x20 && b != '\t' {
			continue
		}
		token.WriteByte(b)
	}
}

// percentRe matches "45%", "  45 %", and progress lines like "  45% 12".
var percentRe = regexp.MustCompile(`(?i)(?:^|[^0-9])(\d{1,3})\s*%`)

func consume7zToken(token string, progress chan<- int, logs chan<- string) {
	text := strings.TrimSpace(token)
	if text == "" {
		return
	}
	// Skip scan-phase size lines like "0M Scan /path" — not extract percent.
	lower := strings.ToLower(text)
	if strings.Contains(lower, "scan ") && !strings.Contains(text, "%") {
		return
	}
	for _, match := range percentRe.FindAllStringSubmatch(text, -1) {
		p, err := strconv.Atoi(match[1])
		if err == nil && p >= 0 && p <= 100 {
			// Prefer the highest percent seen in this token (progress redraws can concatenate).
			select {
			case progress <- p:
			default:
				// Drop if consumer is behind; later ticks or higher values will catch up.
			}
		}
	}
	select {
	case logs <- text:
	default:
	}
}

func shouldSurface7zLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "error") ||
		strings.Contains(lower, "wrong password") ||
		strings.Contains(lower, "can not open") ||
		strings.Contains(lower, "cannot open") ||
		strings.Contains(lower, "data error") ||
		strings.Contains(lower, "crc failed") ||
		strings.Contains(lower, "is not archive") ||
		strings.Contains(lower, "everything is ok")
}

func humanize7zLine(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "wrong password"):
		return "密码错误"
	case strings.Contains(lower, "can not open") || strings.Contains(lower, "cannot open"):
		return "无法打开压缩包（可能密码错误或文件损坏）"
	case strings.Contains(lower, "data error"):
		return "数据错误（可能密码错误或分卷不完整）"
	case strings.Contains(lower, "crc failed"):
		return "CRC 校验失败"
	case strings.Contains(lower, "everything is ok"):
		return "7-Zip 报告完成"
	default:
		return line
	}
}

func classify7zError(err error, lastPercent int) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "exit status") {
		// 7-Zip non-zero exit: surface a clearer Chinese message.
		return fmt.Errorf("解压失败（已进行到约 %d%%）：%s。常见原因：密码错误、分卷缺失或文件损坏", maxInt(lastPercent, 0), msg)
	}
	return err
}

// passwordSlangReplacements maps Chinese net-speak fragments to password characters.
// Longer keys must be listed first so multi-char phrases win over single chars.
var passwordSlangReplacements = []struct {
	from string
	to   string
}{
	{"点斜点", "./."},
	{"点斜杠点", "./."},
	{"点反斜点", ".\\."},
	{"点斜杠", "./"},
	{"斜杠点", "/."},
	{"星号", "*"},
	{"星星", "*"},
	{"下划线", "_"},
	{"中划线", "-"},
	{"横杠", "-"},
	{"减号", "-"},
	{"加号", "+"},
	{"等号", "="},
	{"井号", "#"},
	{"井", "#"},
	{"百分号", "%"},
	{"感叹号", "!"},
	{"叹号", "!"},
	{"问号", "?"},
	{"艾特", "@"},
	{"小老鼠", "@"},
	{"美元", "$"},
	{"与号", "&"},
	{"空格", " "},
	{"左括号", "("},
	{"右括号", ")"},
	{"左方括号", "["},
	{"右方括号", "]"},
	{"反斜杠", "\\"},
	{"斜杠", "/"},
	{"斜", "/"},
	{"星", "*"},
	{"点", "."},
	{"杠", "-"},
}

func decodePasswordSlang(password string) string {
	if password == "" {
		return password
	}
	out := password
	for _, pair := range passwordSlangReplacements {
		if strings.Contains(out, pair.from) {
			out = strings.ReplaceAll(out, pair.from, pair.to)
		}
	}
	return out
}

func deleteArchiveParts(firstPart string) (int, error) {
	parts, _ := discoverParts(firstPart)
	for i, part := range parts {
		if err := os.Remove(part); err != nil {
			return i, err
		}
	}
	return len(parts), nil
}

// jobOutcome classifies a finished job so the UI can show success, partial
// failure, and total failure differently. Reporting "处理完成" with a green check
// when every archive failed hid real errors from users.
func jobOutcome(successCount, failedCount int, cancelled bool) string {
	switch {
	case cancelled:
		return "cancelled"
	case failedCount == 0:
		return "done"
	case successCount == 0:
		return "failed"
	default:
		return "partial"
	}
}

func buildJobSummary(total, successCount, failedCount, warningCount int, cancelled bool) string {
	var status string
	switch jobOutcome(successCount, failedCount, cancelled) {
	case "cancelled":
		status = "任务已取消"
	case "failed":
		status = "全部失败"
	case "partial":
		status = "部分完成"
	default:
		status = "全部成功"
	}
	summary := fmt.Sprintf("%s：%d 个文件中 %d 成功，%d 失败", status, total, successCount, failedCount)
	if warningCount > 0 {
		summary += fmt.Sprintf("，%d 个告警", warningCount)
	}
	if failedCount > 0 {
		return summary + "。失败项可修改密码后重试。"
	}
	return summary + "。输出位置为每个压缩包所在目录。"
}

func newJob() *job {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()
	return &job{
		id:      strconv.FormatInt(now.UnixNano(), 36),
		ctx:     ctx,
		cancel:  cancel,
		latest:  map[string]jobEvent{},
		subs:    map[chan jobEvent]struct{}{},
		started: now,
	}
}

func (s *jobStore) add(j *job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[j.id] = j
	// Opportunistic cleanup of very old finished jobs so memory stays bounded.
	cutoff := time.Now().Add(-2 * time.Hour)
	for id, existing := range s.jobs {
		if existing == j {
			continue
		}
		existing.mu.Lock()
		done := existing.done
		finished := existing.finished
		existing.mu.Unlock()
		if done && !finished.IsZero() && finished.Before(cutoff) {
			delete(s.jobs, id)
		}
	}
}

func (s *jobStore) get(id string) *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[id]
}

func (s *jobStore) list(activeOnly bool) []jobSnapshot {
	s.mu.Lock()
	jobs := make([]*job, 0, len(s.jobs))
	for _, j := range s.jobs {
		jobs = append(jobs, j)
	}
	s.mu.Unlock()

	out := make([]jobSnapshot, 0, len(jobs))
	for _, j := range jobs {
		snap := j.snapshot()
		if activeOnly && snap.Done {
			continue
		}
		out = append(out, snap)
	}
	sort.Slice(out, func(i, k int) bool {
		return out[i].Started.After(out[k].Started)
	})
	return out
}

func (j *job) isDone() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.done
}

func (j *job) publish(evt jobEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()

	// Coalesce pure progress ticks for the same archive so reconnect history stays small.
	if evt.Type == "archive" && evt.Status == "running" && evt.Error == "" && evt.ArchiveID != "" {
		if n := len(j.events); n > 0 {
			last := j.events[n-1]
			if last.Type == "archive" && last.ArchiveID == evt.ArchiveID && last.Status == "running" && last.Error == "" {
				// Replace previous running tick for this archive.
				j.events[n-1] = evt
			} else {
				j.events = append(j.events, evt)
			}
		} else {
			j.events = append(j.events, evt)
		}
	} else {
		j.events = append(j.events, evt)
	}

	key := evt.ArchiveID
	if evt.Type == "job" {
		key = ""
	}
	j.latest[key] = evt

	for sub := range j.subs {
		select {
		case sub <- evt:
		default:
			// Subscriber is slow: drop this tick. Snapshot/latest still has the truth.
		}
	}
}

func (j *job) close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.done = true
	j.finished = time.Now()
	for sub := range j.subs {
		close(sub)
		delete(j.subs, sub)
	}
}

func (j *job) snapshot() jobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()

	events := make([]jobEvent, 0, len(j.latest)+1)
	// Job-level first, then archives sorted by index.
	if jobEvt, ok := j.latest[""]; ok {
		events = append(events, jobEvt)
	}
	var archiveEvts []jobEvent
	for key, evt := range j.latest {
		if key == "" {
			continue
		}
		archiveEvts = append(archiveEvts, evt)
	}
	sort.Slice(archiveEvts, func(i, k int) bool {
		return archiveEvts[i].Index < archiveEvts[k].Index
	})
	events = append(events, archiveEvts...)

	status := "running"
	message := ""
	if jobEvt, ok := j.latest[""]; ok {
		if jobEvt.Status != "" {
			status = jobEvt.Status
		}
		message = jobEvt.Message
	}
	if j.done && status == "running" {
		status = "done"
	}

	snap := jobSnapshot{
		ID:      j.id,
		Done:    j.done,
		Root:    j.root,
		Total:   j.total,
		Started: j.started,
		Status:  status,
		Message: message,
		Events:  events,
	}
	if j.done && !j.finished.IsZero() {
		finished := j.finished
		snap.Finished = &finished
	}
	return snap
}

func (j *job) subscribe() ([]jobEvent, chan jobEvent) {
	// Larger buffer so progress bursts after reconnect are less likely to drop.
	ch := make(chan jobEvent, 256)
	j.mu.Lock()
	defer j.mu.Unlock()
	// Prefer compact latest snapshot over full raw history for reconnect speed.
	history := make([]jobEvent, 0, len(j.latest)+1)
	if jobEvt, ok := j.latest[""]; ok {
		history = append(history, jobEvt)
	}
	var archiveEvts []jobEvent
	for key, evt := range j.latest {
		if key == "" {
			continue
		}
		archiveEvts = append(archiveEvts, evt)
	}
	sort.Slice(archiveEvts, func(i, k int) bool {
		return archiveEvts[i].Index < archiveEvts[k].Index
	})
	history = append(history, archiveEvts...)
	if j.done {
		close(ch)
		return history, ch
	}
	j.subs[ch] = struct{}{}
	return history, ch
}

func (j *job) unsubscribe(ch chan jobEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, ok := j.subs[ch]; ok {
		delete(j.subs, ch)
		close(ch)
	}
}

func streamJobEvents(w http.ResponseWriter, r *http.Request, j *job) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	history, ch := j.subscribe()
	defer j.unsubscribe(ch)

	send := func(evt jobEvent) bool {
		data, _ := json.Marshal(evt)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	for _, evt := range history {
		if !send(evt) {
			return
		}
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			if !send(evt) {
				return
			}
		}
	}
}

func streamJobWebSocket(w http.ResponseWriter, r *http.Request, j *job) {
	conn, err := upgradeWebSocket(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer conn.Close()

	history, ch := j.subscribe()
	defer j.unsubscribe(ch)

	for _, evt := range history {
		if err := writeWebSocketJSON(conn, evt); err != nil {
			return
		}
	}
	for evt := range ch {
		if err := writeWebSocketJSON(conn, evt); err != nil {
			return
		}
	}
}

func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if !headerContainsToken(r.Header, "Connection", "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("websocket upgrade required")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, errors.New("missing websocket key")
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("websocket unsupported")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}
	accept := websocketAcceptKey(key)
	if _, err := rw.WriteString(
		"HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n",
	); err != nil {
		conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func websocketAcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func headerContainsToken(header http.Header, name, token string) bool {
	for _, part := range strings.Split(header.Get(name), ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func writeWebSocketJSON(conn net.Conn, evt jobEvent) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	return writeWebSocketTextFrame(conn, data)
}

func writeWebSocketTextFrame(conn net.Conn, payload []byte) error {
	header := []byte{0x81}
	switch n := len(payload); {
	case n <= 125:
		header = append(header, byte(n))
	case n <= 65535:
		header = append(header, 126, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(n))
	default:
		header = append(header, 127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[len(header)-8:], uint64(n))
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func withEvent(base jobEvent, status string, percent int, message, errText string) jobEvent {
	base.Status = status
	base.Percent = percent
	base.Message = message
	base.Error = errText
	return base
}

func cleanAbs(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func normalizeScanDepth(depth int) int {
	switch {
	case depth <= 0:
		return defaultScanDepth
	case depth > maxScanDepth:
		return maxScanDepth
	default:
		return depth
	}
}

func normalizeConflictPolicy(policy string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "", "skip":
		return "skip", nil
	case "overwrite":
		return "overwrite", nil
	case "rename":
		return "rename", nil
	default:
		return "", errors.New("invalid conflict policy")
	}
}

func isInside(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func isSplitArchive(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	return strings.HasSuffix(name, ".001") || name == "001"
}

func isSupportedArchive(path string) bool {
	if isSplitArchive(path) {
		return true
	}
	_, ok := supportedSingleExtensions[strings.ToLower(filepath.Ext(path))]
	return ok
}

func archiveFormat(path string) string {
	if isSplitArchive(path) {
		base := strings.TrimSuffix(strings.ToLower(filepath.Base(path)), filepath.Ext(path))
		switch filepath.Ext(base) {
		case ".zip":
			return "zip"
		case ".7z":
			return "7z"
		default:
			return "split"
		}
	}
	return strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
}

func dirDepth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return len(strings.Split(filepath.Clean(rel), string(os.PathSeparator)))
}

func archiveID(path string) string {
	sum := sha1.Sum([]byte(filepath.Clean(path)))
	return hex.EncodeToString(sum[:])
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
