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
)

var supportedSingleExtensions = map[string]struct{}{
	".zip": {},
	".7z":  {},
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
	// PasswordDecoded is set on archive start when slang substitution changed the password.
	PasswordDecoded string `json:"passwordDecoded,omitempty"`
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
	for _, name := range []string{"7za", "7z"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", errors.New("install p7zip so 7za or 7z is available in PATH")
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
			writeError(w, http.StatusBadRequest, "archive must be a supported .zip, .7z, or .001 file")
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
	j.publish(jobEvent{
		Type:           "job",
		JobID:          j.id,
		Status:         "running",
		Message:        "任务已开始",
		Total:          total,
		DeleteOriginal: req.DeleteOriginal,
		ConflictPolicy: req.ConflictPolicy,
	})
	defer j.close()

	successCount := 0
	failedCount := 0
	warningCount := 0

	for i, archive := range req.Archives {
		select {
		case <-j.ctx.Done():
			j.publish(jobEvent{
				Type:           "job",
				JobID:          j.id,
				Status:         "cancelled",
				Message:        buildJobSummary(total, successCount, failedCount, warningCount, true),
				Total:          total,
				SuccessCount:   successCount,
				FailedCount:    failedCount,
				WarningCount:   warningCount,
				DeleteOriginal: req.DeleteOriginal,
				ConflictPolicy: req.ConflictPolicy,
			})
			return
		default:
		}

		info, err := buildArchiveInfo(root, archive.Path)
		if err != nil {
			failedCount++
			j.publish(jobEvent{Type: "archive", JobID: j.id, Status: "failed", ArchiveID: archive.ID, Path: archive.Path, Error: err.Error(), Index: i + 1, Total: len(req.Archives)})
			continue
		}
		passwordRaw := strings.TrimSpace(archive.Password)
		if passwordRaw == "" {
			passwordRaw = info.DefaultPassword
		}
		password := decodePasswordSlang(passwordRaw)

		base := jobEvent{Type: "archive", JobID: j.id, ArchiveID: info.ID, ArchiveName: info.Name, Path: info.Path, Index: i + 1, Total: len(req.Archives)}
		startMsg := "正在解压 " + info.RelativeFile
		startEvt := withEvent(base, "running", 0, startMsg, "")
		if password != passwordRaw {
			startEvt.PasswordDecoded = password
			startEvt.Message = startMsg + "（密码黑话已转换）"
		}
		j.publish(startEvt)

		if _, err := a.extractOne(j, base, info, password, req.ConflictPolicy); err != nil {
			if errors.Is(err, context.Canceled) {
				j.publish(jobEvent{
					Type:           "job",
					JobID:          j.id,
					Status:         "cancelled",
					Message:        buildJobSummary(total, successCount, failedCount, warningCount, true),
					Total:          total,
					SuccessCount:   successCount,
					FailedCount:    failedCount,
					WarningCount:   warningCount,
					DeleteOriginal: req.DeleteOriginal,
					ConflictPolicy: req.ConflictPolicy,
				})
				return
			}
			failedCount++
			j.publish(withEvent(base, "failed", 0, "", err.Error()))
			continue
		}

		message := "解压完成"
		if req.DeleteOriginal {
			// Only delete the source after 7-Zip verifies the archive end to end.
			// Extraction succeeding is not proof enough to discard the only copy.
			if err := a.verifyArchive(j.ctx, info, password); err != nil {
				successCount++
				warningCount++
				j.publish(withEvent(base, "warning", 100, "解压完成，但校验未通过，已保留原始压缩包: "+err.Error(), ""))
				continue
			}
			deleted, err := deleteArchiveParts(info.Path)
			if err != nil {
				successCount++
				warningCount++
				j.publish(withEvent(base, "warning", 100, "解压完成，但删除原始分卷失败: "+err.Error(), ""))
				continue
			}
			message = "解压完成，已删除 " + strconv.Itoa(deleted) + " 个原始分卷"
		}
		successCount++
		j.publish(withEvent(base, "done", 100, message, ""))
	}
	j.publish(jobEvent{
		Type:           "job",
		JobID:          j.id,
		Status:         jobOutcome(successCount, failedCount, false),
		Percent:        100,
		Message:        buildJobSummary(total, successCount, failedCount, warningCount, false),
		Total:          total,
		SuccessCount:   successCount,
		FailedCount:    failedCount,
		WarningCount:   warningCount,
		DeleteOriginal: req.DeleteOriginal,
		ConflictPolicy: req.ConflictPolicy,
	})
}

// checkArchivePassword fails fast on a wrong password or an unreadable archive.
// "l -slt" only reads the header, so this costs milliseconds even for multi-GB
// archives and — unlike "x" — writes nothing to disk. Running it first means a
// bad password never gets the chance to spill partial output.
func (a *app) checkArchivePassword(ctx context.Context, info archiveInfo, password string) error {
	cmd := exec.CommandContext(ctx, a.sevenZip, "l", "-slt", "-p"+password, info.Path)
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
	return fmt.Errorf("无法读取压缩包：%s。常见原因：密码错误、分卷缺失或文件损坏", err)
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
func (a *app) extractOne(j *job, base jobEvent, info archiveInfo, password, conflictPolicy string) (commitStats, error) {
	// Fail before creating anything if the password is wrong or the archive is broken.
	if err := a.checkArchivePassword(j.ctx, info, password); err != nil {
		return commitStats{}, err
	}

	staging, err := os.MkdirTemp(info.Directory, stagingPrefix+"*")
	if err != nil {
		return commitStats{}, fmt.Errorf("无法创建临时解压目录: %w", err)
	}
	// Always clear staging: on success commitStaged has already moved everything
	// out, on any failure or cancellation this is what discards the garbage.
	defer os.RemoveAll(staging)

	if err := a.run7z(j, base, info, password, staging); err != nil {
		return commitStats{}, err
	}
	return commitStaged(staging, info.Directory, conflictPolicy)
}

func (a *app) run7z(j *job, base jobEvent, info archiveInfo, password, outDir string) error {
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
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-j.ctx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			<-done
			return context.Canceled
		case p, ok := <-progress:
			if ok && p != last {
				last = p
				j.publish(withEvent(base, "running", p, fmt.Sprintf("解压中 %d%%", p), ""))
			}
		case line, ok := <-logs:
			if ok && shouldSurface7zLine(line) {
				j.publish(withEvent(base, "running", maxInt(last, 0), humanize7zLine(line), ""))
			}
		case <-ticker.C:
			// Keep UI alive; do not spam empty ticks when still at -1 (waiting for first %).
			if last >= 0 {
				j.publish(withEvent(base, "running", last, fmt.Sprintf("解压中 %d%%", last), ""))
			}
		case err := <-done:
			for p := range progress {
				if p != last {
					last = p
					j.publish(withEvent(base, "running", p, fmt.Sprintf("解压中 %d%%", p), ""))
				}
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
