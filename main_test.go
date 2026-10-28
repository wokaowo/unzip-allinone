package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanArchivesDepthAndDefaultPassword(t *testing.T) {
	root := t.TempDir()
	inRange := filepath.Join(root, "alpha", "b", "c", "d", "e")
	tooDeep := filepath.Join(root, "alpha", "b", "c", "d", "e", "f")
	if err := os.MkdirAll(inRange, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tooDeep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inRange, "demo.7z.001"), []byte("part"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tooDeep, "skip.7z.001"), []byte("part"), 0o644); err != nil {
		t.Fatal(err)
	}

	archives, err := scanArchives(root, defaultScanDepth, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) != 1 {
		t.Fatalf("expected 1 archive, got %d: %#v", len(archives), archives)
	}
	if archives[0].DefaultPassword != "alpha" {
		t.Fatalf("expected default password alpha, got %q", archives[0].DefaultPassword)
	}
}

func TestScanArchivesSupportsBasicFormats(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"demo.zip", "demo.7z", "demo.7z.001", "ignore.rar"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("part"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	archives, err := scanArchives(root, defaultScanDepth, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) != 3 {
		t.Fatalf("expected 3 supported archives, got %d: %#v", len(archives), archives)
	}
	formats := map[string]bool{}
	for _, archive := range archives {
		formats[archive.Format] = true
	}
	for _, format := range []string{"zip", "7z"} {
		if !formats[format] {
			t.Fatalf("expected format %q in scanned archives, got %#v", format, formats)
		}
	}
}

func TestScanArchivesIncludeHiddenAndDepth(t *testing.T) {
	root := t.TempDir()
	hiddenDir := filepath.Join(root, ".secret")
	deepDir := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(hiddenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hiddenDir, "hidden.7z.001"), []byte("part"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepDir, "deep.7z.001"), []byte("part"), 0o644); err != nil {
		t.Fatal(err)
	}

	archives, err := scanArchives(root, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) != 0 {
		t.Fatalf("expected no archives with shallow non-hidden scan, got %d", len(archives))
	}

	archives, err = scanArchives(root, 3, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) != 2 {
		t.Fatalf("expected 2 archives with hidden/deeper scan, got %d", len(archives))
	}
}

func TestDiscoverPartsForPlain001Name(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"001", "002", "003"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("skip"), 0o644); err != nil {
		t.Fatal(err)
	}

	parts, total := discoverParts(filepath.Join(dir, "001"))
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %#v", len(parts), parts)
	}
	if total != 9 {
		t.Fatalf("expected total size 9, got %d", total)
	}
}

func TestExtractOneWith7zaVolume(t *testing.T) {
	sevenZip, err := find7za()
	if err != nil {
		t.Skip(err)
	}

	root := t.TempDir()
	dir := filepath.Join(root, "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(source, []byte("hello from test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	archiveBase := filepath.Join(dir, "demo.7z")
	cmd := exec.Command(sevenZip, "a", "-t7z", "-v1k", "-palpha", archiveBase, source)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create archive: %v\n%s", err, out)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}

	info, err := buildArchiveInfo(root, archiveBase+".001")
	if err != nil {
		t.Fatal(err)
	}
	j := newJob()
	a := &app{sevenZip: sevenZip, jobs: &jobStore{jobs: map[string]*job{}}}
	if _, err := a.extractOne(j, jobEvent{Type: "archive", JobID: j.id, ArchiveID: info.ID}, info, info.DefaultPassword, "overwrite", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("expected extracted file: %v", err)
	}
}

func TestNormalizeConflictPolicy(t *testing.T) {
	tests := map[string]string{
		"":          "skip",
		"skip":      "skip",
		"overwrite": "overwrite",
		"rename":    "rename",
	}
	for input, want := range tests {
		got, err := normalizeConflictPolicy(input)
		if err != nil {
			t.Fatalf("normalizeConflictPolicy(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Fatalf("normalizeConflictPolicy(%q) = %q, want %q", input, got, want)
		}
	}
	if _, err := normalizeConflictPolicy("bad"); err == nil {
		t.Fatal("expected invalid policy to fail")
	}
}

func TestArchiveFormat(t *testing.T) {
	tests := map[string]string{
		"/tmp/demo.zip":    "zip",
		"/tmp/demo.7z":     "7z",
		"/tmp/demo.wim":    "wim",
		"/tmp/demo.esd":    "esd",
		"/tmp/demo.swm":    "swm",
		"/tmp/demo.7z.001": "7z",
		"/tmp/001":         "split",
	}
	for input, want := range tests {
		if got := archiveFormat(input); got != want {
			t.Fatalf("archiveFormat(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestScanArchivesSupportsWim(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"install.wim", "image.esd", "install.swm"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("image"), 0o644); err != nil {
			t.Fatal(err)
		}
		if !isSupportedArchive(filepath.Join(dir, name)) {
			t.Fatalf("%s must be a supported archive", name)
		}
	}

	archives, err := scanArchives(root, defaultScanDepth, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) != 3 {
		t.Fatalf("expected three image archives, got %#v", archives)
	}
	formats := map[string]bool{}
	for _, archive := range archives {
		formats[archive.Format] = true
	}
	for _, format := range []string{"wim", "esd", "swm"} {
		if !formats[format] {
			t.Fatalf("expected format %q, got %#v", format, formats)
		}
	}
}

func TestFindSplitArchives(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"inner.7z.001", "inner.7z.002", "skip.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"001", "002"} {
		if err := os.WriteFile(filepath.Join(sub, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got := findSplitArchives(dir)
	if len(got) != 2 {
		t.Fatalf("expected 2 split sets, got %#v", got)
	}
}

// A container archive whose payload is a 001/002 split set must be expanded in
// the same task, not left for a second scan.
func TestExtractOneExpandsNestedSplitArchive(t *testing.T) {
	sevenZip, err := find7za()
	if err != nil {
		t.Skip(err)
	}

	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}

	const want = "nested payload content that is long enough to span volumes"
	payload := filepath.Join(work, "payload.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat(want+"\n", 200)), 0o644); err != nil {
		t.Fatal(err)
	}

	inner := filepath.Join(work, "inner.7z")
	cmd := exec.Command(sevenZip, "a", "-t7z", "-mx0", "-v1k", "-palpha", inner, payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create inner archive: %v\n%s", err, out)
	}
	if err := os.Remove(payload); err != nil {
		t.Fatal(err)
	}
	parts, _ := filepath.Glob(inner + ".0*")
	if len(parts) < 2 {
		t.Fatalf("expected a multi-volume inner archive, got %#v", parts)
	}

	outer := filepath.Join(work, "outer.7z")
	args := append([]string{"a", "-t7z", outer}, parts...)
	if out, err := exec.Command(sevenZip, args...).CombinedOutput(); err != nil {
		t.Fatalf("create outer archive: %v\n%s", err, out)
	}
	for _, part := range parts {
		if err := os.Remove(part); err != nil {
			t.Fatal(err)
		}
	}

	a := newTestApp(t)
	info, err := buildArchiveInfo(work, outer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.extractOne(newJob(), jobEvent{}, info, "alpha", "overwrite", false); err != nil {
		t.Fatalf("extractOne failed: %v", err)
	}

	extracted := filepath.Join(work, "payload.txt")
	got, err := os.ReadFile(extracted)
	if err != nil {
		t.Fatalf("nested payload was not expanded: %v", err)
	}
	if !strings.Contains(string(got), want) {
		t.Fatalf("nested payload content mismatch")
	}
}

// Plain "001"/"002" volumes (no format extension) must be expanded too — this is
// the exact naming a WIM payload often uses.
func TestExtractOneExpandsPlainNumberedVolumes(t *testing.T) {
	sevenZip, err := find7za()
	if err != nil {
		t.Skip(err)
	}

	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}

	payload := filepath.Join(work, "payload.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("plain volume data\n", 200)), 0o644); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(work, "inner.7z")
	if out, err := exec.Command(sevenZip, "a", "-t7z", "-mx0", "-v1k", inner, payload).CombinedOutput(); err != nil {
		t.Fatalf("create inner archive: %v\n%s", err, out)
	}
	if err := os.Remove(payload); err != nil {
		t.Fatal(err)
	}

	// Rename inner.7z.001/002/... to plain 001/002/... before packing into outer.
	parts, _ := filepath.Glob(inner + ".0*")
	if len(parts) < 2 {
		t.Fatalf("expected multi-volume archive, got %#v", parts)
	}
	plain := make([]string, 0, len(parts))
	for i, part := range parts {
		plainName := filepath.Join(work, fmt.Sprintf("%03d", i+1))
		if err := os.Rename(part, plainName); err != nil {
			t.Fatal(err)
		}
		plain = append(plain, plainName)
	}

	outer := filepath.Join(work, "outer.7z")
	args := append([]string{"a", "-t7z", outer}, plain...)
	if out, err := exec.Command(sevenZip, args...).CombinedOutput(); err != nil {
		t.Fatalf("create outer archive: %v\n%s", err, out)
	}
	for _, part := range plain {
		if err := os.Remove(part); err != nil {
			t.Fatal(err)
		}
	}

	a := newTestApp(t)
	info, err := buildArchiveInfo(work, outer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.extractOne(newJob(), jobEvent{}, info, "", "overwrite", false); err != nil {
		t.Fatalf("extractOne failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(work, "payload.txt"))
	if err != nil {
		t.Fatalf("plain numbered payload was not expanded: %v", err)
	}
	if !strings.Contains(string(got), "plain volume data") {
		t.Fatalf("plain numbered payload content mismatch")
	}
}

func TestDecodePasswordSlang(t *testing.T) {
	tests := map[string]string{
		"":           "",
		"alpha":      "alpha",
		"星":          "*",
		"星号":         "*",
		"点斜点":        "./.",
		"点斜杠点":       "./.",
		"abc星def":    "abc*def",
		"前缀点斜点后缀":    "前缀./.后缀",
		"用户下划线名":     "用户_名",
		"a杠b":        "a-b",
		"井号tag":      "#tag",
		"mix星点斜点下划线": "mix*./._",
		// Plain passwords without slang stay unchanged.
		"p@ss.w*rd": "p@ss.w*rd",
	}
	for input, want := range tests {
		if got := decodePasswordSlang(input); got != want {
			t.Fatalf("decodePasswordSlang(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestConsume7zTokenProgress(t *testing.T) {
	progress := make(chan int, 8)
	logs := make(chan string, 8)

	// p7zip-style redraw tokens after splitting on backspace.
	consume7zToken("  0%", progress, logs)
	consume7zToken(" 45%", progress, logs)
	consume7zToken("100%", progress, logs)
	// Scan phase must not be treated as extract percent.
	consume7zToken("  0M Scan /tmp/", progress, logs)

	close(progress)
	close(logs)

	var got []int
	for p := range progress {
		got = append(got, p)
	}
	if len(got) != 3 || got[0] != 0 || got[1] != 45 || got[2] != 100 {
		t.Fatalf("unexpected progress values: %#v", got)
	}
}

func TestScan7zOutputBackspaceProgress(t *testing.T) {
	// Simulate p7zip in-place progress: "  0%\b\b\b\b  50%\b\b\b\b 100%"
	raw := "  0%\x08\x08\x08\x08  50%\x08\x08\x08\x08 100%\nEverything is Ok\n"
	progress := make(chan int, 16)
	logs := make(chan string, 16)
	scan7zOutput(strings.NewReader(raw), progress, logs)
	close(progress)
	close(logs)

	var got []int
	for p := range progress {
		got = append(got, p)
	}
	if len(got) < 2 {
		t.Fatalf("expected multiple progress ticks, got %#v", got)
	}
	if got[len(got)-1] != 100 {
		t.Fatalf("expected last progress 100, got %#v", got)
	}
	foundOK := false
	for line := range logs {
		if strings.Contains(strings.ToLower(line), "everything is ok") {
			foundOK = true
		}
	}
	if !foundOK {
		t.Fatal("expected Everything is Ok log line")
	}
}

func TestJobSnapshotSurvivesProgressFlood(t *testing.T) {
	j := newJob()
	j.total = 2
	j.root = "/tmp/demo"
	j.publish(jobEvent{Type: "job", JobID: j.id, Status: "running", Message: "任务已开始", Total: 2})
	for p := 0; p <= 100; p += 5 {
		j.publish(jobEvent{
			Type: "archive", JobID: j.id, Status: "running",
			ArchiveID: "a1", ArchiveName: "one.7z", Index: 1, Total: 2, Percent: p,
			Message: "解压中",
		})
	}
	j.publish(jobEvent{
		Type: "archive", JobID: j.id, Status: "done",
		ArchiveID: "a1", ArchiveName: "one.7z", Index: 1, Total: 2, Percent: 100,
	})

	snap := j.snapshot()
	if snap.Total != 2 {
		t.Fatalf("snapshot total = %d", snap.Total)
	}
	if snap.Status != "running" {
		t.Fatalf("snapshot status = %q", snap.Status)
	}
	// Compact: job + one archive latest (done), not 20+ progress events.
	if len(snap.Events) > 4 {
		t.Fatalf("expected compact snapshot, got %d events", len(snap.Events))
	}
	history, ch := j.subscribe()
	j.unsubscribe(ch)
	if len(history) > 4 {
		t.Fatalf("subscribe history too large: %d", len(history))
	}
	var foundDone bool
	for _, evt := range history {
		if evt.ArchiveID == "a1" && evt.Status == "done" {
			foundDone = true
		}
	}
	if !foundDone {
		t.Fatalf("expected done archive in history: %#v", history)
	}
}

// makeEncrypted7z builds an encrypted archive containing one file with the given
// content and returns the archive path plus the path the content extracts to.
func makeEncrypted7z(t *testing.T, root, dirName, password, content string) (archivePath, extractedPath string) {
	t.Helper()
	sevenZip, err := find7za()
	if err != nil {
		t.Skip(err)
	}
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(payload, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	archivePath = filepath.Join(dir, "data.7z")
	cmd := exec.Command(sevenZip, "a", "-t7z", "-p"+password, archivePath, payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create archive: %v\n%s", err, out)
	}
	if err := os.Remove(payload); err != nil {
		t.Fatal(err)
	}
	return archivePath, payload
}

func newTestApp(t *testing.T) *app {
	t.Helper()
	sevenZip, err := find7za()
	if err != nil {
		t.Skip(err)
	}
	return &app{sevenZip: sevenZip, jobs: &jobStore{jobs: map[string]*job{}}}
}

// A wrong password must fail without writing anything into the target dir.
// Previously 7-Zip wrote full-size garbage before reporting the failure.
func TestExtractOneWrongPasswordLeavesNoPartialFiles(t *testing.T) {
	root := t.TempDir()
	archive, extracted := makeEncrypted7z(t, root, "alpha", "RIGHTPW", "the real content")

	a := newTestApp(t)
	info, err := buildArchiveInfo(root, archive)
	if err != nil {
		t.Fatal(err)
	}
	j := newJob()
	if _, err := a.extractOne(j, jobEvent{Type: "archive", ArchiveID: info.ID}, info, "WRONGPW", "skip", false); err == nil {
		t.Fatal("expected wrong password to fail")
	}
	if _, err := os.Stat(extracted); !os.IsNotExist(err) {
		t.Fatalf("wrong password left a partial file behind at %s", extracted)
	}
	entries, err := os.ReadDir(filepath.Dir(archive))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != filepath.Base(archive) {
			t.Fatalf("unexpected leftover in target dir: %s", entry.Name())
		}
	}
}

// The core corruption regression: a failed attempt must not poison a later retry.
// Before staging, the failed run left garbage that "skip existing" preserved,
// and the retry then reported success over corrupt data.
func TestRetryAfterWrongPasswordYieldsCorrectContent(t *testing.T) {
	root := t.TempDir()
	const want = "the real content"
	archive, extracted := makeEncrypted7z(t, root, "alpha", "RIGHTPW", want)

	a := newTestApp(t)
	info, err := buildArchiveInfo(root, archive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.extractOne(newJob(), jobEvent{}, info, "WRONGPW", "skip", false); err == nil {
		t.Fatal("expected first attempt to fail")
	}
	if _, err := a.extractOne(newJob(), jobEvent{}, info, "RIGHTPW", "skip", false); err != nil {
		t.Fatalf("retry with correct password failed: %v", err)
	}
	got, err := os.ReadFile(extracted)
	if err != nil {
		t.Fatalf("expected extracted file after retry: %v", err)
	}
	if string(got) != want {
		t.Fatalf("retry produced corrupt content: got %q, want %q", got, want)
	}
}

func TestCommitStagedAppliesConflictPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy      string
		wantContent string
		wantRenamed bool
	}{
		{"skip", "existing", false},
		{"overwrite", "fresh", false},
		{"rename", "existing", true},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			base := t.TempDir()
			staging := filepath.Join(base, "staging")
			target := filepath.Join(base, "target")
			for _, dir := range []string{staging, target} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(target, "f.txt"), []byte("existing"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(staging, "f.txt"), []byte("fresh"), 0o644); err != nil {
				t.Fatal(err)
			}

			if _, err := commitStaged(staging, target, tc.policy); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(target, "f.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.wantContent {
				t.Fatalf("policy %q: f.txt = %q, want %q", tc.policy, got, tc.wantContent)
			}
			_, err = os.Stat(filepath.Join(target, "f (2).txt"))
			if tc.wantRenamed && err != nil {
				t.Fatalf("policy rename: expected 'f (2).txt' to exist: %v", err)
			}
			if !tc.wantRenamed && err == nil {
				t.Fatalf("policy %q: unexpected renamed copy created", tc.policy)
			}
		})
	}
}

// Committing must merge into an existing directory, not replace it.
func TestCommitStagedMergesDirectories(t *testing.T) {
	base := t.TempDir()
	staging := filepath.Join(base, "staging", "shared")
	target := filepath.Join(base, "target", "shared")
	for _, dir := range []string{staging, target} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(target, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "add.txt"), []byte("add"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := commitStaged(filepath.Join(base, "staging"), filepath.Join(base, "target"), "skip"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"keep.txt", "add.txt"} {
		if _, err := os.Stat(filepath.Join(target, name)); err != nil {
			t.Fatalf("expected %s to survive the merge: %v", name, err)
		}
	}
}

// A wrong password must never delete the original archive.
func TestVerifyArchiveGuardsOriginalDeletion(t *testing.T) {
	root := t.TempDir()
	archive, _ := makeEncrypted7z(t, root, "alpha", "RIGHTPW", "content")
	a := newTestApp(t)
	info, err := buildArchiveInfo(root, archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.verifyArchive(context.Background(), info, "WRONGPW"); err == nil {
		t.Fatal("expected verifyArchive to reject a wrong password")
	}
	if err := a.verifyArchive(context.Background(), info, "RIGHTPW"); err != nil {
		t.Fatalf("expected verifyArchive to accept the correct password: %v", err)
	}
}

func TestScanArchivesSkipsStagingDirs(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, stagingPrefix+"abc123")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "leftover.zip"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	archives, err := scanArchives(root, defaultScanDepth, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) != 0 {
		t.Fatalf("staging leftovers must not be scanned, got %#v", archives)
	}
}

func TestJobOutcomeClassification(t *testing.T) {
	tests := []struct {
		name            string
		success, failed int
		cancelled       bool
		want            string
	}{
		{"all succeeded", 3, 0, false, "done"},
		{"all failed", 0, 3, false, "failed"},
		{"partially failed", 2, 1, false, "partial"},
		{"cancelled wins", 1, 1, true, "cancelled"},
		{"nothing processed", 0, 0, false, "done"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := jobOutcome(tc.success, tc.failed, tc.cancelled); got != tc.want {
				t.Fatalf("jobOutcome(%d, %d, %v) = %q, want %q", tc.success, tc.failed, tc.cancelled, got, tc.want)
			}
		})
	}
}

// An all-failed job must not be described as success.
func TestBuildJobSummaryDistinguishesFailure(t *testing.T) {
	allFailed := buildJobSummary(3, 0, 3, 0, false)
	if !strings.Contains(allFailed, "全部失败") {
		t.Fatalf("all-failed summary should say 全部失败, got %q", allFailed)
	}
	if strings.Contains(allFailed, "全部成功") {
		t.Fatalf("all-failed summary must not claim success: %q", allFailed)
	}
	partial := buildJobSummary(3, 2, 1, 0, false)
	if !strings.Contains(partial, "部分完成") {
		t.Fatalf("partial summary should say 部分完成, got %q", partial)
	}
	success := buildJobSummary(3, 3, 0, 0, false)
	if !strings.Contains(success, "全部成功") {
		t.Fatalf("success summary should say 全部成功, got %q", success)
	}
}

func TestParseArchiveListingDetectsSplitParts(t *testing.T) {
	out := `Path = /tmp/pack.wim
Type = wim
Physical Size = 4096

----------

Path = payload.7z.001
Size = 1000
Attributes = A
Folder = -

Path = payload.7z.002
Size = 2000
Attributes = A
Folder = -

Path = docs
Attributes = D
Folder = +

Path = readme.txt
Size = 12
Attributes = A
Folder = -
`
	listing := parseArchiveListing(out)
	if !listing.HasNested {
		t.Fatal("expected nested split set to be detected")
	}
	if listing.NestedBytes != 3000 {
		t.Fatalf("NestedBytes = %d, want 3000", listing.NestedBytes)
	}
}

func TestParseArchiveListingPlainNumberedVolumes(t *testing.T) {
	out := `Path = /tmp/pack.zip
Type = zip
Physical Size = 100

----------

Path = 001
Size = 500
Attributes = A
Folder = -

Path = 002
Size = 700
Attributes = A
Folder = -

Path = notes.txt
Size = 3
Attributes = A
Folder = -
`
	listing := parseArchiveListing(out)
	if !listing.HasNested {
		t.Fatal("expected plain numbered volumes to be detected")
	}
	if listing.NestedBytes != 1200 {
		t.Fatalf("NestedBytes = %d, want 1200", listing.NestedBytes)
	}
}

func TestParseArchiveListingWithoutVolumes(t *testing.T) {
	out := `Path = /tmp/plain.7z
Type = 7z
Physical Size = 100

----------

Path = file.txt
Size = 20
Attributes = A
Folder = -
`
	listing := parseArchiveListing(out)
	if listing.HasNested || listing.NestedBytes != 0 {
		t.Fatalf("expected no nested volumes, got %#v", listing)
	}
}

func TestPhaseBoundary(t *testing.T) {
	// No nested payload: the outer archive owns the whole bar.
	if got := phaseBoundary(1000, 0); got != 100 {
		t.Fatalf("phaseBoundary(1000, 0) = %d, want 100", got)
	}
	// Half and half split by bytes, clamped into a visible range.
	if got := phaseBoundary(1000, 1000); got != 50 {
		t.Fatalf("phaseBoundary(1000, 1000) = %d, want 50", got)
	}
	// A tiny outer with a huge payload still leaves room to see the first phase.
	if got := phaseBoundary(1, 100000); got != 10 {
		t.Fatalf("phaseBoundary(1, 100000) = %d, want clamped 10", got)
	}
}

// The nested tracker must keep the outer archive's bar advancing after the first
// phase, never jumping backwards or past 100.
func TestNestedTrackerProgressIsMonotonic(t *testing.T) {
	j := newJob()
	var percents []int
	// Capture published events via a subscriber.
	ch := make(chan jobEvent, 512)
	j.mu.Lock()
	j.subs[ch] = struct{}{}
	j.mu.Unlock()

	tracker := &nestedTracker{j: j, base: jobEvent{Type: "archive", ArchiveID: "outer"}, start: 60, end: 100}
	tracker.addBytes(1000)
	tracker.addBytes(1000)
	tracker.beginSet(1000)
	for _, p := range []int{0, 50, 100} {
		tracker.progress(p, "")
	}
	tracker.completeSet()
	tracker.beginSet(1000)
	for _, p := range []int{0, 50, 100} {
		tracker.progress(p, "")
	}
	tracker.completeSet()
	tracker.finish()

	close(ch)
	for evt := range ch {
		percents = append(percents, evt.Percent)
	}
	if len(percents) == 0 {
		t.Fatal("expected progress events")
	}
	prev := -1
	for _, p := range percents {
		if p < prev {
			t.Fatalf("percent went backwards: %v", percents)
		}
		if p > 100 {
			t.Fatalf("percent exceeded 100: %v", percents)
		}
		prev = p
	}
	if percents[len(percents)-1] != 100 {
		t.Fatalf("expected final percent 100, got %v", percents)
	}
}

// extractOne must advertise both phases when a container holds a split set, and
// the reported bar must climb monotonically from 0 to 100 across them.
func TestExtractOnePublishesTwoPhaseProgress(t *testing.T) {
	sevenZip, err := find7za()
	if err != nil {
		t.Skip(err)
	}

	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}

	payload := filepath.Join(work, "payload.txt")
	if err := os.WriteFile(payload, []byte(strings.Repeat("nested two-phase data\n", 400)), 0o644); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(work, "inner.7z")
	if out, err := exec.Command(sevenZip, "a", "-t7z", "-mx0", "-v1k", "-palpha", inner, payload).CombinedOutput(); err != nil {
		t.Fatalf("create inner archive: %v\n%s", err, out)
	}
	if err := os.Remove(payload); err != nil {
		t.Fatal(err)
	}
	parts, _ := filepath.Glob(inner + ".0*")
	if len(parts) < 2 {
		t.Fatalf("expected multi-volume archive, got %#v", parts)
	}
	outer := filepath.Join(work, "outer.7z")
	args := append([]string{"a", "-t7z", outer}, parts...)
	if out, err := exec.Command(sevenZip, args...).CombinedOutput(); err != nil {
		t.Fatalf("create outer archive: %v\n%s", err, out)
	}
	for _, part := range parts {
		if err := os.Remove(part); err != nil {
			t.Fatal(err)
		}
	}

	a := newTestApp(t)
	info, err := buildArchiveInfo(work, outer)
	if err != nil {
		t.Fatal(err)
	}
	j := newJob()
	ch := make(chan jobEvent, 4096)
	j.mu.Lock()
	j.subs[ch] = struct{}{}
	j.mu.Unlock()

	phases := map[string]bool{}
	percents := []int{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for evt := range ch {
			if evt.Type != "archive" || evt.Status != "running" {
				continue
			}
			if evt.Phase != "" {
				phases[evt.Phase] = true
			}
			percents = append(percents, evt.Percent)
		}
	}()

	if _, err := a.extractOne(j, jobEvent{Type: "archive", ArchiveID: info.ID}, info, "alpha", "overwrite", false); err != nil {
		t.Fatalf("extractOne failed: %v", err)
	}
	j.unsubscribe(ch)
	<-done

	if !phases["analyze"] || !phases["outer"] || !phases["nested"] || !phases["commit"] {
		t.Fatalf("expected analyze/outer/nested/commit phases, got %#v", phases)
	}
	prev := -1
	for _, p := range percents {
		if p < prev {
			t.Fatalf("percent went backwards: %v", percents)
		}
		prev = p
	}
}

// A cancelled job must abort nested extraction with context.Canceled so the
// caller does not commit a half-expanded payload.
func TestExtractNestedAbortsOnCancel(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"001", "002"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("part"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	j := newJob()
	j.cancel()

	a := &app{}
	tracker := &nestedTracker{j: j, base: jobEvent{Type: "archive", ArchiveID: "outer"}, start: 50, end: 100}
	if _, err := a.extractNested(j, "", dir, false, map[string]bool{}, 0, tracker); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if tracker.doneBytes != 0 {
		t.Fatalf("cancelled extraction must not account work as done, got %d", tracker.doneBytes)
	}
}
