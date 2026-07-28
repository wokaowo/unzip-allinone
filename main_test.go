package main

import (
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
	if err := a.extractOne(j, jobEvent{Type: "archive", JobID: j.id, ArchiveID: info.ID}, info, info.DefaultPassword, "overwrite"); err != nil {
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
		"/tmp/demo.7z.001": "7z",
		"/tmp/001":         "split",
	}
	for input, want := range tests {
		if got := archiveFormat(input); got != want {
			t.Fatalf("archiveFormat(%q) = %q, want %q", input, got, want)
		}
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
