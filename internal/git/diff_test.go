package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const sampleDiff = `diff --git a/a.go b/a.go
index 1111111..2222222 100644
--- a/a.go
+++ b/a.go
@@ -41,0 +42 @@ func a() {
+	added()
@@ -10,2 +10,5 @@ func b() {
-	old()
+	new1()
@@ -15,3 +15,0 @@ func c() {
-	removed()
diff --git a/old.go b/pkg/renamed.go
similarity index 90%
rename from old.go
rename to pkg/renamed.go
--- a/old.go
+++ b/pkg/renamed.go
@@ -3 +3 @@ package pkg
-var x = 1
+var x = 2
diff --git a/gone.go b/gone.go
deleted file mode 100644
--- a/gone.go
+++ /dev/null
@@ -1,3 +0,0 @@
-package gone
diff --git "a/sp ace.go" "b/sp ace.go"
--- "a/sp ace.go"
+++ "b/sp ace.go"
@@ -1 +1,2 @@
+// comment
`

func TestParseUnifiedDiff(t *testing.T) {
	changed, err := ParseUnifiedDiff(strings.NewReader(sampleDiff))
	if err != nil {
		t.Fatal(err)
	}
	want := ChangedLines{
		"a.go":           {{42, 42}, {10, 14}},
		"pkg/renamed.go": {{3, 3}},
		"sp ace.go":      {{1, 2}},
	}
	if !reflect.DeepEqual(changed, want) {
		t.Fatalf("changed = %+v, want %+v", changed, want)
	}
	if !changed.Contains("a.go", 42) || !changed.Contains("a.go", 12) || changed.Contains("a.go", 15) || changed.Contains("a.go", 43) {
		t.Fatal("Contains does not follow the hunks")
	}
	if changed.Touched("gone.go") || !changed.Touched("pkg/renamed.go") {
		t.Fatal("Touched reports deleted or misses renamed files")
	}
	if _, err := ParseUnifiedDiff(strings.NewReader("+++ b/x.go\n@@ broken @@\n")); err == nil {
		t.Fatal("malformed hunk accepted")
	}
}

func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiffAgainstRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q")
	writeFile(t, filepath.Join(repo, "svc", "go.mod"), "module example.com/svc\n")
	writeFile(t, filepath.Join(repo, "svc", "main.go"), "package main\n\nfunc main() {\n}\n")
	writeFile(t, filepath.Join(repo, "other.go"), "package other\n")
	gitCmd(t, repo, "add", ".")
	gitCmd(t, repo, "commit", "-q", "-m", "init")

	writeFile(t, filepath.Join(repo, "svc", "main.go"), "package main\n\nfunc main() {\n\tprintln(1)\n}\n")
	writeFile(t, filepath.Join(repo, "svc", "new.go"), "package main\n")
	writeFile(t, filepath.Join(repo, "other.go"), "package other\n\nvar x = 1\n")

	changed, err := Diff(context.Background(), filepath.Join(repo, "svc"), "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if !changed.Contains("main.go", 4) || changed.Contains("main.go", 3) {
		t.Fatalf("working tree change not detected: %+v", changed)
	}
	if !changed.Contains("new.go", 1) {
		t.Fatalf("untracked file not reported: %+v", changed)
	}
	if changed.Touched("../other.go") || changed.Touched("other.go") {
		t.Fatalf("change outside the directory reported: %+v", changed)
	}
	if _, err := Diff(context.Background(), repo, "--output=/tmp/x"); err == nil {
		t.Fatal("option-like reference accepted")
	}
}
