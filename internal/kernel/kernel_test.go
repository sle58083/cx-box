package kernel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDefaultDownloadURL(t *testing.T) {
	m := New(t.TempDir(), "")
	u := m.DefaultDownloadURL()
	want := "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-" + runtime.GOOS + "-"
	if !strings.HasPrefix(u, want) || !strings.HasSuffix(u, ".tar.gz") {
		t.Fatalf("url = %s", u)
	}
}

func TestExtractSingBox(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "sb.tar.gz")

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	content := []byte("#!/bin/sh\necho sing-box\n")
	_ = tw.WriteHeader(&tar.Header{Name: "sing-box-1.14.4-linux-amd64/sing-box", Size: int64(len(content)), Mode: 0o755, Typeflag: tar.TypeReg})
	_, _ = tw.Write(content)
	_ = tw.WriteHeader(&tar.Header{Name: "sing-box-1.14.4-linux-amd64/LICENSE", Size: 3, Mode: 0o644, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("MIT"))
	_ = tw.Close()
	_ = gz.Close()
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "sing-box")
	if err := extractSingBox(archive, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("dest content = %q, err %v", got, err)
	}
}

// 回归：经 HTTP apply 触发的 Restart 传入的是请求级 ctx，请求结束即取消；
// 内核进程绝不能因此被杀（Start 内部与调用方 ctx 解耦）。
func TestStartSurvivesCallerContextCancel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses shell script as fake binary")
	}
	dir := t.TempDir()
	m := New(dir, "")
	bin := m.BinaryPath()
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nsleep 30\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	cancel() // 模拟请求结束
	time.Sleep(300 * time.Millisecond)
	if !m.Running() {
		t.Fatal("kernel died with caller context; Start must detach from caller ctx")
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}
