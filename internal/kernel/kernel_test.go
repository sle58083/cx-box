package kernel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
