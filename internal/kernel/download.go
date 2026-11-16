// Package kernel 负责 sing-box 二进制的下载与进程托管。
package kernel

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// extractSingBox 从官方 Release 的 .tar.gz 包中解出 sing-box 二进制到 dest。
// 包内布局为 sing-box-<ver>-<os>-<arch>/sing-box（Windows 为 sing-box.exe）。
func extractSingBox(archivePath, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("压缩包内未找到内核二进制")
		}
		if err != nil {
			return err
		}
		base := filepath.Base(hdr.Name)
		if hdr.Typeflag != tar.TypeReg || (base != "sing-box" && base != "sing-box.exe") {
			continue
		}
		tmp := dest + ".tmp"
		out, err := os.Create(tmp)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			os.Remove(tmp)
			return err
		}
		if err := out.Close(); err != nil {
			os.Remove(tmp)
			return err
		}
		return os.Rename(tmp, dest)
	}
}

// downloadFileWithRetry 下载文件，带重试（镜像回退由调用方处理）。
func downloadFileWithRetry(url, dest string, retries int) error {
	var lastErr error
	for i := 0; i < retries; i++ {
		if err := downloadOnce(url, dest); err == nil {
			return nil
		} else {
			lastErr = err
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}
	return lastErr
}

// downloadOnce 单次下载。
func downloadOnce(url, dest string) error {
	client := &http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}
