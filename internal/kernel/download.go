// Package kernel 负责 sing-box 二进制的下载与进程托管。
package kernel

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

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
