package server

import "testing"

func TestParseCPUStat(t *testing.T) {
	content := "cpu  100 0 100 600 200 0 0 0 0 0\ncpu0 50 0 50 300 100 0 0 0 0 0\n"
	total, idle, ok := parseCPUStat(content)
	if !ok {
		t.Fatal("应解析成功")
	}
	if total != 1000 || idle != 800 {
		t.Fatalf("total/idle 不符: got %d/%d want 1000/800", total, idle)
	}
	if _, _, ok := parseCPUStat("intr 123\n"); ok {
		t.Fatal("无 cpu 行时应失败")
	}
}

func TestParseMeminfo(t *testing.T) {
	content := "MemTotal:       16384000 kB\nMemFree:         1024000 kB\nMemAvailable:    8192000 kB\n"
	total, avail := parseMeminfo(content)
	if total != 16384000*1024 || avail != 8192000*1024 {
		t.Fatalf("meminfo 解析不符: got %d/%d", total, avail)
	}
}

func TestCollectServerStatsSane(t *testing.T) {
	st := collectServerStats()
	if st.MemTotal == 0 || st.DiskTotal == 0 || st.UptimeSeconds <= 0 {
		t.Fatalf("本机采样应有内存/磁盘/运行时间: %+v", st)
	}
	if st.CPUPercent < 0 || st.CPUPercent > 100 || st.MemPercent < 0 || st.MemPercent > 100 {
		t.Fatalf("百分比越界: %+v", st)
	}
}
