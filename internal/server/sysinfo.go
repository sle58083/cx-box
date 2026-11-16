package server

import (
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// serverStats 是状态页展示的服务器运行状态，全部来自 Linux /proc 与
// statfs 采样，不引入外部依赖；读不到时对应字段为 0。
type serverStats struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemTotal      uint64  `json:"mem_total"`
	MemUsed       uint64  `json:"mem_used"`
	MemPercent    float64 `json:"mem_percent"`
	DiskTotal     uint64  `json:"disk_total"`
	DiskUsed      uint64  `json:"disk_used"`
	DiskPercent   float64 `json:"disk_percent"`
	Load1         float64 `json:"load1"`
	UptimeSeconds int64   `json:"uptime_seconds"`
}

var (
	cpuMu       sync.Mutex
	cpuLastTot  uint64
	cpuLastIdle uint64
)

// parseCPUStat 解析 /proc/stat 首行，返回总 jiffies 与空闲（idle+iowait）。
func parseCPUStat(content string) (total, idle uint64, ok bool) {
	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return 0, 0, false
		}
		for i, f := range fields[1:] {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				return 0, 0, false
			}
			total += v
			if i == 3 || i == 4 { // idle, iowait
				idle += v
			}
		}
		return total, idle, true
	}
	return 0, 0, false
}

func readCPUTimes() (uint64, uint64, bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	return parseCPUStat(string(b))
}

// cpuPercent 计算 CPU 使用率：优先用与上次调用的计数差值；首次调用做
// 200ms 短采样。状态页是低频访问，采样开销可忽略。
func cpuPercent() float64 {
	tot, idle, ok := readCPUTimes()
	if !ok {
		return 0
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if cpuLastTot > 0 && tot > cpuLastTot {
		dTot := tot - cpuLastTot
		dIdle := idle - cpuLastIdle
		cpuLastTot, cpuLastIdle = tot, idle
		if dTot == 0 || dIdle > dTot {
			return 0
		}
		return round1(float64(dTot-dIdle) * 100 / float64(dTot))
	}
	cpuLastTot, cpuLastIdle = tot, idle
	time.Sleep(200 * time.Millisecond)
	tot2, idle2, ok := readCPUTimes()
	if !ok || tot2 <= tot {
		return 0
	}
	dTot := tot2 - tot
	dIdle := idle2 - idle
	cpuLastTot, cpuLastIdle = tot2, idle2
	if dIdle > dTot {
		return 0
	}
	return round1(float64(dTot-dIdle) * 100 / float64(dTot))
}

// parseMeminfo 从 /proc/meminfo 内容取 MemTotal/MemAvailable（字节）。
func parseMeminfo(content string) (total, avail uint64) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	return total, avail
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// collectServerStats 汇总一次服务器状态采样。
func collectServerStats() serverStats {
	var st serverStats
	st.CPUPercent = cpuPercent()
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		total, avail := parseMeminfo(string(b))
		st.MemTotal = total
		if total > 0 && avail <= total {
			st.MemUsed = total - avail
			st.MemPercent = round1(float64(st.MemUsed) * 100 / float64(total))
		}
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err == nil && fs.Blocks > 0 {
		st.DiskTotal = fs.Blocks * uint64(fs.Bsize)
		free := fs.Bavail * uint64(fs.Bsize)
		if free <= st.DiskTotal {
			st.DiskUsed = st.DiskTotal - free
			st.DiskPercent = round1(float64(st.DiskUsed) * 100 / float64(st.DiskTotal))
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if fields := strings.Fields(string(b)); len(fields) > 0 {
			st.Load1, _ = strconv.ParseFloat(fields[0], 64)
			st.Load1 = round1(st.Load1)
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if fields := strings.Fields(string(b)); len(fields) > 0 {
			if up, err := strconv.ParseFloat(fields[0], 64); err == nil {
				st.UptimeSeconds = int64(up)
			}
		}
	}
	return st
}
