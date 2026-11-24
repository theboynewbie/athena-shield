package web

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

type SystemMetrics struct {
	CPUPercent float64 `json:"cpu_percent"`
	RAMPercent float64 `json:"ram_percent"`
	RAMUsedGB  float64 `json:"ram_used_gb"`
	RAMTotalGB float64 `json:"ram_total_gb"`
}

var (
	cpuMu       sync.Mutex
	prevIdle    uint64
	prevTotal   uint64
	hasPrevCPU  bool
)

func ReadSystemMetrics() SystemMetrics {
	if runtime.GOOS != "linux" {
		return SystemMetrics{}
	}
	var m SystemMetrics
	m.CPUPercent = readLinuxCPU()
	m.RAMPercent, m.RAMUsedGB, m.RAMTotalGB = readLinuxRAM()
	return m
}

func readLinuxCPU() float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 {
		return 0
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}
	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if !hasPrevCPU {
		prevIdle = idle
		prevTotal = total
		hasPrevCPU = true
		return 0
	}
	dt := total - prevTotal
	di := idle - prevIdle
	prevTotal = total
	prevIdle = idle
	if dt == 0 {
		return 0
	}
	pct := float64(dt-di) / float64(dt) * 100.0
	return float64(int(pct*10)) / 10
}

func readLinuxRAM() (pct, usedGB, totalGB float64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0
	}
	var memTotalKB, memAvailKB uint64
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			memTotalKB, _ = strconv.ParseUint(fields[1], 10, 64)
		case "MemAvailable:":
			memAvailKB, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}
	if memTotalKB == 0 {
		return 0, 0, 0
	}
	usedKB := memTotalKB - memAvailKB
	totalGB = float64(int(float64(memTotalKB)/(1024*1024)*10)) / 10
	usedGB = float64(int(float64(usedKB)/(1024*1024)*10)) / 10
	pct = float64(int(float64(usedKB)/float64(memTotalKB)*1000)) / 10
	return pct, usedGB, totalGB
}
