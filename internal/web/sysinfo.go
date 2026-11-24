package web

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SystemMetrics struct {
	CPUPercent   float64 `json:"cpu_percent"`
	RAMPercent   float64 `json:"ram_percent"`
	RAMUsedGB    float64 `json:"ram_used_gb"`
	RAMTotalGB   float64 `json:"ram_total_gb"`
	NICName      string  `json:"nic_name"`
	NICSpeed     string  `json:"nic_speed"`
	NICSpeedMbps int     `json:"nic_speed_mbps"`
}

var (
	cpuMu      sync.Mutex
	prevIdle   uint64
	prevTotal  uint64
	hasPrevCPU bool

	nicMu        sync.Mutex
	cachedNIC    string
	cachedSpeed  string
	cachedMbps   int
	nicCachedAt  time.Time
)

func ReadSystemMetrics() SystemMetrics {
	nicName, nicSpeed, nicMbps := getCachedNICInfo()
	m := SystemMetrics{
		NICName:      nicName,
		NICSpeed:     nicSpeed,
		NICSpeedMbps: nicMbps,
	}
	if runtime.GOOS != "linux" {
		return m
	}
	m.CPUPercent = readLinuxCPU()
	m.RAMPercent, m.RAMUsedGB, m.RAMTotalGB = readLinuxRAM()
	return m
}

func formatNICSpeed(mbps int) string {
	if mbps <= 0 {
		return ""
	}
	if mbps >= 1000 {
		if mbps%1000 == 0 {
			return fmt.Sprintf("%dGbps", mbps/1000)
		}
		return fmt.Sprintf("%.1fGbps", float64(mbps)/1000.0)
	}
	return fmt.Sprintf("%dMbps", mbps)
}

func getCachedNICInfo() (name, speedLabel string, speedMbps int) {
	if envSpeed := strings.TrimSpace(os.Getenv("HOST_NIC_SPEED")); envSpeed != "" {
		return "host", envSpeed, 0
	}

	nicMu.Lock()
	if !nicCachedAt.IsZero() && time.Since(nicCachedAt) < 60*time.Second {
		n, s, m := cachedNIC, cachedSpeed, cachedMbps
		nicMu.Unlock()
		return n, s, m
	}
	nicMu.Unlock()

	if runtime.GOOS == "linux" {
		name, speedLabel, speedMbps = readLinuxNIC()
	} else {
		name, speedLabel, speedMbps = readGenericNIC()
	}

	nicMu.Lock()
	cachedNIC = name
	cachedSpeed = speedLabel
	cachedMbps = speedMbps
	nicCachedAt = time.Now()
	nicMu.Unlock()
	return name, speedLabel, speedMbps
}

func isVirtualNICName(name string) bool {
	if name == "lo" {
		return true
	}
	for _, prefix := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "tailscale", "wg", "tun", "tap", "kube", "wl"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func scanSysClassNet(netDir string) (physName, physSpeedLabel string, physMbps int, fallbackUp string) {
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return "", "", 0, ""
	}

	for _, ent := range entries {
		name := ent.Name()
		if isVirtualNICName(name) {
			continue
		}
		base := filepath.Join(netDir, name)
		opBytes, err := os.ReadFile(filepath.Join(base, "operstate"))
		if err != nil || strings.TrimSpace(string(opBytes)) != "up" {
			continue
		}
		if fallbackUp == "" {
			fallbackUp = name
		}

		// Must be backed by a real hardware/PCI/virtio device
		if _, devErr := os.Stat(filepath.Join(base, "device")); devErr != nil {
			continue
		}

		// Exclude veth pairs (where iflink != ifindex)
		ifIdx, err1 := os.ReadFile(filepath.Join(base, "ifindex"))
		ifLnk, err2 := os.ReadFile(filepath.Join(base, "iflink"))
		if err1 == nil && err2 == nil && strings.TrimSpace(string(ifIdx)) != strings.TrimSpace(string(ifLnk)) {
			continue
		}

		// Exclude explicit virtual DEVTYPE in uevent
		if uev, err := os.ReadFile(filepath.Join(base, "uevent")); err == nil {
			uevStr := string(uev)
			if strings.Contains(uevStr, "DEVTYPE=veth") || strings.Contains(uevStr, "DEVTYPE=bridge") {
				continue
			}
		}

		spBytes, spErr := os.ReadFile(filepath.Join(base, "speed"))
		if spErr != nil {
			continue
		}
		mbps, err := strconv.Atoi(strings.TrimSpace(string(spBytes)))
		if err != nil || mbps <= 0 {
			continue
		}
		if mbps > physMbps {
			physMbps = mbps
			physName = name
			physSpeedLabel = formatNICSpeed(mbps)
		}
	}
	return physName, physSpeedLabel, physMbps, fallbackUp
}

func readNICDriver(ifaceDir string) string {
	for _, p := range []string{
		filepath.Join(ifaceDir, "device", "uevent"),
		filepath.Join(filepath.Dir(filepath.Dir(ifaceDir)), "uevent"),
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "DRIVER=") {
				return strings.TrimSpace(strings.TrimPrefix(line, "DRIVER="))
			}
		}
	}
	return ""
}

func friendlyDriverLabel(driver string) string {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "virtio_net":
		return "VirtIO NIC"
	case "vmxnet3":
		return "VMXNET3"
	case "hv_netvsc":
		return "Hyper-V NIC"
	case "xen-netfront", "vif":
		return "Xen NIC"
	case "e1000", "e1000e":
		return "1Gbps (e1000)"
	case "":
		return "Virtual NIC"
	default:
		return strings.ToUpper(driver) + " NIC"
	}
}

func isIfaceUp(ifaceDir string) bool {
	opBytes, err := os.ReadFile(filepath.Join(ifaceDir, "operstate"))
	if err != nil {
		return false
	}
	op := strings.TrimSpace(string(opBytes))
	if op == "up" {
		return true
	}
	if op == "unknown" {
		carBytes, err := os.ReadFile(filepath.Join(ifaceDir, "carrier"))
		return err == nil && strings.TrimSpace(string(carBytes)) == "1"
	}
	return false
}

func scanPCINetDevices(devicesDir string) (physName, physSpeedLabel string, physMbps int) {
	topEntries, err := os.ReadDir(devicesDir)
	if err != nil {
		return "", "", 0
	}

	var fallbackVMName, fallbackVMLabel string

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > 6 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			name := ent.Name()
			if name == "power" || name == "iommu" || name == "iommu_group" || name == "subsystem" || name == "driver" || name == "firmware_node" {
				continue
			}
			full := filepath.Join(dir, name)
			if name == "net" {
				ifaces, err := os.ReadDir(full)
				if err != nil {
					continue
				}
				for _, iface := range ifaces {
					in := iface.Name()
					if isVirtualNICName(in) {
						continue
					}
					ifaceDir := filepath.Join(full, in)
					if !isIfaceUp(ifaceDir) {
						continue
					}
					drv := readNICDriver(ifaceDir)
					displayName := in
					if drv != "" {
						displayName = fmt.Sprintf("%s (%s)", in, drv)
					}

					spBytes, spErr := os.ReadFile(filepath.Join(ifaceDir, "speed"))
					if spErr == nil {
						if mbps, err := strconv.Atoi(strings.TrimSpace(string(spBytes))); err == nil && mbps > 0 {
							if mbps > physMbps {
								physMbps = mbps
								physName = displayName
								physSpeedLabel = formatNICSpeed(mbps)
							}
							continue
						}
					}
					if fallbackVMName == "" {
						fallbackVMName = displayName
						fallbackVMLabel = friendlyDriverLabel(drv)
					}
				}
				continue
			}
			walk(full, depth+1)
		}
	}

	for _, ent := range topEntries {
		if !ent.IsDir() {
			continue
		}
		n := ent.Name()
		if strings.HasPrefix(n, "pci") || strings.HasPrefix(n, "vif") || strings.HasPrefix(n, "vmbus") {
			walk(filepath.Join(devicesDir, n), 1)
		}
	}
	if physName != "" {
		return physName, physSpeedLabel, physMbps
	}
	return fallbackVMName, fallbackVMLabel, 0
}

func scanBusNetDevices(busDir string) (string, string, int) {
	entries, err := os.ReadDir(busDir)
	if err != nil {
		return "", "", 0
	}
	for _, ent := range entries {
		netDir := filepath.Join(busDir, ent.Name(), "net")
		ifaces, err := os.ReadDir(netDir)
		if err != nil {
			continue
		}
		for _, iface := range ifaces {
			in := iface.Name()
			if isVirtualNICName(in) {
				continue
			}
			ifaceDir := filepath.Join(netDir, in)
			if !isIfaceUp(ifaceDir) {
				continue
			}
			drv := readNICDriver(ifaceDir)
			displayName := in
			if drv != "" {
				displayName = fmt.Sprintf("%s (%s)", in, drv)
			}
			if spBytes, err := os.ReadFile(filepath.Join(ifaceDir, "speed")); err == nil {
				if mbps, err := strconv.Atoi(strings.TrimSpace(string(spBytes))); err == nil && mbps > 0 {
					return displayName, formatNICSpeed(mbps), mbps
				}
			}
			return displayName, friendlyDriverLabel(drv), 0
		}
	}
	return "", "", 0
}

func readLinuxNIC() (string, string, int) {
	if name, label, mbps := scanPCINetDevices("/host/sys/devices"); name != "" && mbps > 0 {
		return name, label, mbps
	}
	if name, label, mbps := scanPCINetDevices("/sys/devices"); name != "" && mbps > 0 {
		return name, label, mbps
	}
	if name, label, mbps, _ := scanSysClassNet("/host/sys/class/net"); name != "" {
		return name, label, mbps
	}
	if name, label, mbps, _ := scanSysClassNet("/sys/class/net"); name != "" {
		return name, label, mbps
	}
	// VM hypervisor NICs without numeric PHY speed (e.g., KVM/Proxmox virtio_net, Hyper-V hv_netvsc, Xen vif)
	if name, label, mbps := scanPCINetDevices("/host/sys/devices"); name != "" {
		return name, label, mbps
	}
	if name, label, mbps := scanPCINetDevices("/sys/devices"); name != "" {
		return name, label, mbps
	}
	if name, label, mbps := scanBusNetDevices("/host/sys/bus/vmbus/devices"); name != "" {
		return name, label, mbps
	}
	if name, label, mbps := scanBusNetDevices("/sys/bus/vmbus/devices"); name != "" {
		return name, label, mbps
	}
	_, _, _, fallbackUp := scanSysClassNet("/sys/class/net")
	if fallbackUp != "" {
		return fallbackUp, "Virtual NIC", 0
	}
	return "", "Auto", 0
}

func readGenericNIC() (string, string, int) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "Auto", 0
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		return iface.Name, "Auto", 0
	}
	return "", "Auto", 0
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
