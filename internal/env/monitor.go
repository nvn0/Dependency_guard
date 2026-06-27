package env

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"Dependency_guard/internal/ebpf"
	"Dependency_guard/internal/env/utils"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
)

func Monitor(projectName string) {
	_, containerID, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project info: %v\n", err)
		return
	}

	config, err := utils.GetConfigInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project config: %v\n", err)
		return
	}

	if !config.Ebpf.Enabled {
		fmt.Println("eBPF monitoring is disabled in the project config")
		return
	}

	containerPIDValue, err := utils.GetContainerPID(containerID)
	if err != nil {
		fmt.Printf("Error getting container PID: %v\n", err)
		return
	}

	containerPID, err := strconv.Atoi(containerPIDValue)
	if err != nil {
		fmt.Printf("Error parsing container PID %q: %v\n", containerPIDValue, err)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	monitor, err := ebpf.StartMonitor(ctx, ebpf.MonitorConfig{
		ProjectName:      projectName,
		ContainerID:      containerID,
		ContainerPID:     containerPID,
		DenyPaths:        config.Ebpf.DenyPaths,
		NetworkWhitelist: config.Ebpf.Whitelist,
	})
	if err != nil {
		fmt.Printf("Error starting eBPF monitor: %v\n", err)
		return
	}
	defer func() {
		if err := monitor.Close(); err != nil {
			fmt.Printf("Error closing eBPF monitor: %v\n", err)
		}
	}()

	fmt.Printf("Monitoring project %s container %s with PID %d. Press Ctrl+C to stop.\n", projectName, containerID, containerPID)

	for {
		select {
		case event, ok := <-monitor.Events():
			if !ok {
				return
			}
			printMonitorEvent(event)
		case err, ok := <-monitor.Errors():
			if ok && err != nil {
				fmt.Printf("eBPF monitor error: %v\n", err)
			}
			return
		case <-ctx.Done():
			fmt.Println("\nStopping eBPF monitor")
			return
		}
	}
}

func printMonitorEvent(event ebpf.Event) {
	if event.Type == ebpf.EventOpen || event.Type == ebpf.EventConnect {
		fmt.Printf("[%s] pid=%d tgid=%d uid=%d comm=%s data=%s\n", event.TypeName(), event.PID, event.TGID, event.UID, event.Comm, event.Data)
		return
	}

	if event.Type == ebpf.EventConnectResult {
		status := "success"
		if event.Ret < 0 {
			status = "failed"
			fmt.Printf(Red + "[%s] pid=%d tgid=%d uid=%d comm=%s ret=%d status=%s" + Reset + "\n", event.TypeName(), event.PID, event.TGID, event.UID, event.Comm, event.Ret, status)
			return
		}
		fmt.Printf(Green + "[%s] pid=%d tgid=%d uid=%d comm=%s ret=%d status=%s" + Reset + "\n", event.TypeName(), event.PID, event.TGID, event.UID, event.Comm, event.Ret, status)
		return
	}

	if event.Data == "" {
		fmt.Printf(Yellow + "[%s] pid=%d tgid=%d uid=%d comm=%s" + Reset + "\n", event.TypeName(), event.PID, event.TGID, event.UID, event.Comm)
		return
	}

	fmt.Printf(Blue + "[%s] pid=%d tgid=%d uid=%d comm=%s data=%s" + Reset + "\n", event.TypeName(), event.PID, event.TGID, event.UID, event.Comm, event.Data)
}
