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
	if event.Data == "" {
		fmt.Printf("[%s] pid=%d tgid=%d uid=%d comm=%s\n", event.TypeName(), event.PID, event.TGID, event.UID, event.Comm)
		return
	}

	fmt.Printf("[%s] pid=%d tgid=%d uid=%d comm=%s data=%s\n", event.TypeName(), event.PID, event.TGID, event.UID, event.Comm, event.Data)
}
