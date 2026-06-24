package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	EventExec    uint32 = 1
	EventConnect uint32 = 2
	EventOpen    uint32 = 3

	eventCommLen = 16
	eventDataLen = 256
)

type MonitorConfig struct {
	ProjectName      string
	ContainerID      string
	ContainerPID     int
	DenyPaths        []string
	NetworkWhitelist []string
	ObjectPath       string
}

type Event struct {
	PID  uint32
	TGID uint32
	UID  uint32
	Type uint32
	Comm string
	Data string
}

type Monitor struct {
	collection *cebpf.Collection
	reader     *ringbuf.Reader
	links      []link.Link
	events     chan Event
	errs       chan error
	cancel     context.CancelFunc
	closeOnce  sync.Once
}

func StartMonitor(ctx context.Context, cfg MonitorConfig) (*Monitor, error) {
	if cfg.ContainerPID <= 0 {
		return nil, fmt.Errorf("invalid container PID: %d", cfg.ContainerPID)
	}

	spec, err := loadMonitorSpec(cfg.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load eBPF object: %w", err)
	}

	collection, err := cebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create eBPF collection: %w", err)
	}

	cleanup := func() {
		collection.Close()
	}

	if err := setTargetCgroup(collection, cfg.ContainerPID); err != nil {
		cleanup()
		return nil, err
	}

	attachedLinks, err := attachTracepoints(collection)
	if err != nil {
		cleanup()
		return nil, err
	}

	eventsMap := collection.Maps["events"]
	if eventsMap == nil {
		closeLinks(attachedLinks)
		cleanup()
		return nil, errors.New("eBPF map events not found")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		closeLinks(attachedLinks)
		cleanup()
		return nil, fmt.Errorf("open eBPF ring buffer: %w", err)
	}

	monitorCtx, cancel := context.WithCancel(ctx)
	m := &Monitor{
		collection: collection,
		reader:     reader,
		links:      attachedLinks,
		events:     make(chan Event, 64),
		errs:       make(chan error, 1),
		cancel:     cancel,
	}

	go m.readEvents(monitorCtx)

	return m, nil
}

func (m *Monitor) Events() <-chan Event {
	return m.events
}

func (m *Monitor) Errors() <-chan error {
	return m.errs
}

func (m *Monitor) Close() error {
	var closeErr error

	m.closeOnce.Do(func() {
		if m.cancel != nil {
			m.cancel()
		}

		if m.reader != nil {
			if err := m.reader.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
				closeErr = err
			}
		}

		closeLinks(m.links)

		if m.collection != nil {
			m.collection.Close()
		}
	})

	return closeErr
}

func (m *Monitor) readEvents(ctx context.Context) {
	defer close(m.events)
	defer close(m.errs)

	for {
		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			m.errs <- fmt.Errorf("read eBPF event: %w", err)
			return
		}

		event, err := decodeEvent(record.RawSample)
		if err != nil {
			m.errs <- err
			return
		}

		select {
		case m.events <- event:
		case <-ctx.Done():
			return
		}
	}
}

func setTargetCgroup(collection *cebpf.Collection, pid int) error {
	targetMap := collection.Maps["target_cgroup"]
	if targetMap == nil {
		return errors.New("eBPF map target_cgroup not found")
	}

	cgroupPath, err := containerCgroupPath(pid)
	if err != nil {
		return err
	}

	cgroup, err := os.Open(cgroupPath)
	if err != nil {
		return fmt.Errorf("open container cgroup %s: %w", cgroupPath, err)
	}
	defer cgroup.Close()

	var key uint32
	fd := uint32(cgroup.Fd())
	if err := targetMap.Put(key, fd); err != nil {
		return fmt.Errorf("set eBPF target cgroup %s: %w", cgroupPath, err)
	}

	return nil
}

func containerCgroupPath(pid int) (string, error) {
	procPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	contents, err := os.ReadFile(procPath)
	if err != nil {
		return "", fmt.Errorf("read container cgroup for PID %d: %w", pid, err)
	}

	relativePath, err := parseCgroupV2Path(string(contents))
	if err != nil {
		return "", fmt.Errorf("resolve container cgroup for PID %d: %w", pid, err)
	}

	return filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(relativePath, "/")), nil
}

func parseCgroupV2Path(contents string) (string, error) {
	for _, line := range strings.Split(contents, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" && parts[2] != "" {
			return parts[2], nil
		}
	}

	return "", errors.New("cgroup v2 entry not found; a unified cgroup v2 hierarchy is required")
}

func attachTracepoints(collection *cebpf.Collection) ([]link.Link, error) {
	definitions := []struct {
		programName string
		category    string
		name        string
	}{
		{"trace_execve", "syscalls", "sys_enter_execve"},
		{"trace_connect", "syscalls", "sys_enter_connect"},
		{"trace_openat", "syscalls", "sys_enter_openat"},
	}

	links := make([]link.Link, 0, len(definitions))
	for _, definition := range definitions {
		program := collection.Programs[definition.programName]
		if program == nil {
			closeLinks(links)
			return nil, fmt.Errorf("eBPF program %s not found", definition.programName)
		}

		tp, err := link.Tracepoint(definition.category, definition.name, program, nil)
		if err != nil {
			closeLinks(links)
			return nil, fmt.Errorf("attach tracepoint %s/%s: %w", definition.category, definition.name, err)
		}

		links = append(links, tp)
	}

	return links, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}

func decodeEvent(raw []byte) (Event, error) {
	const fixedLen = 16

	if len(raw) < fixedLen+eventCommLen+eventDataLen {
		return Event{}, fmt.Errorf("invalid eBPF event size: got %d bytes", len(raw))
	}

	event := Event{
		PID:  binary.LittleEndian.Uint32(raw[0:4]),
		TGID: binary.LittleEndian.Uint32(raw[4:8]),
		UID:  binary.LittleEndian.Uint32(raw[8:12]),
		Type: binary.LittleEndian.Uint32(raw[12:16]),
		Comm: cString(raw[16 : 16+eventCommLen]),
		Data: cString(raw[16+eventCommLen : 16+eventCommLen+eventDataLen]),
	}

	return event, nil
}

func cString(raw []byte) string {
	if index := bytes.IndexByte(raw, 0); index >= 0 {
		raw = raw[:index]
	}
	return string(raw)
}

func (e Event) TypeName() string {
	switch e.Type {
	case EventExec:
		return "exec"
	case EventConnect:
		return "connect"
	case EventOpen:
		return "open"
	default:
		return fmt.Sprintf("unknown:%d", e.Type)
	}
}

func loadMonitorSpec(objectPath string) (*cebpf.CollectionSpec, error) {
	if objectPath != "" {
		return cebpf.LoadCollectionSpec(objectPath)
	}

	return loadProgram()
}
