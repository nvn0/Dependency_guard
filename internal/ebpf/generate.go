package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -go-package ebpf -output-dir . -no-strip program program.bpf.c
