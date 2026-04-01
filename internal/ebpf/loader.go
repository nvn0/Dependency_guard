// internal/ebpf/loader.go
package ebpf

import (
	"log"

	"github.com/cilium/ebpf"
)

func Load() {
	spec, err := ebpf.LoadCollectionSpec("program.o")
	if err != nil {
		log.Fatal(err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("eBPF loaded:", collection)
}
