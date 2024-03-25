package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Check wether kernel supports XDP or not
	err := features.HaveProgramType(ebpf.XDP)
	if errors.Is(err, ebpf.ErrNotSupported) {
		fmt.Println("XDP program type is not supported")
		return
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs dropObjects
	if err := loadDropObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Execute `ip a` command for network interfaces and change this to an interface on your machine.
	ifname := "lo"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	var port uint32 = 9254

	// put port number on which packets should be dropped.
	err = objs.PortMap.Put(uint32(0), port)
	if err != nil {
		log.Printf("Unable to set port number default port will be used (default: 4040)\n %s", err)
	}

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DropPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Dropping incoming packets on interface %s", ifname)

	var preDroppedPkts uint32
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var currDroppedPkts uint32
			err := objs.PktCount.Lookup(uint32(0), &currDroppedPkts)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}

			if preDroppedPkts != currDroppedPkts {
				preDroppedPkts = currDroppedPkts
				log.Printf("%d packet(s) are dropped on PORT:%d\n", preDroppedPkts, port)
			}

		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
