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
	
	err := features.HaveProgramType(ebpf.XDP)
	if errors.Is(err, ebpf.ErrNotSupported) {
		fmt.Println("XDP program type is not supported")
		return
	}

	
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}


	var objs dropObjects
	if err := loadDropObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	
	ifname := "lo"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	var port uint32 = 4040


	err = objs.PortMap.Put(uint32(0), port)
	if err != nil {
		log.Printf("Unable to set port number, default port will be used (default: 4040)\n%s", err)
	}

	
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
