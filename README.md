## Problem statement 1: Drop packets using eBPF

Write an eBPF code to drop the TCP packets on a port (def: 4040). Additionally, if you can make the port number configurable from the userspace, that will be a big plus.

## Solution

A simple program written in Golang along with [eBPF/XDP](https://en.wikipedia.org/wiki/Express_Data_Path) program written in C to drop incoming network packets on a port `P`.


![](./drop-packets-demo.gif)


### how to run

#### for linux
**Step 1:**
```bash
# install the necessary dependencies to run the program

sudo apt update
sudo apt install clang llvm gcc golang-go
sudo apt install linux-headers-$(uname -r)

sudo apt-get update
sudo apt-get install bpfcc-tools libbpfcc-dev
```

**Step 2:**
```bash
# clone the repository
git clone github.com/zakisk/drop-packets
```

**Step 3:**
```bash

# build and run program
cd drop-packets
go build && sudo ./drop-packets
```

To change the network interface on your machine change `ifname` variable value in [main.go](https://github.com/zakisk/drop-packets/blob/master/main.go). Execute `ip a` command to list network interfaces available on machine.

here in code:

```go
ifname := "lo"
iface, err := net.InterfaceByName(ifname)
if err != nil {
    log.Fatalf("Getting interface %s: %s", ifname, err)
}
```

