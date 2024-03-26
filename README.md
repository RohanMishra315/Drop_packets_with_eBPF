## drop-packets

A simple program written in Golang along with [eBPF/XDP](https://en.wikipedia.org/wiki/Express_Data_Path) program written in C to drop incoming network packets on a port `P`.
![](./drop-packets-demo.gif)


### how to run

#### for linux
**Step 1:**
```
// install the necessary dependencies to run the program

sudo apt update
sudo apt install clang llvm gcc golang-go
sudo apt install linux-headers-$(uname -r)

sudo apt-get update
sudo apt-get install bpfcc-tools libbpfcc-dev
```

**Step 2:**
```
// clone the repository
git clone github.com/zakisk/drop-packets
```


**Step 3:**
```
// change director to drop-packets
cd drop-packets
```

**Step 4:**
```
// change director to drop-packets
cd drop-packets

// build and run program
go build && sudo ./drop-packets
```

To change the network interface on your machine change `ifname` variable value in [main.go](https://github.com/zakisk/drop-packets/blob/master/main.go) 

here in code:

```go
// Execute `ip a` command for network interfaces and change this to an interface on your machine.
ifname := "lo"
iface, err := net.InterfaceByName(ifname)
if err != nil {
    log.Fatalf("Getting interface %s: %s", ifname, err)
}
```

