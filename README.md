# GoLeash <img src="logo.jpg" width="45" height="30" alt="Logo" style="vertical-align: middle;"> 
Runtime enforcement of software supply chain capabilities in Go

# Runnable example
Run a Go program invoking some denied capability, with goleash runtime enforcement attached. 

```bash
cd examples/example_unrestrict
```

First, generate the hashes for allowed invocations of capabilities, for the *trusted* initial version of the program. 

```bash
make all-hash
```

Execute the trusted version of the program.
```bash
make all
```

Then, add a new denied capability invocation to the program. 
```bash
sed -i '27,31s/^[[:space:]]*\/\/[[:space:]]*TestReadFile()/TestReadFile()/' dependencyC/dep.go
```

Execute the compromised version of the program, with the same previously generated hashes.
```bash
make all
```


# Syscall tracing
This tool allows you to track syscalls for a specified binary using eBPF.

## Prerequisites
-

## Building the Tracer

1. Navigate to the `track_syscalls` folder and build the tracer
```bash
cd track_syscalls
make
```

## Testing with CoreDNS

To demonstrate the syscall tracking capabilities, we'll use CoreDNS as an example.

### Compiling CoreDNS

1. Navigate to the CoreDNS folder and compile CoreDNS using the provided script:
```bash
./build.sh
```
This will generate the coreDNS binary to run later.

### Generate an allowlist for the CoreDNS Syscalls

2. Navigate back to the `track_syscalls` folder and run the syscall tracker (with root privileges), pointing it to the CoreDNS binary:
```bash
sudo ./bpf_loader -binary /binary_path -mod-manifest /go.mod -mode build
```

Replace `/binary_path` and `/go.mod` with the actual path to the binary and go manifest of the application you want to monitor.


### Start CoreDNS and send a test request
3.  In a new terminal window run coreDNS
```bash
./coredns/run.sh
```

CoreDNS will start with a default configuration.

4. To trigger some operations to track, you can send a request to coreDNS

```bash
./make_request.sh
```

This script will send a DNS query to the running CoreDNS instance.

4. Observe the syscall tracking output in the terminal where you ran `bpf_loader`.

You should now see the syscalls triggered by CoreDNS in response to the DNS query. Closing the tracker with CTRL+C, the allowlist will be saved. 



