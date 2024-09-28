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

### Compiling and Running CoreDNS

1. Navigate to the CoreDNS folder. Compile and run CoreDNS using the provided script:
```bash
./build_and_run.sh
```

This script will build CoreDNS and start it with a default configuration.

### Tracking CoreDNS Syscalls

1. In a new terminal window, navigate back to the `track_syscalls` folder.
2. Run the syscall tracker (with root privileges), pointing it to the CoreDNS binary:
```bash
sudo ./hello_ebpf -binary /path/to/the/binary/to/track
```

Replace `/path/to/the/binary/to/track` with the actual path to the binary you want to monitor.

3. The program will start tracking syscalls for the specified binary. You'll see output in the termi>

4. To stop the tracking, press Ctrl+C.


### Sending a Test Request to CoreDNS

To generate some DNS activity and observe the syscalls:

1. Open another terminal window.

2. Execute the test request script:
```bash
./make_request.sh
```

This script will send a DNS query to the running CoreDNS instance.

3. Observe the syscall tracking output in the terminal where you ran `hello_ebpf`.

You should now see the syscalls triggered by CoreDNS in response to the DNS query, allowing you to analyze its behavior at the system call level.



