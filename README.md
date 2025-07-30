# GoLeash <img src="logo.jpg" width="45" height="30" alt="Logo" style="vertical-align: middle;"> 

GoLeash is a eBPF-based runtime policy enforcement tool designed to defend Go applications against software supply chain attacks. It enforces the principle of least privilege at the package level, identifying and blocking unauthorized or malicious behavior introduced via compromised dependencies. 

GoLeash monitors system calls at runtime to:
- Detect when Go packages use system capabilities they shouldn't (e.g., making network connections, modifying files).
- Mitigate the impact of malicious or overprivileged third-party dependencies.
- Remain effective even under advanced code obfuscation techniques. 

Modes of Operations
- **Analysis Mode**: Automatically profiles legitimate runtime behavior by observing system calls and stack traces to generate fine-grained, per-package allowlists.
- **Enforcement Mode**: At runtime, validates syscalls against the previously generated policies, blocking  logging violations.


See the paper: [GoLeash: Mitigating Golang Software Supply Chain Attacks
with Runtime Policy Enforcement](https://arxiv.org/pdf/2505.11016)


## Requirements
- llvm
- clang
- libbpf-dev
- gcc-multilib

## Runnable example: FRP (Fast Reverse Proxy)
We provide a runnable example of GoLeash in action, using FRP (Fast Reverse Proxy), a reverse proxy written in Go. This example demonstrates how to profile, generate, and enforce package-level capability policies against FRP's ```frpc``` (client) and ```frps``` (server) binaries.

### Setup the target application

First, clone the repository:
```bash
git clone https://github.com/fatedier/frp.git
```

GoLeash uses Go symbol information for stack resolution. To enable this:
- In the FRP ```Makefile```, remove ```-ldflags "$(LDFLAGS)"``` from the compilation rule. 
- Or more generally, remove ```-w -s``` flags, which strip debug information.

Still in the Makefile, set 
```bash
CGO_ENABLED=1
```

Finally, compile both server and client binaries:
```bash
cd frp
make
```

Optional: You can increase test parallelism in ```/hack/run-e2e.sh``` by modifying the ```concurrency``` parameter.


### Configure and Compile GoLeash
Edit the ```config.toml``` file in GoLeash to tell it which binaries to monitor: 

```toml
[targets]
binaries = [
  "frpc",
  "frps"
]
binary_paths = [
  "..frp/bin/frps",
  "..frp/target/bin/frpc"
]
```

Compile GoLeash 
```bash
cd goleash
make
```

### Run Profiling and Enforcement
Run FRP's end-to-end tests while GoLeash monitors execution to build a policy.

First, run GoLeash in the analysis mode. 
```bash
make build
```

Then, in another shell, run the end-to-end tests:
```bash
cd frp
make e2e
```
You can run this multiple times to improve coverage in the policy. When done, stop goleash (CTRL+C) and the policy will be saved in the current directory (```trace\store.json```).


To simulate a violation, manually remove a capability from ```tracestore.json``` for any package. Then launch GoLeash in enforcement mode, when executing again e2e test. 
```bash
cd goleash
make cap-enforce
```


**Note**: For more runnable examples, see ```execute_target.md```



