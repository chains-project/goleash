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