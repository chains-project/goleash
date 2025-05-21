### KUBERNETES

Compile Kubernetes binaries with debug info
```
make all DBG=1
```

Run a Kubernetes cluster and execute e2e tests
```
./run_e2e.sh
```

------------------------------------------------------------------------
### [FRP (Fast Reverse Proxy)](https://github.com/fatedier/frp)

In the Makefile, remove the following flags from the compilation rule, to enable debug info:
```
-ldflags "$(LDFLAGS)"
```

Or, more generally, remove the flags ```-w -s```

Still in the the Makefile, enable CGO:
```
CGO_ENABLED=1
```

Finally, compile FRP binaries:
```
make
```

Execute e2e tests:
```
make e2e
```
Optional: to increase E2E Test Parallelism, in hack/run-e2e.sh, adjust the ```concurrency``` parameter.

------------------------------------------------------------------------

### [ETCD](https://github.com/etcd-io/etcd)

Debug symbols are included by default in the tested version. Otherwise, remove ```-w -s``` from ```/scripts/build_lib.sh```.

In the ```Makefile```, enable CGO:
```
CGO_ENABLED="${CGO_ENABLED:-1}"
```

Finally, execute e2e tests: 
```
make test-e2e GO_TEST_FLAGS="-v"
make test-grpcproxy-e2e GO_TEST_FLAGS="-v"
```

---------------------------------------------------------------------

# [GO-ETHEREUM](https://github.com/ethereum/go-ethereum)

Clone and and build your own debug docker image:
```
git clone -recurse-submodules -j8 https://github.com/ethereum/go-ethereum.git
```

In the file ```go-ethereum/build/ci.go```, remove ```--build-id=none``` and ```--strip-all``` from:
```
extld := []string{"-Wl,-z,stack-size=0x800000,--build-id=none,--strip-all"}
```

Then build the docker image:
```
sudo docker build -t geth-debug:latest .
```

Finally, execute the e2e tests with Hive:
```
git clone https://github.com/ethereum/hive.git
```

In ```/hive/clients/go-ethereum/Dockerfile```, modify: 
```
ARG baseimage=geth-debug
```

Extract the same binary hive executes, from the container:
```
docker run --name geth-debug -d geth-debug
docker cp geth-debug:/usr/local/bin/geth ./geth
docker stop geth-debug
docker rm geth-debug
```

Run Hive Simulations:
```
cd hive
go build
HIVE_PARALLELISM=16 ./hive --sim ethereum/consensus --client go-ethereum
HIVE_PARALLELISM=16 ./hive --sim devp2p --client go-ethereum
```

Monitor Hive logs
```
go build ./cmd/hiveview
./hiveview --serve --logdir ./workspace/logs/
```

After execution, clean up
```
docker image prune -f
```


