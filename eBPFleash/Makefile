.PHONY: all clean build cap-enforce sys-enforce

TARGET_NAME ?= default

# Functional test: testExec
# BINARIES ?= ../testPkgs/testExec/testExec

# Malicious Behaviors
#BINARIES ?= ../exp1/testMalicious/target/testMalicious

# Experiment 1: frps
#BINARIES ?= ../exp1/frp/target/bin/frps \
# 			../exp1/frp/target/bin/frpc

# Experiment 1: geth
#BINARIES ?= ../exp1/go-ethereum/geth

# Experiment 1: coredns
#BINARIES ?= ../exp1/coredns/target/coredns

# Experiment 1: etcd
#BINARIES ?= ../exp1/etcd/target/bin/etcd \
#			../exp1/etcd/target/bin/etcdctl \
#			../exp1/etcd/target/bin/etcdutl

# Experiment 1: kubernetes
BINARIES ?= ../exp1/kubernetes/target/_output/local/bin/linux/amd64/kube-apiserver \
            ../exp1/kubernetes/target/_output/local/bin/linux/amd64/kube-controller-manager \
            ../exp1/kubernetes/target/_output/local/bin/linux/amd64/kube-scheduler \
            ../exp1/kubernetes/target/_output/local/bin/linux/amd64/kube-proxy \
            ../exp1/kubernetes/target/_output/local/bin/linux/amd64/kubelet \
            ../exp1/kubernetes/target/_output/local/bin/linux/amd64/kubectl \
            ../exp1/kubernetes/target/_output/local/bin/linux/amd64/kubeadm

space := $(empty) $(empty)
comma := ,
BINARY_ARGS := $(subst $(space),$(comma),$(BINARIES))

all: bpf_loader

bpf_loader: main.go
	TARGET_CMD=$(TARGET_NAME) go generate
	go build -o bpf_loader

build:
	sudo ./bpf_loader -binary $(BINARY_ARGS) -mode build

cap-enforce:
	sudo ./bpf_loader -binary $(BINARY_ARGS) -mode cap-enforce

sys-enforce:
	sudo ./bpf_loader -binary $(BINARY_ARGS) -mode sys-enforce

clean:
	rm -f bpf_loader
	rm -r *.o
	rm ebpf_*
