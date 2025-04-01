.PHONY: all clean build cap-enforce sys-enforce

# Functional test: testExec
#TARGET_NAME ?= testExec
#BINARY ?= ../testPkgs/testExec/testExec

# Experiment 1: frps
#TARGET_NAME ?= frps
#BINARY ?= ../exp1/frp/target/bin/$(TARGET_NAME)

# Experiment 1: geth
#TARGET_NAME ?= geth
#BINARY ?= ../exp1/go-ethereum/$(TARGET_NAME)

# Experiment 1: etcd
#TARGET_NAME ?= etcd
#BINARY ?= ../exp1/etcd/target/bin/$(TARGET_NAME)

# Malicious Behaviors
TARGET_NAME ?= testMalicious
BINARY ?= ../exp1/testMalicious/target/$(TARGET_NAME)

all: bpf_loader

bpf_loader: main.go
	TARGET_CMD=$(TARGET_NAME) go generate
	go build -o bpf_loader

build:
	sudo ./bpf_loader -binary $(BINARY) -mode build

cap-enforce:
	sudo ./bpf_loader -binary $(BINARY) -mode cap-enforce

sys-enforce:
	sudo ./bpf_loader -binary $(BINARY) -mode sys-enforce

clean:
	rm -f bpf_loader
	rm -r *.o
	rm ebpf_*
