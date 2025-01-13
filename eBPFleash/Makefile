.PHONY: all clean build cap-enforce sys-enforce

TARGET_CMD ?= testCGO
BINARY ?= ../testPkg/testCGO
MANIFEST ?= ../testPkg/go.mod

all: bpf_loader

bpf_loader: main.go
	TARGET_CMD=$(TARGET_CMD) go generate
	go build -o bpf_loader

trace:
	sudo ./bpf_loader -binary $(BINARY) -manifest $(MANIFEST) -mode trace
build:
	sudo ./bpf_loader -binary $(BINARY) -manifest $(MANIFEST) -mode build

cap-enforce:
	sudo ./bpf_loader -binary $(BINARY) -manifest $(MANIFEST) -mode cap-enforce

sys-enforce:
	sudo ./bpf_loader -binary $(BINARY) -manifest $(MANIFEST) -mode sys-enforce

clean:
	rm -f bpf_loader
	rm -r *.o
	rm ebpf_*
