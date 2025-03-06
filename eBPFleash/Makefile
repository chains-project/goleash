.PHONY: all clean build cap-enforce sys-enforce

TARGET ?= testExec
TARGET_DIR ?= ../testPkgs/testExec
BINARY ?= $(TARGET_DIR)/$(TARGET)
MANIFEST ?= $(TARGET_DIR)/go.mod

all: bpf_loader

bpf_loader: main.go
	TARGET_CMD=$(TARGET) go generate
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
