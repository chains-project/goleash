.PHONY: all clean build cap-enforce sys-enforce

all: bpf_loader

bpf_loader: main.go
	go generate
	go build -o bpf_loader

build:
	sudo ./bpf_loader -binary ../../testCGO/testCGO -manifest ../../testCGO/go.mod -mode build

cap-enforce:
	sudo ./bpf_loader -binary ../../testCGO/testCGO -manifest ../../testCGO/go.mod -mode cap-enforce

sys-enforce:
	sudo ./bpf_loader -binary ../../testCGO/testCGO -manifest ../../testCGO/go.mod -mode sys-enforce

clean:
	rm -f bpf_loader
	rm -r *.o
	rm ebpf_*
