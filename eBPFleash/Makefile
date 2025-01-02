.PHONY: all clean

all: bpf_loader

bpf_loader: main.go
	go generate
	go build -o bpf_loader

clean:
	rm -f bpf_loader
	rm -r *.o
	rm ebpf_*
