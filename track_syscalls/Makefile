.PHONY: all clean

all: hello_ebpf

hello_ebpf: main.go
	go generate
	go build -o hello_ebpf

clean:
	rm -f hello_ebpf
	rm -r *.o
	rm ebpf_*
