.PHONY: all clean build

PACKAGE_PATH := $(shell go list -f '{{.Dir}}' -m github.com/carminecesarano/mal_dependency)
PLUGIN_SRC := $(PACKAGE_PATH)/exec/binary/main.go
PLUGIN_DIR := ./binary
PLUGIN_DEST := $(PLUGIN_DIR)/main.go
PLUGIN_SO := $(PLUGIN_DIR)/bin_hello

all: buildBinary buildMain

buildMain: main.go
	go build -o testExec

buildBinary: $(PLUGIN_SRC)
	mkdir binary
	cp $(PLUGIN_SRC) $(PLUGIN_DEST)
	go build -o $(PLUGIN_SO) $(PLUGIN_DEST)

clean:
	rm -f testExec
	rm -rf $(PLUGIN_DIR)
