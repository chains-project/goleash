.PHONY: all clean build

PACKAGE_PATH := $(shell go list -f '{{.Dir}}' -m github.com/carminecesarano/mal_dependency)
PLUGIN_SRC := $(PACKAGE_PATH)/plugin/sources/plugin_main.go
PLUGIN_DIR := ./plugin
PLUGIN_DEST := $(PLUGIN_DIR)/plugin_main.go
PLUGIN_SO := $(PLUGIN_DIR)/plugin.so

all: buildPlugin buildMain

buildMain: main.go
	go build -o testPlugin

buildPlugin: $(PLUGIN_SRC)
	#cp $(PLUGIN_SRC) $(PLUGIN_DEST)
	go build -buildmode=plugin -o $(PLUGIN_SO) $(PLUGIN_DEST)

clean:
	rm -f testPlugin
	rm -f $(PLUGIN_DIR)
