package main

import pluginloader "github.com/carminecesarano/mal_dependency/plugin"

func main() {
	pluginloader.LoadAndInvokePlugin("./plugin/plugin.so", "PluginFunc")
}
