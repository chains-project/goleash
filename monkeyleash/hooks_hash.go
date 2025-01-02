package monkeyleash

import (
	"fmt"
	"net"
	"os"

	"bou.ke/monkey"
)

//go:noinline
func WriteFileReplaceHash(name string, data []byte, perm os.FileMode) error {
	fmt.Println("os.WriteFile hooked for hash.")
	UpdateStackHashes("os.WriteFile")
	monkey.Unpatch(os.WriteFile)
	ret1 := os.WriteFile(name, data, perm)
	monkey.Patch(os.WriteFile, WriteFileReplaceHash)
	return ret1
}

//go:noinline
func ReadFileReplaceHash(name string) ([]byte, error) {
	fmt.Println("os.ReadFile hooked for hash.")
	UpdateStackHashes("os.ReadFile")
	monkey.Unpatch(os.ReadFile)
	ret1, ret2 := os.ReadFile(name)
	monkey.Patch(os.ReadFile, ReadFileReplaceHash)
	return ret1, ret2
}

//go:noinline
func CreateReplaceHash(name string) (*os.File, error) {
	fmt.Println("os.Create hooked for hash.")
	UpdateStackHashes("os.Create")
	monkey.Unpatch(os.Create)
	ret1, ret2 := os.Create(name)
	monkey.Patch(os.Create, CreateReplaceHash)
	return ret1, ret2
}

//go:noinline
func ChmodReplaceHash(name string, mode os.FileMode) error {
	fmt.Println("os.Chmod hooked for hash.")
	UpdateStackHashes("os.Chmod")
	monkey.Unpatch(os.Chmod)
	ret := os.Chmod(name, mode)
	monkey.Patch(os.Chmod, ChmodReplaceHash)
	return ret
}

//go:noinline
func FileChmodReplaceHash(f *os.File, mode os.FileMode) error {
	fmt.Println("(*os.File).Chmod hooked for hash.")
	UpdateStackHashes("(*os.File).Chmod")
	monkey.Unpatch((*os.File).Chmod)
	ret := f.Chmod(mode)
	monkey.Patch((*os.File).Chmod, FileChmodReplaceHash)
	return ret
}

//go:noinline
func LookupHostReplaceHash(host string) ([]string, error) {
	fmt.Println("net.LookupHost hooked for hash.")
	UpdateStackHashes("net.LookupHost")
	monkey.Unpatch(net.LookupHost)
	ret1, ret2 := net.LookupHost(host)
	monkey.Patch(net.LookupHost, LookupHostReplaceHash)
	return ret1, ret2
}
