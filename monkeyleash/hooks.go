package monkey

import (
	"fmt"
	"net"
	"os"

	"bou.ke/monkey"
)

//go:noinline
func WriteFileReplace(name string, data []byte, perm os.FileMode) error {
	fmt.Println("os.WriteFile hooked.")
	if err := CheckCapability("os.WriteFile"); err != nil {
		panic(fmt.Sprintf("\n%v", err))
	}
	monkey.Unpatch(os.WriteFile)
	ret1 := os.WriteFile(name, data, perm)
	monkey.Patch(os.WriteFile, WriteFileReplace)
	return ret1
}

//go:noinline
func ReadFileReplace(name string) ([]byte, error) {
	fmt.Println("os.ReadFile hooked.")
	if err := CheckCapability("os.ReadFile"); err != nil {
		panic(fmt.Sprintf("\n%v", err))
	}
	monkey.Unpatch(os.ReadFile)
	ret1, ret2 := os.ReadFile(name)
	monkey.Patch(os.ReadFile, ReadFileReplace)
	return ret1, ret2
}

//go:noinline
func CreateReplace(name string) (*os.File, error) {
	fmt.Println("os.Create hooked.")
	if err := CheckCapability("os.Create"); err != nil {
		panic(fmt.Sprintf("\n%v", err))
	}
	monkey.Unpatch(os.Create)
	ret1, ret2 := os.Create(name)
	monkey.Patch(os.Create, CreateReplace)
	return ret1, ret2
}

//go:noinline
func ChmodReplace(name string, mode os.FileMode) error {
	fmt.Println("os.Chmod hooked.")
	if err := CheckCapability("os.Chmod"); err != nil {
		panic(fmt.Sprintf("\n%v", err))
	}
	monkey.Unpatch(os.Chmod)
	ret := os.Chmod(name, mode)
	monkey.Patch(os.Chmod, ChmodReplace)
	return ret
}

//go:noinline
func FileChmodReplace(f *os.File, mode os.FileMode) error {
	fmt.Println("(*os.File).Chmod hooked.")
	if err := CheckCapability("(*os.File).Chmod"); err != nil {
		panic(fmt.Sprintf("\n%v", err))
	}
	monkey.Unpatch((*os.File).Chmod)
	ret := f.Chmod(mode)
	monkey.Patch((*os.File).Chmod, FileChmodReplace)
	return ret
}

//go:noinline
func LookupHostReplace(host string) ([]string, error) {
	fmt.Println("net.LookupHost hooked.")
	if err := CheckCapability("net.LookupHost"); err != nil {
		panic(fmt.Sprintf("\n%v", err))
	}
	monkey.Unpatch(net.LookupHost)
	ret1, ret2 := net.LookupHost(host)
	monkey.Patch(net.LookupHost, LookupHostReplace)
	return ret1, ret2
}
