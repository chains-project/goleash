// dependencyB/dep.go
package dependencyB

import (
	"fmt"
	"os"

	"github.com/jung-kurt/gofpdf"
)

func TestChmod() {
	// Create a temporary file
	tempFile, err := os.CreateTemp("", "example")
	if err != nil {
		fmt.Println("Error creating temp file:", err)
	}
	defer os.Remove(tempFile.Name())

	// Get the current permissions
	info, err := tempFile.Stat()
	if err != nil {
		fmt.Println("Error getting file info:", err)
	}
	fmt.Printf("Initial permissions: %v\n", info.Mode().Perm())

	// Change the permissions using Chmod
	err = tempFile.Chmod(0644)
	if err != nil {
		fmt.Println("Error changing permissions:", err)
	}

	// Get the updated permissions
	info, err = tempFile.Stat()
	if err != nil {
		fmt.Println("Error getting updated file info:", err)
	}
	fmt.Printf("Updated permissions: %v\n", info.Mode().Perm())

	tempFile.Close()
}

func TestWriteFile() {
	data := []byte("Hello, World!")
	err := os.WriteFile("./example1.txt", data, 0644)
	if err != nil {
		fmt.Printf("error reading file")
	}
}

func TestReadFile() {
	_, err := os.ReadFile("./example1.txt")
	if err != nil {
		fmt.Printf("error reading file")
	}
}

func CallPDF() {

	//	TestChmod()
	TestWriteFile()
	TestReadFile()

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Hello, world")
	pdf.OutputFileAndClose("hello.pdf")

}
