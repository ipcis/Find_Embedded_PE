package main

import (
	"debug/pe"
	"fmt"
	"log"
	"os"
)

func searchMZHeader(data []byte) bool {
	for i := 0; i < len(data)-1; i++ {
		if data[i] == 'M' && data[i+1] == 'Z' {
			return true
		}
	}
	return false
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run find_embedded_pe.go <PE_file_path>")
		os.Exit(1)
	}

	peFilePath := os.Args[1]

	file, err := os.Open(peFilePath)
	if err != nil {
		log.Fatalf("Error opening file: %v\n", err)
	}
	defer file.Close()

	peFile, err := pe.NewFile(file)
	if err != nil {
		log.Fatalf("Error parsing PE file: %v\n", err)
	}

	for _, section := range peFile.Sections {
		fmt.Printf("Section: %s\n", section.Name)
		sectionData, err := section.Data()
		if err != nil {
			log.Fatalf("Error reading section data: %v\n", err)
		}

		if searchMZHeader(sectionData) {
			fmt.Println("Embedded PE header (MZ) found in this section.")
		}
	}
}
