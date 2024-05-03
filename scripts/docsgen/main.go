package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/coder/envbuilder"
)

const (
	startSection = "<!--- START docsgen --->"
	endSection   = "<!--- END docsgen --->"
)

func main() {
	readmePath := "README.md"
	readmeFile, err := os.ReadFile(readmePath)
	if err != nil {
		panic("error reading " + readmePath + " file")
	}
	readmeContent := string(readmeFile)
	startIndex := strings.Index(readmeContent, startSection)
	endIndex := strings.Index(readmeContent, endSection)
	if startIndex == -1 || endIndex == -1 {
		panic("start or end section comments not found in the file.")
	}

	var options envbuilder.Options
	mkd := "\n## Environment Variables\n\n" + options.Markdown()
	modifiedContent := readmeContent[:startIndex+len(startSection)] + mkd + readmeContent[endIndex:]

	err = os.WriteFile(readmePath, []byte(modifiedContent), 0o644)
	if err != nil {
		panic(err)
	}

	fmt.Println("README updated successfully with the latest flags!")
}
