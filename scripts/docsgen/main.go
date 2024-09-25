package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/coder/envbuilder/options"
)

func main() {
	path := filepath.Join("docs", "env-variables.md")
	var options options.Options
	mkd := "\n# Environment Variables\n\n" + options.Markdown()
	err := os.WriteFile(path, []byte(mkd), 0o644)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s updated successfully with the latest flags!", path)
}
