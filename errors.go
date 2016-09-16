package main

import (
	"fmt"
	"os"
)

// maybe blow up nicely
func maybeWups(err error) {
	if err != nil {
		wups(err)
	}
}

// blow up nicely
func wups(v interface{}) {
	fmt.Fprintf(os.Stderr, "!! %s\n", v)
	os.Exit(1)
}
