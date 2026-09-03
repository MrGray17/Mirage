package main

import (
	"fmt"
	"io"
)

var launchDocument = openDocument

func openObservatory(path string, stderr io.Writer) {
	if err := launchDocument(path); err != nil {
		fmt.Fprintf(stderr, "mirage: security run succeeded; could not open Observatory: %v\n", err)
	}
}
