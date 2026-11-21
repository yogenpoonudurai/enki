package main

import (
	"errors"
	"fmt"
	"os"
)

var errThreshold = errors.New("findings at or above failure threshold")

func main() {
	err := Execute()
	if err == nil {
		return
	}
	if errors.Is(err, errThreshold) {
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "enki:", err)
	os.Exit(2)
}
