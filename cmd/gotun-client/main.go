package main

import (
	"fmt"
	"os"

	"github.com/legion/go-tun/internal/gotunclient"
)

func main() {
	if err := gotunclient.Run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "gotun-client: %v\n", err)
		os.Exit(1)
	}
}
