package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		wups("Exactly one argument expected")
	}
	fmt.Print(newVaultClient(os.Args[1]).getKey())
}
