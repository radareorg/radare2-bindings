package main

import (
	"fmt"
	"os"
	"r_core"
)

func main() {
	cmd := "?e Hello World"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	c := r_core.NewRCore()
	fmt.Print(c.Cmd_str(cmd))
}
