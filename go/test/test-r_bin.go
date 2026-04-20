package main

import (
	"fmt"
	"os"
	"r_core"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:", os.Args[0], "<bin>")
		os.Exit(1)
	}
	c := r_core.NewRCore()
	if c.File_open(os.Args[1], 0, 0) == nil {
		fmt.Println("cannot open file")
		os.Exit(1)
	}
	c.Bin_load(os.Args[1], 0)
	b := c.GetBin()
	baddr := b.Get_baddr()
	fmt.Println("-> Sections")
	fmt.Printf("baddr=%08x\n", baddr)
	sections := b.Get_sections()
	n := int(sections.Size())
	for i := 0; i < n; i++ {
		s := sections.Get(i)
		fmt.Printf("offset=0x%08x va=0x%08x size=%05d %s\n",
			s.GetPaddr(), baddr+s.GetVaddr(), s.GetSize(), s.GetName())
	}
}
