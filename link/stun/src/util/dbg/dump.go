package dbg

import (
	"fmt"
)

func PrintMem(buf []byte, col int) {

	output := fmt.Sprintf("-------------------- %d bytes --------------------", len(buf))
	output += DumpMem(buf, col)
	output += fmt.Sprintf("\n----------------- end of %d bytes -----------------", len(buf))
	fmt.Println(output)
}

func DumpMem(buf []byte, col int) string {

	output := ""
	for i, v := range buf {
		if col != 0 && i % col == 0 {
			output += "\n"
		}
		output += fmt.Sprintf("0x%02x ", v)
	}
	return output
}
