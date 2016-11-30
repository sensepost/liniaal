package main

import (
	"fmt"
	"io/ioutil"
)

func main() {

	data, err := ioutil.ReadFile("log.txt")
	if err != nil {
		fmt.Println("No file found")
		return
	}
	rpc := string(data[0:100])
	fmt.Println("now; ", rpc)
	var rtot string
	var split int = 39 //must be multiple of 3, otherwise we get the - at end of line
	if len(rpc) > split {
		piecescnt := len(rpc) / split
		index := 0

		var rrpc string

		for kk := 0; kk < piecescnt; kk++ {
			if index+split < len(rpc) {

				rrpc = rpc[index : index+split]
				if rrpc[len(rrpc)-1:] == "-" {
					rrpc = rrpc[:len(rrpc)-1]
					fmt.Printf("%s\n\n", rrpc)
					index += split
				} else {
					index += split
				}

			}
			//skip over the - at the end of a line
			rtot += rrpc
		}
		if len(rpc) > split*piecescnt {
			rrpc = rpc[index:]
			fmt.Printf("%s\n\n", rrpc)
		}
	}
}
