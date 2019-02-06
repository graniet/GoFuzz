package main

import (
	"github.com/akamensky/argparse"
	"github.com/graniet/GoFuzz/fuzzer"
	"github.com/common-nighthawk/go-figure"
	"os"
	"fmt"
)

func main(){
	parser := argparse.NewParser("Gofuzz", "API Rest fuzzer written in Golang")
	file := parser.String("f", "file", &argparse.Options{Required:true, Help:"File to API requests dump."})
	fuzzType := parser.String("t", "type", &argparse.Options{Required: true, Help: "Type of fuzzing: SQL, XSS"})
	printPayload := parser.Flag("v", "verbose", &argparse.Options{Required:false, Help:"Print payload verbose in checking process"})
	customPayload := parser.String("p", "payload", &argparse.Options{Required:false, Help:"Custom payload file"})

	err := parser.Parse(os.Args)
	if err != nil{
		fmt.Print(parser.Usage(err))
		return
	}
	fmt.Printf("\n")
	figure.NewFigure("GoFuzz", "colossal", true).Print()
	fmt.Printf("\n")

	Flag := fuzzer.Flag{
		Verbose: *printPayload,
	}

	configuration := fuzzer.GoFuzz{
		Target: *file,
		ParamUsed: make(map[string]string),
		Fuzzer: fuzzer.Vulnerability{
			Type: *fuzzType,
		},
		Flags:Flag,
		CustomPayload: *customPayload,
	}

	configuration.Run()
}
