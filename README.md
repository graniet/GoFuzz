# GoFuzz
A simple request fuzzer written in Golang with love


```shell
$ go get github.com/graniet/GoFuzz
$ cd $GOPATH/src/github.com/graniet/GoFuzz
$ go build && ./GoFuzz
```

Implement:

```go
package main

import (
	"github.com/graniet/GoFuzz/fuzzer"
)

func main(){

	linker := fuzzer.Linker{}
	linker.Type = "GET"
	linker.Url = "http://localhost:8080/v1/users/2"
	linker.Header = map[string]string{
		"Content-Type": "application/json",
	}
	linker.Body = map[string]string{
		"user_token": "88777e22803a1684bc9b9bd9711262fc",
	}

	Fuzz := fuzzer.GoFuzz{
		Fuzzer: fuzzer.Vulnerability{
			Type: "sql",
		},
	}

	Fuzz.Mapper = append(Fuzz.Mapper, linker)
	Fuzz.Fuzzer.LoadPayload()
	Fuzz.Fuzzing()
}
```
