# GoFuzz

A Request fuzzer written in Go 


```shell
$ go get github.com/graniet/GoFuzz
$ cd $GOPATH/src/github.com/graniet/GoFuzz
$ go build && ./GoFuzz
```

Implement example :

```
[
    {
        "type": "DELETE",
        "url" : "http://localhost:8080/v1/users/2",
        "header":  {
            "Content-Type": "application/json"
        },
        "body": {
            "userToken": "88777e22803a1684bc9b9bd9711262fc"
        }
    }
]
```

```go
package main

import (
	"github.com/graniet/GoFuzz/fuzzer"
)

func main(){

	linker := fuzzer.Linker{}
	linker.Type = "DELETE"
	linker.Url = "http://localhost:8080/v1/users/2"
	linker.Header = map[string]string{
		"Content-Type": "application/json",
	}
	linker.Body = map[string]string{
		"userToken": "88777e22803a1684bc9b9bd9711262fc",
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
