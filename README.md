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

### How to add a new attack :
+ Create a folder inside payload folder
+ Create a file with same name of folder with .txt extension (this it's injections pattern)
+ Create a file with  detector.txt as name (this it's detection pattern)

```go
go build
./GoFuzz --file 'file with request.txt' --type newType
```
