# GoFuzz

A Request fuzzer written in Go 


```shell
$ go get github.com/graniet/GoFuzz
$ GoFuzz -h
```


### How to add a new attack :
+ Create a folder inside payload folder
+ Create a file with same name of folder with .txt extension (this it's injections pattern)
+ Create a file with  detector.txt as name (this it's detection pattern)

```go
./GoFuzz --file 'file with request.txt' --type newType
```
