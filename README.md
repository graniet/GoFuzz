# GoFuzz

#### A Request fuzzer written in Go 


```shell
$ go get github.com/graniet/GoFuzz
$ GoFuzz -h
```

#### Custom payload :

example/payloads_custom/
+ payload.txt
+ detector.txt


```shell
$ GoFuzz -f example/requests.txt -t xss -c "example/payloads_custom/payload.txt"
```
