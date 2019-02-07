# GoFuzz

#### A Request fuzzer written in Go 


```shell
$ go get github.com/graniet/GoFuzz
$ GoFuzz -h

Arguments:

  -h  --help      Print help information
  -r  --requests  File to API requests dump.
  -t  --type      Type of fuzzing: SQL, XSS
  -v  --verbose   Print payload verbose in checking process
  -c  --custom   Custom payload file
  -p  --postman   Use postman format
```

#### Custom payload :

example/payloads_custom/
+ payload.txt
+ detector.txt


```shell
$ GoFuzz -f example/requests.txt -t xss -c "example/payloads_custom/payload.txt"
```
