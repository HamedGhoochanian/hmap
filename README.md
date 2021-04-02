# hmap

## Compile & Run
```console 
$ go build scanner.go
$ ./scanner -ip 127.0.0.1 
 port 111  is open
 port 4369  is open
 port 5432  is open
```
## flags
`-ip` scan target(default 127.0.0.1)  
`-f` if you're using range scan, this flag will be the scanned first(default 1)  
`-l` if you're using range scan, this flag will be the scanned last(default 65535)  
`-reserved` only check famous reserved ports  
`-app` only check app layer service ports  
`-printClosed` prints the closed ports during range scan
run `./scanner -help` for more details