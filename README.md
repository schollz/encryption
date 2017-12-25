# encryption

[![travis](https://travis-ci.org/schollz/encryption.svg?branch=master)](https://travis-ci.org/schollz/encryption) 
[![go report card](https://goreportcard.com/badge/github.com/schollz/encryption)](https://goreportcard.com/report/github.com/schollz/encryption) 
[![coverage](https://img.shields.io/badge/coverage-85%25-brightgreen.svg)](https://gocover.io/github.com/schollz/encryption)
[![godocs](https://godoc.org/github.com/schollz/encryption?status.svg)](https://godoc.org/github.com/schollz/encryption) 

A very simple wrapper for pbkdf2 encryption that follows NIST recommendations for constructing IVs (see [NIST publication section 8.2](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
)). See godoc for information and tests for usage.

### Example

```go
package main

import (
        "fmt"
        "github.com/schollz/encryption"
)

func main() {
        s := []byte("hello, world")
        p := "secret passphrase"
        encrypted := encryption.Encrypt(s, p)
        fmt.Println(encrypted)
        // prints: agjZrMKjmY2LOnq3.jsOW25nDrq4=.UydSNRCWCwev1Pp53ThDZtUZkJoDuFBt81aZTA==
        
        decrypted, err := encryption.Decrypt(encrypted, p)
        fmt.Println(string(decrypted), err)
        // Hello, world <nil>
}
```
