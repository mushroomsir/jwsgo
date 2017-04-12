# jsonrpc

[![Build Status](https://travis-ci.org/mushroomsir/jwsgo.svg?branch=master)](https://travis-ci.org/mushroomsir/jwsgo)
[![Coverage Status](http://img.shields.io/coveralls/mushroomsir/jwsgo.svg?style=flat-square)](https://coveralls.io/r/mushroomsir/jwsgo)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/mushroomsir/jwsgo/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/mushroomsir/jwsgo)

## Installation
```go
go get github.com/mushroomsir/jwsgo
```

## Feature
- HMAC signatures with HS256, HS384 and HS512.
- Support custom algorithm for encrypt data.
- Support custom Header
- Easy to understand and use.

## API
### Basic usage
NewSha256 create the jws instance with HMAC-SHA256.
```go
// or NewSha512, NewSha384
jws:=jwsgo.NewSha256("Secret-key")

// create the payload
payload := &Payload{
    Iss: "http://google.com/",
    Exp: 3610,
    Iat: 10,
}

// You can also add some extra fileds
payload.Set("userid", "123456")

// encode this payload and get token
token,err := jws.Encode(payload)

// decode token
playload,err := jws.Decode(token)

```
### Custom Header
you can even make own Header with custom value.
```go
header := &Header{
    Algorithm: "HS1",
}
header.Set("id", "mushroom")
token, err := jws.EncodeWith(header, payload)
```
### Custom algorithm
use custom hash func for encrypt data.
```go
hasher := func(data string) []byte {
    h := hmac.New(sha1.New, []byte("xx"))
    h.Write([]byte(data))
    return h.Sum(nil)
}
jws := New("HS256",hasher)
```