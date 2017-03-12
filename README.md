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
- Support HS256, HS384, HS512 algorithms
- Support custom algorithm for encrypt data
- Easy to unstand and use

## API
### Basic usage
NewSha256 create the jws instance with HMAC-SHA256:
```go
    jws:=jwsgo.NewSha256("Secret-key")
    //or NewSha512, NewSha384
```
Then create an payload :
```go
    payload := &Payload{
        Iss: "http://google.com/",
        Exp: 3610,
        Iat: 10,
    }
```
You can also add some extra fileds by:
```go
    payload.Set("userid", "123456")
```
Then encode this payload and get token:
```go
    token,err:=jws.Encode(payload)
```
### Custom Header
you can even make own Header with custom value:
```go
    header := &Header{
        Algorithm: "HS1",
    }
    header.Set("id", "mushroom")
    token, err := jws.EncodeWith(header, payload)
```
### Custom algorithm
use new Func with custom hash func and algorithm's name
```go
    hasher:=func(data string) []byte {
        h := hmac.New(sha1.New, []byte("xx"))
        h.Write([]byte(data))
        return h.Sum(nil)
    }
    jws := New("HS256",hasher)
```