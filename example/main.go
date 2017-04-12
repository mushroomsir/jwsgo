package main

import "github.com/mushroomsir/jwsgo"

func main() {
	var payload = &jwsgo.Payload{
		Iss: "http://google.com/",
		Exp: 3610,
		Iat: 10,
	}
	jws := jwsgo.NewSha256("xx")
	token, _ := jws.Encode(payload)

	jws.Decode(token)
}
