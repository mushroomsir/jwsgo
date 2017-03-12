package jwsgo

import (
	"crypto/hmac"
	"crypto/sha1"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJwsgo(t *testing.T) {
	t.Run("jwsgo with Encode and Verify func that should be", func(t *testing.T) {
		assert := assert.New(t)

		payload := &Payload{
			Iss: "http://google.com/",
			Exp: 3610,
			Iat: 10,
		}
		payload.Set("userid", "3610")
		jws := NewSha256("xx")
		token, err := jws.Encode(payload)
		assert.Nil(err)
		assert.NotEmpty(token)

		assert.Nil(jws.Verify(token))

	})
	t.Run("jwso with error that should be", func(t *testing.T) {
		assert := assert.New(t)
		jws := NewSha256("xx")
		assert.Equal("invalid token received, token must have 3 parts", jws.Verify("token.").Error())
	})
	t.Run("jwso with PrivatePayload and PrivateHeader that should be", func(t *testing.T) {
		assert := assert.New(t)
		header := &Header{
			Algorithm: "HS256",
		}
		header.Set("id", "mushroom")
		payload := &Payload{
			Iss: "http://google.com/",
			Exp: 3610,
			Iat: 10,
		}
		payload.Set("age", 18)
		jws := NewSha256("xx")
		token, err := jws.EncodeWith(header, payload)
		assert.Nil(err)
		assert.NotEmpty(token)

		assert.Equal("invalid data", jws.Verify(token+"a").Error())

	})
	t.Run("jwso with sha1 that should be", func(t *testing.T) {

		assert := assert.New(t)
		header := &Header{
			Algorithm: "HS1",
		}
		header.Set("id", "mushroom")
		payload := &Payload{
			Iss: "http://google.com/",
			Exp: 3610,
			Iat: 10,
		}
		payload.Set("age", 18)
		jws := New("HS256", func(data string) []byte {
			h := hmac.New(sha1.New, []byte("xx"))
			h.Write([]byte(data))
			return h.Sum(nil)
		})
		token, err := jws.EncodeWith(header, payload)
		assert.Nil(err)
		assert.NotEmpty(token)

		assert.Nil(jws.Verify(token))

	})

	t.Run("jwso with PrivatePayload and PrivateHeader that should be", func(t *testing.T) {
		assert := assert.New(t)
		header := &Header{
			Algorithm: "HS256",
		}
		header.Set("id", make(chan int, 2))
		str, err := header.Encode()
		assert.Empty(str)
		assert.Equal("invalid map of private header", err.Error())

		payload := &Payload{
			Iss: "http://google.com/",
			Exp: 3610,
			Iat: 10,
		}
		payload.Set("age", make(chan int, 2))
		str, err = payload.Encode()
		assert.Empty(str)
		assert.Equal("invalid map of private payload", err.Error())

		jws := NewSha256("xx")
		token, err := jws.EncodeWith(header, payload)
		assert.Equal("invalid map of private header", err.Error())
		assert.Empty(token)

		header = &Header{
			Algorithm: "HS256",
		}
		header.Set("id", 1)
		token, err = jws.EncodeWith(header, payload)
		assert.Empty(token)
		assert.Equal("invalid map of private payload", err.Error())
	})
	t.Run("jwsgo with NewSha512 and NewSha384 func that should be", func(t *testing.T) {
		assert := assert.New(t)

		payload := &Payload{
			Iss: "http://google.com/",
			Exp: 3610,
			Iat: 10,
		}
		payload.Set("userid", "3610")

		assert.Equal("3610", payload.Get("userid"))
		jws := NewSha256("xx")
		token, err := jws.Encode(payload)
		assert.Nil(err)
		assert.NotEmpty(token)
		assert.Nil(jws.Verify(token))

		header := &Header{
			Algorithm: "HS1",
		}
		assert.Equal(nil, header.Get("idx"))
		header.Set("id", "mushroom")
		assert.Equal("mushroom", header.Get("id"))
		assert.Equal(nil, header.Get("idx"))

		jws = NewSha512("xx")
		token, err = jws.Encode(payload)
		assert.Nil(err)
		assert.NotEmpty(token)
		assert.Nil(jws.Verify(token))

		payload = &Payload{
			Iss: "http://google.com/",
			Exp: 3610,
			Iat: 10,
		}
		assert.Equal(nil, payload.Get("userid"))
		jws = NewSha384("xx")
		token, err = jws.Encode(payload)
		assert.Nil(err)
		assert.NotEmpty(token)
		assert.Nil(jws.Verify(token))

	})
}
