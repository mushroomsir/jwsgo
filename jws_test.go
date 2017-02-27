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
		header := &Header{
			Algorithm: "HS256",
		}
		payload := &Payload{
			Iss: "http://google.com/",
			Exp: 3610,
			Iat: 10,
		}
		jws := New("xx")
		token, err := jws.Encode(header, payload)
		assert.Nil(err)
		assert.NotEmpty(token)

		assert.Nil(jws.Verify(token))

	})
	t.Run("jwso with error that should be", func(t *testing.T) {
		assert := assert.New(t)
		jws := New("xx")
		assert.Equal("invalid token received, token must have 3 parts", jws.Verify("token.").Error())
	})
	t.Run("jwso with PrivatePayload and PrivateHeader that should be", func(t *testing.T) {
		assert := assert.New(t)
		header := &Header{
			Algorithm:     "HS256",
			PrivateHeader: map[string]interface{}{"id": "mushroom"},
		}
		payload := &Payload{
			Iss:            "http://google.com/",
			Exp:            3610,
			Iat:            10,
			PrivatePayload: map[string]interface{}{"age": 18},
		}
		jws := New("xx")
		token, err := jws.Encode(header, payload)
		assert.Nil(err)
		assert.NotEmpty(token)

		assert.Equal("invalid data", jws.Verify(token+"a").Error())

	})
	t.Run("jwso with sha1 that should be", func(t *testing.T) {

		SetHash(func(key, data string) []byte {
			h := hmac.New(sha1.New, []byte(key))
			h.Write([]byte(data))
			return h.Sum(nil)
		})

		assert := assert.New(t)
		header := &Header{
			Algorithm:     "HS1",
			PrivateHeader: map[string]interface{}{"id": "mushroom"},
		}
		payload := &Payload{
			Iss:            "http://google.com/",
			Exp:            3610,
			Iat:            10,
			PrivatePayload: map[string]interface{}{"age": 18},
		}
		jws := New("xx")
		token, err := jws.Encode(header, payload)
		assert.Nil(err)
		assert.NotEmpty(token)

		assert.Nil(jws.Verify(token))

		defer func() {
			r := recover()
			assert.NotNil(r)
		}()
		SetHash(nil)
	})

	t.Run("jwso with PrivatePayload and PrivateHeader that should be", func(t *testing.T) {
		assert := assert.New(t)
		header := &Header{
			Algorithm:     "HS256",
			PrivateHeader: map[string]interface{}{"id": make(chan int, 2)},
		}
		str, err := header.Encode()
		assert.Empty(str)
		assert.Equal("invalid map of private header", err.Error())

		payload := &Payload{
			Iss:            "http://google.com/",
			Exp:            3610,
			Iat:            10,
			PrivatePayload: map[string]interface{}{"age": make(chan int, 2)},
		}
		str, err = payload.Encode()
		assert.Empty(str)
		assert.Equal("invalid map of private payload", err.Error())

		jws := New("xx")
		token, err := jws.Encode(header, payload)
		assert.Equal("invalid map of private header", err.Error())
		assert.Empty(token)

		header = &Header{
			Algorithm:     "HS256",
			PrivateHeader: map[string]interface{}{"id": 1},
		}
		token, err = jws.Encode(header, payload)
		assert.Empty(token)
		assert.Equal("invalid map of private payload", err.Error())
	})
}
