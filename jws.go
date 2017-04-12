package jwsgo

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
)

type hasher func(data string) []byte

//New returns the jws instance with custome sign method
func New(alg string, hash hasher) *JWS {
	return &JWS{
		algorithm: alg,
		hash:      hash,
	}
}

//NewSha256 returns the jws instance with HMAC-SHA256
func NewSha256(key string) *JWS {
	return &JWS{
		algorithm:   "HS256",
		signingHash: hmac.New(sha256.New, []byte(key)),
	}
}

//NewSha512 returns the jws instance with HMAC-SHA256
func NewSha512(key string) *JWS {
	return &JWS{
		algorithm:   "HS512",
		signingHash: hmac.New(sha512.New, []byte(key)),
	}
}

//NewSha384 returns the jws instance with HMAC-SHA256
func NewSha384(key string) *JWS {
	return &JWS{
		algorithm:   "HS384",
		signingHash: hmac.New(crypto.SHA384.New, []byte(key)),
	}
}

// JWS provides a golang implementation
// of JSON Web Signature encoding and decoding.
// See RFC 7515.
type JWS struct {
	signingHash hash.Hash
	algorithm   string
	hash        hasher
}

// Verify Returns true or false for whether a signature matches a secret or key.
func (jws *JWS) Verify(token string) (err error) {

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token received, token must have 3 parts")
	}
	signedContent := parts[0] + "." + parts[1]
	var newsign []byte
	if jws.signingHash != nil {
		jws.signingHash.Write([]byte(signedContent))
		newsign = jws.signingHash.Sum(nil)
		defer jws.signingHash.Reset()
	} else {
		newsign = jws.hash(signedContent)
	}
	sign, err := base64.RawURLEncoding.DecodeString(parts[2])
	if bytes.Compare(sign, newsign) != 0 {
		err = errors.New("invalid data")
	}
	return
}

// Encode return token by the payload
func (jws *JWS) Encode(payload *Payload) (token string, err error) {
	header := &Header{
		Typ:       "JWT",
		Algorithm: jws.algorithm,
	}
	return jws.EncodeWith(header, payload)
}

// EncodeWith return token by the jws header and payload
func (jws *JWS) EncodeWith(header *Header, payload *Payload) (token string, err error) {
	head, err := header.Encode()
	if err != nil {
		return
	}
	payloadstr, err := payload.Encode()
	if err != nil {
		return
	}
	signedContent := fmt.Sprintf("%s.%s", head, payloadstr)
	var signature []byte
	if jws.signingHash != nil {
		jws.signingHash.Write([]byte(signedContent))
		signature = jws.signingHash.Sum(nil)
		defer jws.signingHash.Reset()
	} else {
		signature = jws.hash(signedContent)
	}
	token = fmt.Sprintf("%s.%s", signedContent, base64.RawURLEncoding.EncodeToString(signature))
	return
}

// Decode ...
func (jws *JWS) Decode(token string) (payload *Payload, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token")
	}
	signedContent := parts[0] + "." + parts[1]
	var signature []byte
	if jws.signingHash != nil {
		jws.signingHash.Write([]byte(signedContent))
		signature = jws.signingHash.Sum(nil)
		defer jws.signingHash.Reset()
	} else {
		signature = jws.hash(signedContent)
	}
	oldsig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if bytes.Compare(signature, oldsig) != 0 || err != nil {
		return nil, errors.New("invalid signature")
	}
	payload = new(Payload)
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	err = json.Unmarshal(b, payload)
	err = json.Unmarshal(b, &payload.privatePayload)
	return payload, err
}

//Payload  contains information about the JWT signature including the permissions being requested (scopes),
// the target of the token, the issuer, the time the token was issued, and the lifetime of the token.
type Payload struct {
	Iss   string `json:"iss"`             // email address of the client_id of the application making the access token request
	Scope string `json:"scope,omitempty"` // space-delimited list of the permissions the application requests
	Aud   string `json:"aud,omitempty"`   // descriptor of the intended target of the assertion (Optional).
	Exp   int64  `json:"exp"`             // the expiration time of the assertion (seconds since Unix epoch)
	Iat   int64  `json:"iat"`             // the time the assertion was issued (seconds since Unix epoch)
	Typ   string `json:"typ,omitempty"`   // token type (Optional).
	// Email for which the application is requesting delegated access (Optional).
	Sub            string                 `json:"sub,omitempty"`
	privatePayload map[string]interface{} `json:"-"`
}

// Set ...
func (c *Payload) Set(key string, value interface{}) {
	if c.privatePayload == nil {
		c.privatePayload = make(map[string]interface{})
	}
	c.privatePayload[key] = value
}

// Get ...
func (c *Payload) Get(key string) interface{} {
	if c.privatePayload == nil {
		return nil
	}
	return c.privatePayload[key]
}

//Encode the current payload of jwt
func (c *Payload) Encode() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	if len(c.privatePayload) == 0 {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	// Marshal private payload set and then append it to b.
	prv, err := json.Marshal(c.privatePayload)
	if err != nil {
		return "", fmt.Errorf("invalid map of private payload")
	}
	b[len(b)-1] = ','         // Replace closing curly brace with a comma.
	b = append(b, prv[1:]...) // Append private payload.
	return base64.RawURLEncoding.EncodeToString(b), nil
}

//Header is header of jwt
type Header struct {
	Algorithm string `json:"alg"`
	// Represents the token type.
	Typ string `json:"typ"`
	// The optional hint of which key is being used.
	KeyID         string `json:"kid,omitempty"`
	privateHeader map[string]interface{}
}

// Set ...
func (h *Header) Set(key string, value interface{}) {
	if h.privateHeader == nil {
		h.privateHeader = make(map[string]interface{})
	}
	h.privateHeader[key] = value
}

// Get ...
func (h *Header) Get(key string) interface{} {
	if h.privateHeader == nil {
		return nil
	}
	return h.privateHeader[key]
}

//Encode the current header of jwt
func (h *Header) Encode() (string, error) {
	if h.Typ == "" {
		h.Typ = "JWT"
	}
	b, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	if len(h.privateHeader) == 0 {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	// Marshal private header and then append it to b.
	prv, err := json.Marshal(h.privateHeader)
	if err != nil {
		return "", fmt.Errorf("invalid map of private header")
	}
	b[len(b)-1] = ','         // Replace closing curly brace with a comma.
	b = append(b, prv[1:]...) // Append private Header.
	return base64.RawURLEncoding.EncodeToString(b), nil
}
