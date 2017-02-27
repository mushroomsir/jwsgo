package jwsgo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var hasher = Hash256

// SetHash set a global hash function for signing, default to:
//
// func Hash(key, data string) (sig []byte) {
// 	mac := hmac.New(sha256.New, []byte(key))
// 	mac.Write([]byte(data))
// 	return mac.Sum(nil)
// }
//
func SetHash(fn func(key, data string) []byte) {
	if fn == nil {
		panic("invalid hash function")
	}
	hasher = fn
}

// Hash256 the default hash function
func Hash256(key, data string) (sig []byte) {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// Verify Returns true or false for whether a signature matches a secret or key.
func Verify(token, key string) (err error) {

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token received, token must have 3 parts")
	}
	signedContent := parts[0] + "." + parts[1]
	sign1 := hasher(key, signedContent)
	sign2, err := base64.RawURLEncoding.DecodeString(parts[2])
	if bytes.Compare(sign1, sign2) != 0 {
		err = errors.New("invalid data")
	}
	return
}

// New return a jws instance
func New(key string) *JWS {
	return &JWS{key: key}
}

// JWS provides a partial implementation
// of JSON Web Signature encoding and decoding.
// See RFC 7515.
type JWS struct {
	key string
}

// Verify tests whether the provided JWT token's signature was right.
func (jws *JWS) Verify(token string) error {
	return Verify(token, jws.key)
}

// Encode the jws header and payload return token
func (jws *JWS) Encode(header *Header, payload *Payload) (token string, err error) {
	head, err := header.Encode()
	if err != nil {
		return
	}
	payloadstr, err := payload.Encode()
	if err != nil {
		return
	}
	signedContent := fmt.Sprintf("%s.%s", head, payloadstr)

	signature := hasher(jws.key, signedContent)
	token = fmt.Sprintf("%s.%s", signedContent, base64.RawURLEncoding.EncodeToString(signature))
	return
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
	PrivatePayload map[string]interface{} `json:"-"`
}

//Encode the current payload of jwt
func (c *Payload) Encode() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	if len(c.PrivatePayload) == 0 {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	// Marshal private payload set and then append it to b.
	prv, err := json.Marshal(c.PrivatePayload)
	if err != nil {
		return "", fmt.Errorf("invalid map of private payload")
	}

	// Concatenate public and private arguments JSON objects.
	if !bytes.HasSuffix(b, []byte{'}'}) {
		return "", fmt.Errorf("invalid JSON %s", b)
	}
	if !bytes.HasPrefix(prv, []byte{'{'}) {
		return "", fmt.Errorf("invalid JSON %s", prv)
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
	KeyID         string                 `json:"kid,omitempty"`
	PrivateHeader map[string]interface{} `json:"-"`
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
	if len(h.PrivateHeader) == 0 {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	// Marshal private header and then append it to b.
	prv, err := json.Marshal(h.PrivateHeader)
	if err != nil {
		return "", fmt.Errorf("invalid map of private header")
	}

	// Concatenate public and private claim JSON objects.
	if !bytes.HasSuffix(b, []byte{'}'}) {
		return "", fmt.Errorf("invalid JSON %s", b)
	}
	if !bytes.HasPrefix(prv, []byte{'{'}) {
		return "", fmt.Errorf("invalid JSON %s", prv)
	}
	b[len(b)-1] = ','         // Replace closing curly brace with a comma.
	b = append(b, prv[1:]...) // Append private Header.
	return base64.RawURLEncoding.EncodeToString(b), nil
}
