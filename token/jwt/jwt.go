package jwt

import (
	"crypto/rsa"
	"github.com/zxfishhack/go-common/token"
	"reflect"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type tokenClaim struct {
	jwt.StandardClaims

	UserData interface{}
}

type Service struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

func NewTokenService(keyPem []byte) (s token.ITokenService, err error) {
	res := &Service{}
	res.priv, err = jwt.ParseRSAPrivateKeyFromPEM(keyPem)
	if err != nil {
		return
	}
	res.pub = &res.priv.PublicKey
	s = res

	return
}

func (s *Service) keyFunc(*jwt.Token) (interface{}, error) {
	return s.pub, nil
}

func (s *Service) Marshal(v interface{}) (string, error) {
	claim := &tokenClaim{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
		},
		UserData: v,
	}
	tk := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)
	return tk.SignedString(s.priv)
}

func (s *Service) Unmarshal(data string, v interface{}) (err error) {
	tk, err := jwt.ParseWithClaims(data, &tokenClaim{UserData: v}, s.keyFunc)
	if err != nil {
		return
	}
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr && !val.IsNil() {
		val = val.Elem()
	}
	if claim, ok := tk.Claims.(*tokenClaim); ok {
		dVal := reflect.ValueOf(claim.UserData)
		if dVal.Kind() == reflect.Ptr && !dVal.IsNil() {
			dVal = dVal.Elem()
		}
		switch val.Kind() {
		case reflect.Slice:
			if (dVal.Type().Kind() == reflect.Slice || dVal.Type().Kind() == reflect.Array) && !val.IsNil() {
				if dVal.Type().Elem().AssignableTo(val.Type().Elem()) {
					val = reflect.AppendSlice(val, dVal)
				}
			}
		case reflect.Array:
			if (dVal.Type().Kind() == reflect.Slice || dVal.Type().Kind() == reflect.Array) && dVal.Len() >= val.Len() {
				if dVal.Type().Elem().AssignableTo(val.Type().Elem()) {
					for i := 0; i < val.Len(); i++ {
						val.Index(i).Set(dVal.Index(i))
					}
				}
			}
		default:
			if val.CanSet() && val.Type().AssignableTo(dVal.Type()) {
				val.Set(dVal)
			}
		}
	}
	return
}

func (s *Service) Validate(data string) (err error) {
	parts := strings.Split(data, ".")
	if len(parts) != 3 {
		return jwt.ErrSignatureInvalid
	}
	return jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), parts[2], s.pub)
}

var _ token.ITokenService = &Service{}
