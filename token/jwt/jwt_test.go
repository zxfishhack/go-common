package jwt

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/zxfishhack/go-common/token"
	"log"
	"os"
	"testing"

	"gotest.tools/v3/assert"
)

var ts token.ITokenService

func TestMain(m *testing.M) {
	var err error
	ts, err = NewTokenService([]byte(privateKey))
	if err != nil {
		log.Fatal(err)
	}
	code := m.Run()
	os.Exit(code)
}

func TestJwt_String(t *testing.T) {

	s := "123"
	res, err := ts.Marshal(s)
	assert.NilError(t, err)
	t.Log(res)
	s2 := ""
	err = ts.Unmarshal(res, &s2)
	assert.NilError(t, err)
	assert.Equal(t, s, s2)
	assert.NilError(t, ts.Validate(res))
}

func TestJwt_StringFailed(t *testing.T) {

	s := "123"
	res, err := ts.Marshal(s)
	assert.NilError(t, err)
	t.Log(res)
	s2 := make([]string, 0)
	err = ts.Unmarshal(res, &s2)
	assert.Check(t, err != nil)
	newErr, ok := err.(*jwt.ValidationError)
	assert.Check(t, ok)
	_, ok = newErr.Inner.(*json.UnmarshalTypeError)
	assert.Check(t, ok)
	assert.NilError(t, ts.Validate(res))
}

func TestJwt_Array(t *testing.T) {

	s := [2]string{"123", "234"}
	res, err := ts.Marshal(s)
	assert.NilError(t, err)
	t.Log(res)
	s2 := [2]string{}
	err = ts.Unmarshal(res, &s2)
	assert.NilError(t, err)
	assert.DeepEqual(t, s, s2)
	assert.NilError(t, ts.Validate(res))
}

func TestJwt_Map(t *testing.T) {

	s := map[string]string{"123": "234"}
	res, err := ts.Marshal(s)
	assert.NilError(t, err)
	t.Log(res)
	s2 := make(map[string]string)
	err = ts.Unmarshal(res, &s2)
	assert.NilError(t, err)
	assert.DeepEqual(t, s, s2)
	assert.NilError(t, ts.Validate(res))
}

type data2 struct {
	V int
}

type data struct {
	Key  string
	Val  string
	Data []data2
}

func TestJwt_Struct(t *testing.T) {

	s := data{
		Key: "123",
		Val: "234",
		Data: []data2{
			{V: 12}, {V: 13},
		},
	}
	res, err := ts.Marshal(s)
	assert.NilError(t, err)
	t.Log(res)
	var s2 data
	err = ts.Unmarshal(res, &s2)
	assert.NilError(t, err)
	assert.DeepEqual(t, s, s2)
	assert.NilError(t, ts.Validate(res))
}
