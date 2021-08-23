package token

type ITokenService interface {
	Marshal(v interface{}) (string, error)
	Unmarshal(data string, v interface{}) error

	Validate(data string) error
}
