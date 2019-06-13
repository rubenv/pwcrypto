package backend

type Algorithm interface {
	ID() string
	Hash(input string) (string, error)
	Check(input, hashed string) (bool, bool, error)
}

type NullCrypto struct {
}

func (n NullCrypto) ID() string {
	return "null"
}

func (n NullCrypto) Hash(input string) (string, error) {
	return input, nil
}

func (n NullCrypto) Check(input, hashed string) (bool, bool, error) {
	return input == hashed, false, nil
}
