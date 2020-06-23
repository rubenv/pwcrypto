package pwcrypto

import "testing"

func notEqual(t *testing.T, a, b interface{}) {
	if a == b {
		t.Logf("%#v should not equal %#v", a, b)
		t.Fail()
	}
}

func equal(t *testing.T, a, b interface{}) {
	if a != b {
		t.Logf("%#v should equal %#v", a, b)
		t.Fail()
	}
}

func noError(t *testing.T, err error) {
	if err != nil {
		t.Logf("unexpected error: %#v", err)
		t.Fail()
	}
}
