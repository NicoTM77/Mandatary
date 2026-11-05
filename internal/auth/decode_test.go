package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestStrictOriginalJSON(t *testing.T) {
	for _, s := range []string{`"\ud800"`, `"\udc00"`, `"\ud800x"`, `"\ud800\u0041"`, string([]byte{'"', 0xff, '"'}), `null`, `"x" "y"`} {
		if b, e := DecodePasswordJSON([]byte(s)); e == nil || b != nil {
			t.Fatal("malformed original encoding accepted")
		}
	}
	for _, s := range []string{`"\ufffd"`, `"�"`, `"\ud83d\ude00"`, `"😀"`} {
		if _, e := DecodePasswordJSON([]byte(s)); e != nil {
			t.Fatal("explicit replacement/paired scalar refused")
		}
	}
	b, e := DecodePasswordJSON([]byte(`" a\u0020 "`))
	if e != nil || !bytes.Equal(b, []byte(" a  ")) {
		t.Fatal("password spaces changed")
	}
	if _, e := DecodePasswordJSON([]byte(`"` + strings.Repeat(`\u0041`, 512) + `"`)); e != nil {
		t.Fatal("escaped representation rejected")
	}
}
