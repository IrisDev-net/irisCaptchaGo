package iriscaptchago

import (
	"fmt"
	"testing"
)

func TestNewIrisCaptchaHandler(t *testing.T) {
	var secretCases = []struct {
		secret string
		want   error
	}{
		{"", ErrInvalidSecret},
		{"abcabcabc", ErrInvalidSecret},
		{"533a64afb4c496ca4dcbe081aa40x2711", nil},
		{"533a64afb4c496ca4dcb0x2711e081aa40x2711", nil},
	}

	for _, tt := range secretCases {
		testname := fmt.Sprintf("%s\n", tt.secret)
		t.Run(testname, func(t *testing.T) {
			_, err := NewIrisCaptchaHandler(tt.secret)
			if err != tt.want {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}
func TestGetJs(t *testing.T) {

	c, err := NewIrisCaptchaHandler("533a64afb4c496ca4dcb0x2711e081aa40x2711")
	if err != nil {
		t.Errorf("got %v, want %v", err, nil)
	}
	ans := c.GetJs()
	const cres = `<script src="https://captcha.irisdev.net/js/0x2711></script>`
	if ans != cres {
		t.Errorf("got %s, want %s", ans, cres)
	}
}
func TestLoadPublicKey(t *testing.T) {
	c := new(irisCaptchaHandler)
	c.provider = IrisDevServer
	err := c.loadPublicKey()
	if err != nil {
		t.Errorf("got %v, want %v", err, nil)
	}
}

func TestValidateReq(t *testing.T) {
	c, err := NewIrisCaptchaHandler("533a64afb4c496cc34dfd00d1ecbd45cfa2784b2c3eba4aa02e7a4dcbe081aa40x2711")
	if err != nil {
		t.Errorf("got %v, want %v", err, nil)
	}
	h := c.(*irisCaptchaHandler)
	h.TestValidateReq(t)
	h.TestValidateSig(t)

}
