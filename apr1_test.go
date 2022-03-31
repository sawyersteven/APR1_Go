package apr1

import (
	"testing"
)

type testInput struct {
	Password       string
	Salt           string
	ExpectedOutput string
}

var testData = []*testInput{
	{Password: "123456", Salt: "IyA2SUNJ", ExpectedOutput: "$apr1$IyA2SUNJ$y19fq7yFUJTA6INGbjThg."},
	{Password: "qwerty", Salt: "5d.PdkJC", ExpectedOutput: "$apr1$5d.PdkJC$NC0X6S4M6r2softOSPJ2G."},
	{Password: "password", Salt: "F0ajl09F", ExpectedOutput: "$apr1$F0ajl09F$kPBydXR.hZiwsj1TXMMqF."},
}

func TestEncode(t *testing.T) {
	for _, td := range testData {
		pw := Encode(td.Password, td.Salt)
		if pw != td.ExpectedOutput {
			t.Fail()
		}
	}
}
