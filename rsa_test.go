package rsa_ext

import (
	"encoding/base64"
	"testing"
)

const (
	pri = `MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDyVY97dQX4b+/X
a2ApQh9QmilKS9WgPfHwS2n6bikDbZ3Qj+iDzjHnDSc616EgDdecuksTXAXQCiKd
OPmOJMr5pNE2WQ1+fJkjclaX0cQwe4pL2Q9B96IAnx1tf9RScKP8IC3CHiHSxTBH
1LmG+PkMW8XN4FWutQCtxBC98NDMzEf0yeLrYTBKKm+04fIKG4prdHIvzlXoKHoZ
BdXW0qS90F1HQQsRHcPOaKvbgV8pj2tqYZDN56KSUklvNJEg2cuy5EzyYBBU/h2q
Jbh1eEf7REVWa3pRkM2c170AALxiWuL03+YGmSVExYGQLQh930kPJ4puD9qsxT/l
s5+4m94RAgMBAAECggEAYNPDEuc9TXkccgybTaD39jLC0MbgQri9lO/tFn0xsgb4
ib8WfqPC2LkutZo27SHaxurA2KlqQSfrkLqVLDCTUZCDb53BgIq0fa9P3jWYmG6k
YY4HRKp3dpwdHAV5hr8vJqyM3AVCKn9TvT/IKaANktyQeqRqV/ZGoSe4MMyqAUnP
WQMhtmXXz+pbkmYMI0n1WcXhH2SrfHIrT50TCNzlOvOTet05oF8zmXjeTtmkPvMO
h0AUDlwVrxGlHpvYUj2QJv1klxPi7Ehgw6itbt4sG5jGncZ7CE7ockAoXzRgyv7K
T1rjPCeBKxQzDy0KsJJHgFB0IUl9NhQifVcTRr69CQKBgQD+MP/ROnEzrGK/tKji
LqLzeKmG45it4ZDgPPi6V+N1pH/vxdDg4YBmkYVSSatMY2sKNFQTUTBQzBT7d5GD
gNb2K45pFKWjVvGZlXJoKtszZXySz2P+Z/r4WJa7TpPWKZ/Pf0FEo3FaE4xwoHmA
dx5XD5nqvMVR3t3bQtUZdY4t8wKBgQD0Dva4Q0+xopaYqtxWzM5IHZm3aaNWPx8k
DuxAw21a29VcS5B16qApFb1SkplpNaMLpY3l1Y+bpthGeezGvyPBrXKY4MES1Z8N
GpxZMTgGHlhdHfaaNgQt+/ZydUtY7BveCnDpO3nwqyh2/JDYvhtf5YyGRuP6HWkU
Lt5wsoWQ6wKBgQCBsz7U450fYLaCWwxRXLqIwOi/iyI8lvv1byb67h2ByY3+KlGK
bYW20EnW0wA02gWkD09XC/Y7Q+bw6PG2x+bndRIVTBO4ZISieT8HJ9bxQrdtsaS0
Cxpj3dALguysOlDw712+SCdubssaLMfSZPV2Nt+yht+oBq/tUQyrEPCbQQKBgQCL
9zz1Rd0hgZ4eZfbBbOlsoFU0w8ehwceJNWm2Zp2DewmsycVKasl5ZndSMLL8jH86
QbLUOZsHaDMmj+wDu0C1ZVSQam0v8QUrTbSWzkxT7fk9Rd7UZ+ATwyl+UNhqYdZF
i/VfPPXc2Tv2qTgkpTor0Ai8RVGfclh987csKKXDCwKBgQDFP8JubMp4EnAKiqqq
Y3Hx55wlArLvf+9Vsr23iwgIIc2gGpdTDdM1jBpFKSOKCdi8+MAILg7Sr+MfSbzS
DNbKoqcrqq+6gF7k9wFv8QNO9+IcF3d5WlcUipYzfIwftZdBwifVrGAIaoMA2egI
UnQ4j7pZ21dIiv9Yd2mzaDYQzQ==`
	pub = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8lWPe3UF+G/v12tgKUIf
UJopSkvVoD3x8Etp+m4pA22d0I/og84x5w0nOtehIA3XnLpLE1wF0AoinTj5jiTK
+aTRNlkNfnyZI3JWl9HEMHuKS9kPQfeiAJ8dbX/UUnCj/CAtwh4h0sUwR9S5hvj5
DFvFzeBVrrUArcQQvfDQzMxH9Mni62EwSipvtOHyChuKa3RyL85V6Ch6GQXV1tKk
vdBdR0ELER3Dzmir24FfKY9ramGQzeeiklJJbzSRINnLsuRM8mAQVP4dqiW4dXhH
+0RFVmt6UZDNnNe9AAC8Ylri9N/mBpklRMWBkC0Ifd9JDyeKbg/arMU/5bOfuJve
EQIDAQAB`
)

/*
	openssl genrsa -out pri.pem 2048
	openssl rsa -in pri.pem -pubout -out pub.pem
	openssl pkcs8 -topk8 -inform PEM -in pri.pem -outform PEM -nocrypt > pkcs8_pri.pem
*/

func TestRsa(t *testing.T) {
	str := "嘎嘎嘎嘎"
	t.Logf("s:\t%s", str)
	cryptor := Cryptor{
		Pri64: pri,
		Pub64: pub,
	}
	enc := base64.StdEncoding.EncodeToString(cryptor.Encrypt([]byte(str)))
	t.Logf("enc:\t%s", enc)
	cipherText, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		panic(err)
	}
	newStr := string(cryptor.Decrypt(cipherText))
	t.Logf("newStr:\t%s", newStr)
	sign := cryptor.Sign([]byte(str))
	err = cryptor.Verify([]byte(str), sign)
	CheckErr(err)
	t.Log("verify success")

	priEnc := cryptor.PriEncrypt([]byte(str))
	priEncStr := base64.StdEncoding.EncodeToString(priEnc)
	CheckErr(err)
	t.Logf("priEnc:\t%s", priEncStr)
	cipherText, err = base64.StdEncoding.DecodeString(priEncStr)
	CheckErr(err)
	newByte := cryptor.PubDecrypt(cipherText)
	pubDec := string(newByte)
	t.Logf("pubDec:\t%s", pubDec)
}

func TestReadFile(t *testing.T) {
	cryptor := Cryptor{
		PriPath: "pkcs8_pri.pem",
		Pub64:   pub,
	}
	str := "嘎嘎嘎嘎"
	t.Logf("s:\t%s", str)
	t.Logf("cs8:\t%s", string(cryptor.Decrypt(cryptor.Encrypt([]byte(str)))))

	cryptor = Cryptor{
		PriPath: "pri.pem",
		Pub64:   pub,
	}
	t.Logf("s:\t%s", str)
	t.Logf("cs1:\t%s", string(cryptor.Decrypt(cryptor.Encrypt([]byte(str)))))
}
