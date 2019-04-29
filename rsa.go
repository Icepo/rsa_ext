package rsa_ext

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"hash"
	"io"
	"io/ioutil"
	"math/big"
	"os"
)

var (
	ErrNoPubKey        = errors.New("no pub key input")
	ErrDuplicatePubKey = errors.New("duplicate pub key specify")
	ErrNoPriKey        = errors.New("no pri key input")
	ErrDuplicatePriKey = errors.New("duplicate pri key specify")
	ErrNoPem           = errors.New("no pem")
	ErrDataToLarge     = errors.New("message too long for RSA public key size")
	ErrDataLen         = errors.New("data length error")
	ErrDataBroken      = errors.New("data broken, first byte is not zero")
	ErrKeyPairDismatch = errors.New("data is not encrypted by the private key")
	ErrDecryption      = errors.New("decryption error")
)

type Cryptor struct {
	pub     *rsa.PublicKey
	pri     *rsa.PrivateKey
	PubPath string //公钥地址
	PriPath string //私钥地址
	Pub64   string //公钥主题不含头尾
	Pri64   string //私钥主体不含头尾
}

func (r *Cryptor) loadPubKey() {
	if r.pub != nil {
		return
	}
	if r.PubPath == "" && r.Pub64 == "" {
		panic(ErrNoPubKey)
	}
	if r.PubPath != "" && r.Pub64 != "" {
		panic(ErrDuplicatePubKey)
	}
	var keyByte []byte
	if r.PubPath != "" {
		keyByte = ReadFile(r.PubPath)
		block, _ := pem.Decode([]byte(keyByte))
		if block == nil {
			panic(ErrNoPem)
		}
		keyByte = block.Bytes
	}
	if r.Pub64 != "" {
		var err error
		keyByte, err = base64.StdEncoding.DecodeString(r.Pub64)
		CheckErr(err)
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(keyByte)
	if err != nil {
		publicKeyInterface, err = x509.ParsePKCS1PublicKey(keyByte)
		CheckErr(err)
	}
	r.pub = publicKeyInterface.(*rsa.PublicKey)
}

func (r *Cryptor) loadPriKey() {
	if r.pri != nil {
		return
	}
	if r.PriPath == "" && r.Pri64 == "" {
		panic(ErrNoPriKey)
	}
	if r.PriPath != "" && r.Pri64 != "" {
		panic(ErrDuplicatePriKey)
	}
	var keyByte []byte
	if r.PriPath != "" {
		keyByte = ReadFile(r.PriPath)
		block, _ := pem.Decode([]byte(keyByte))
		if block == nil {
			panic(ErrNoPem)
		}
		keyByte = block.Bytes
	}
	if r.Pri64 != "" {
		var err error
		keyByte, err = base64.StdEncoding.DecodeString(r.Pri64)
		CheckErr(err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyByte)
	if err != nil {
		privateKey, err = x509.ParsePKCS1PrivateKey(keyByte)
		CheckErr(err)
	}
	r.pri = privateKey.(*rsa.PrivateKey)
}

//公钥加密
func (r *Cryptor) Encrypt(plainText []byte) []byte {
	r.loadPubKey()
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, r.pub, plainText)
	CheckErr(err)
	return cipherText
}

//私钥解密
func (r *Cryptor) Decrypt(cipherText []byte) []byte {
	r.loadPriKey()
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, r.pri, cipherText)
	return plainText
}

//签名 默认SHA512
func (r *Cryptor) Sign(data []byte) []byte {
	return r.SignWithHash(data, sha512.New(), crypto.SHA512)
}

//签名 指定Hash算法 hash和hashType要保持一直
func (r *Cryptor) SignWithHash(data []byte, h hash.Hash, hashType crypto.Hash) []byte {
	r.loadPriKey()
	h.Write([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.pri, hashType, h.Sum(nil))
	CheckErr(err)
	return signature
}

//验签 默认sha512
func (r *Cryptor) Verify(data []byte, sign []byte) error {
	return r.VerifyWithHash(data, sign, sha512.New(), crypto.SHA512)
}

//验签 指定Hash算法 hash和hashType要保持一直
func (r *Cryptor) VerifyWithHash(data []byte, sign []byte, h hash.Hash, hashType crypto.Hash) error {
	r.loadPubKey()
	h.Write(data)
	return rsa.VerifyPKCS1v15(r.pub, hashType, h.Sum(nil), sign)
}

func ReadFile(path string) []byte {
	file, err := os.Open(path)
	CheckErr(err)
	defer file.Close()
	info, err := file.Stat()
	CheckErr(err)
	buf := make([]byte, info.Size())
	_, err = file.Read(buf)
	CheckErr(err)
	return buf
}

// 私钥加密
func (r *Cryptor) PriEncrypt(input []byte) []byte {
	r.loadPriKey()
	output := bytes.NewBuffer(nil)
	err := priKeyIO(r.pri, bytes.NewReader(input), output, true)
	CheckErr(err)
	out, err := ioutil.ReadAll(output)
	CheckErr(err)
	return out
}

// 公钥解密
func (r *Cryptor) PubDecrypt(input []byte) []byte {
	r.loadPubKey()
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(r.pub, bytes.NewReader(input), output, false)
	CheckErr(err)
	out, err := ioutil.ReadAll(output)
	CheckErr(err)
	return out
}

// 私钥加密或解密Reader
func priKeyIO(pri *rsa.PrivateKey, r io.Reader, w io.Writer, isEncrypt bool) (err error) {
	k := (pri.N.BitLen() + 7) / 8
	if isEncrypt {
		k = k - 11
	}
	buf := make([]byte, k)
	var b []byte
	size := 0
	for {
		size, err = r.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if size < k {
			b = buf[:size]
		} else {
			b = buf
		}
		if isEncrypt {
			b, err = priKeyEncrypt(rand.Reader, pri, b)
		} else {
			b, err = rsa.DecryptPKCS1v15(rand.Reader, pri, b)
		}
		if err != nil {
			return err
		}
		if _, err = w.Write(b); err != nil {
			return err
		}
	}
}

// 公钥加密或解密Reader
func pubKeyIO(pub *rsa.PublicKey, in io.Reader, out io.Writer, isEncrytp bool) (err error) {
	k := (pub.N.BitLen() + 7) / 8
	if isEncrytp {
		k = k - 11
	}
	buf := make([]byte, k)
	var b []byte
	size := 0
	for {
		size, err = in.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if size < k {
			b = buf[:size]
		} else {
			b = buf
		}
		if isEncrytp {
			b, err = rsa.EncryptPKCS1v15(rand.Reader, pub, b)
		} else {
			b, err = pubKeyDecrypt(pub, b)
		}
		if err != nil {
			return err
		}
		if _, err = out.Write(b); err != nil {
			return err
		}
	}
}

// 公钥解密
func pubKeyDecrypt(pub *rsa.PublicKey, data []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if k != len(data) {
		return nil, ErrDataLen
	}
	m := new(big.Int).SetBytes(data)
	if m.Cmp(pub.N) > 0 {
		return nil, ErrDataToLarge
	}
	m.Exp(m, big.NewInt(int64(pub.E)), pub.N)
	d := leftPad(m.Bytes(), k)
	if d[0] != 0 {
		return nil, ErrDataBroken
	}
	if d[1] != 0 && d[1] != 1 {
		return nil, ErrKeyPairDismatch
	}
	var i = 2
	for ; i < len(d); i++ {
		if d[i] == 0 {
			break
		}
	}
	i++
	if i == len(d) {
		return nil, nil
	}
	return d[i:], nil
}

// 从crypto/rsa复制
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}

// 私钥加密
func priKeyEncrypt(rand io.Reader, priv *rsa.PrivateKey, hashed []byte) ([]byte, error) {
	tLen := len(hashed)
	k := (priv.N.BitLen() + 7) / 8
	if k < tLen+11 {
		return nil, ErrDataLen
	}
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k], hashed)
	m := new(big.Int).SetBytes(em)
	c, err := decrypt(rand, priv, m)
	if err != nil {
		return nil, err
	}
	copyWithLeftPad(em, c.Bytes())
	return em, nil
}

// 从crypto/rsa复制
var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

func decrypt(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priv.N) > 0 {
		err = ErrDecryption
		return
	}
	var ir *big.Int
	if random != nil {
		var r *big.Int

		for {
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			var ok bool
			ir, ok = modInverse(r, priv.N)
			if ok {
				break
			}
		}
		bigE := big.NewInt(int64(priv.E))
		rpowe := new(big.Int).Exp(r, bigE, priv.N)
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}
	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}
	if ir != nil {
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}

// 从crypto/rsa复制
func modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigOne) != 0 {
		return
	}
	if x.Cmp(bigOne) < 0 {
		x.Add(x, n)
	}
	return x, true
}

// 从crypto/rsa复制
func copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}

func CheckErr(err error) {
	if err != nil {
		panic(err)
	}
}
