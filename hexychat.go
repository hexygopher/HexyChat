package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"io"
)

func keygenRSA(bits int) (privateKey *rsa.PrivateKey, publicKey []byte, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, bits)
	publicKey, err = x509.MarshalPKIXPublicKey(privateKey.Public())
	return
}

func encryptRSA(plaintext []byte, publicKey *rsa.PublicKey) (ciphertext []byte, err error) {
	ciphertext, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, plaintext, make([]byte, 0))
	return
}

func decryptRSA(ciphertext []byte, privateKey *rsa.PrivateKey) (plaintext []byte, err error) {
	plaintext, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, privateKey, ciphertext, make([]byte, 0))
	return
}

func keygenAES() []byte {
	key := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, key)
	return key
}

func encryptAES(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext, plaintext)
	return iv, ciphertext, nil
}

func decryptAES(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func main() {

}
