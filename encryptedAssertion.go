// Copyright 2014 Matthew Endsley
// All rights reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted providing that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"hash"
	"strings"
)

const (
	keyTransportRsa15   = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	keyTransportRsaOAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"

	blockCipherTripleDESCBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	blockCipherAES128CBC    = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	blockCipherAES192CBC    = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	blockCipherAES256CBC    = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
)

// Decrypt an encrypted SAML assertion
func DecodeEncryptedAssertion(data string, key crypto.PrivateKey) (*Assertion, error) {
	privKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Unknown priate key type %T", key)
	}

	var encryptedAssertion struct {
		EncryptedData struct {
			EncryptionMethod struct {
				Algorithm string `xml:",attr"`
			}
			KeyInfo struct {
				EncryptedKey struct {
					EncryptionMethod struct {
						Algorithm    string `xml:",attr"`
						DigestMethod struct {
							Algorithm string `xml:",attr"`
						}
					}
					CipherData struct {
						CipherValue string
					}
				}
			}
			CipherData struct {
				CipherValue string
			}
		}
	}

	err := xml.NewDecoder(strings.NewReader(data)).Decode(&encryptedAssertion)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarhsal encrypted assertion XML: %v", err)
	}

	// get the cipher text for the transient key
	cipherText, err := base64.StdEncoding.DecodeString(encryptedAssertion.EncryptedData.KeyInfo.EncryptedKey.CipherData.CipherValue)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse encrypted transient key: %v", err)
	}

	var transientKey []byte
	switch method := encryptedAssertion.EncryptedData.KeyInfo.EncryptedKey.EncryptionMethod.Algorithm; method {
	case keyTransportRsa15:
		transientKey, err = rsa.DecryptPKCS1v15(rand.Reader, privKey, cipherText)
	case keyTransportRsaOAEP:
		// parse the digest method for this encryption type
		var hash hash.Hash
		switch method := encryptedAssertion.EncryptedData.KeyInfo.EncryptedKey.EncryptionMethod.DigestMethod.Algorithm; method {
		case digestMethodSha1:
			hash = sha1.New()
		case digestMethodSha256:
			hash = sha256.New()
		case digestMethodSha512:
			hash = sha512.New()
		default:
			return nil, fmt.Errorf("Unknown RSA-OAEP digest type: %q", method)
		}

		transientKey, err = rsa.DecryptOAEP(hash, rand.Reader, privKey, cipherText, nil)
	default:
		return nil, fmt.Errorf("Unknown key transport algorithm %q", method)
	}

	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt transient key: %v", err)
	}

	// get the cipher text for the assertion
	cipherText, err = base64.StdEncoding.DecodeString(encryptedAssertion.EncryptedData.CipherData.CipherValue)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse encrypted assertion data: %v", err)
	}

	// parse the encryption mode into something useful
	var bm cipher.BlockMode
	switch method := encryptedAssertion.EncryptedData.EncryptionMethod.Algorithm; method {
	case blockCipherTripleDESCBC:
		block, err := des.NewTripleDESCipher(transientKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to create triple des cipher: %v", err)
		}

		bm = cipher.NewCBCDecrypter(block, cipherText[:des.BlockSize])
		cipherText = cipherText[des.BlockSize:]

	case blockCipherAES128CBC, blockCipherAES192CBC, blockCipherAES256CBC:
		block, err := aes.NewCipher(transientKey)
		if err != nil {
			return nil, fmt.Errorf("Failed to create AES cipher: %v", err)
		}

		iv := cipherText[:aes.BlockSize]
		cipherText = cipherText[aes.BlockSize:]
		bm = cipher.NewCBCDecrypter(block, iv)

	default:
		return nil, fmt.Errorf("Unknown block encryption algorithm %q", method)
	}

	// decrypt the assertion
	assertionBytes := make([]byte, len(cipherText))
	bm.CryptBlocks(assertionBytes, cipherText)

	return UnmarshalAssertion(string(assertionBytes))
}
