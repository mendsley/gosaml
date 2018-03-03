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
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

const (
	assertionNamespace  = "urn:oasis:names:tc:SAML:2.0:assertion"
	signatureNamespace  = "http://www.w3.org/2000/09/xmldsig#"
	stdCanonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#"
	envelopedSignature  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

	digestMethodSha1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	digestMethodSha256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	digestMethodSha512 = "http://www.w3.org/2001/04/xmlenc#sha512"

	signatureMethodRsaSha1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	signatureMethodRsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	signatureMethodRsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
)

type Assertion struct {
	xml                 *Element
	Issuer              string
	SubjectConfirmation string
	Audience            string
	NotBefore           time.Time
	NotOnOrAfter        time.Time
	Attributes          []Attribute
}

type Attribute struct {
	Name  string
	Value string
}

func UnmarshalAssertion(data string) (*Assertion, error) {
	root, err := DecodeXMLDocument(strings.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("Failed to decode XML: %v", err)
	}

	a := &Assertion{
		xml: root,
	}

	// decode issuer
	if issuer, _ := root.FindChild("Issuer"); issuer != nil && issuer.Name.Space == assertionNamespace {
		a.Issuer = issuer.InnerText
	}

	// decode subject confirmation
	if subject, _ := root.FindChild("Subject"); subject != nil && subject.Name.Space == assertionNamespace {
		if confirmation, _ := subject.FindChild("SubjectConfirmation"); confirmation != nil && confirmation.Name.Space == assertionNamespace {
			a.SubjectConfirmation = confirmation.GetAttributeValue("Method")
		}
	}

	// decode the valid time span
	if conditions, _ := root.FindChild("Conditions"); conditions != nil && conditions.Name.Space == assertionNamespace {
		var err error
		a.NotBefore, err = time.Parse(time.RFC3339, conditions.GetAttributeValue("NotBefore"))
		if err != nil {
			return nil, fmt.Errorf("Failed to parse NotBefore attribute: %v", err)
		}

		a.NotOnOrAfter, err = time.Parse(time.RFC3339, conditions.GetAttributeValue("NotOnOrAfter"))
		if err != nil {
			return nil, fmt.Errorf("Failed to parse NotOnOrAfter attribute: %v", err)
		}

		// decode audience restrictions
		if audienceRestriction, _ := conditions.FindChild("AudienceRestriction"); audienceRestriction != nil && audienceRestriction.Name.Space == assertionNamespace {
			if audience, _ := audienceRestriction.FindChild("Audience"); audience != nil && audience.Name.Space == assertionNamespace {
				a.Audience = audience.InnerText
			}
		}
	}

	// decode attributes
	if attrStatement, _ := root.FindChild("AttributeStatement"); attrStatement != nil && attrStatement.Name.Space == assertionNamespace {
		for _, child := range attrStatement.Children {
			if child.Name.Space != assertionNamespace || child.Name.Local != "Attribute" {
				continue
			}

			if attrElem, _ := child.FindChild("AttributeValue"); attrElem != nil && attrElem.Name.Space == assertionNamespace {
				attr := Attribute{
					Name:  child.GetAttributeValue("Name"),
					Value: attrElem.InnerText,
				}

				a.Attributes = append(a.Attributes, attr)
			}
		}
	}

	root.Canonicalize()
	return a, nil
}

// Verify the authenticity of an assertion
func (a *Assertion) VerifySignature(cert *x509.Certificate) error {
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("Certificate provides an unknown public key of type %T", cert.PublicKey)
	}

	assertionId := a.xml.GetAttributeValue("ID")
	if assertionId == "" {
		return errors.New("Assertion does not have an identity attribute")
	}

	// ensure we have a valid signature for the entire document
	signature, signatureIndex := a.xml.FindChild("Signature")
	if signature == nil || signature.Name.Space != signatureNamespace {
		return errors.New("No digital signature element present")
	}

	signedInfo, _ := signature.FindChild("SignedInfo")
	if signedInfo == nil || signature.Name.Space != signatureNamespace {
		return errors.New("No digital signature details present")
	}

	// verify stock canonicalization
	if canonicalization, _ := signedInfo.FindChild("CanonicalizationMethod"); canonicalization == nil || canonicalization.Name.Space != signatureNamespace {
		return errors.New("No canonicalization method for signature")
	} else if method := canonicalization.GetAttributeValue("Algorithm"); method != stdCanonicalization {
		return fmt.Errorf("Unknown XML canonicalization method supplied: %q", method)
	}

	// find reference node for assertion
	var reference *Element
	for _, child := range signedInfo.Children {
		if child.Name.Local != "Reference" || child.Name.Space != signatureNamespace {
			continue
		}

		if child.GetAttributeValue("URI") != "#"+assertionId {
			continue
		}

		reference = child
		break
	}
	if reference == nil {
		return errors.New("No assertion reference found in signature")
	}

	// verify transforms for reference
	if transforms, _ := reference.FindChild("Transforms"); transforms == nil || transforms.Name.Space != signatureNamespace {
		return errors.New("Reference element does not contain a transform stack")
	} else {
		if ll := len(transforms.Children); ll < 2 {
			return fmt.Errorf("Expeted 2 transforms, got %d", ll)
		}

		for ii, child := range transforms.Children {
			if child.Name.Local != "Transform" || child.Name.Space != signatureNamespace {
				continue
			}

			algorithm := child.GetAttributeValue("Algorithm")

			var expected string
			switch ii {
			case 0:
				expected = envelopedSignature
			case 1:
				expected = stdCanonicalization
			default:
				return fmt.Errorf("Unknown extra transform %q present", algorithm)
			}
			if expected != algorithm {
				return fmt.Errorf("Expected transform %q at index %d, got %q", expected, ii, algorithm)
			}
		}
	}

	// get digest value
	digestValue, _ := reference.FindChild("DigestValue")
	if digestValue == nil || digestValue.Name.Space != signatureNamespace {
		return errors.New("No digest value provided for assertion")
	}

	// verify digest method
	digestMethod, _ := reference.FindChild("DigestMethod")
	if digestMethod == nil || digestMethod.Name.Space != signatureNamespace {
		return errors.New("No digest method provided for assertion")
	}

	// parse digest method into something usable
	var hash hash.Hash
	switch method := digestMethod.GetAttributeValue("Algorithm"); method {
	case digestMethodSha1:
		hash = sha1.New()
	case digestMethodSha256:
		hash = sha256.New()
	case digestMethodSha512:
		hash = sha512.New()
	default:
		return fmt.Errorf("Unknown digest method %q supplied", method)
	}

	// remove the signature element from the assertion (for digest calculation)
	n := copy(a.xml.Children[signatureIndex:], a.xml.Children[signatureIndex+1:])
	a.xml.Children = a.xml.Children[:n+signatureIndex]
	defer func() {
		a.xml.Children = append(a.xml.Children, signature)
	}()

	// calculate the digest of the assertion
	var b bytes.Buffer
	EncodeXMLDocument(&b, a.xml)
	hash.Write(b.Bytes())
	digest := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	// compare digest
	if digest != digestValue.InnerText {
		return fmt.Errorf("Digest of assertion does not match %q != %q", digestValue.InnerText, digest)
	}

	// get signature value
	signatureValue, _ := signature.FindChild("SignatureValue")
	if signatureValue == nil || signatureValue.Name.Space != signatureNamespace {
		return errors.New("No signature value provided for assertion")
	}
	providedSignature, err := base64.StdEncoding.DecodeString(signatureValue.InnerText)
	if err != nil {
		return fmt.Errorf("Failed to parse signature value: %v", err)
	}

	// verify signature method
	signatureMethod, _ := signedInfo.FindChild("SignatureMethod")
	if signatureMethod == nil || signatureMethod.Name.Space != signatureNamespace {
		return fmt.Errorf("No signature method was provided for assertion")
	}

	// parse the signature method into something usable
	var hashType crypto.Hash
	switch method := signatureMethod.GetAttributeValue("Algorithm"); method {
	case signatureMethodRsaSha1:
		hash = sha1.New()
		hashType = crypto.SHA1
	case signatureMethodRsaSha256:
		hash = sha256.New()
		hashType = crypto.SHA256
	case signatureMethodRsaSha512:
		hash = sha512.New()
		hashType = crypto.SHA512
	default:
		return fmt.Errorf("Unknown signature method %q supplied", method)
	}

	// ensure the signedInfo element has a namespace reference
	found := false
	for _, attr := range signedInfo.Attr {
		if attr.Name.Space == "xmlns" && attr.Value == signatureNamespace {
			found = true
			break
		}
	}
	if !found {
		for _, attr := range signature.Attr {
			if attr.Name.Space == "xmlns" && attr.Value == signatureNamespace {
				found = true
				signedInfo.Attr = append(signedInfo.Attr, attr)
				defer func(index int) {
					n := copy(signedInfo.Attr[index:], signedInfo.Attr[index+1:])
					signedInfo.Attr = signedInfo.Attr[:index+n]
				}(len(signedInfo.Attr) - 1)
				break
			}
		}
		if !found {
			return errors.New("Failed to locate the xmldsig namespace attribute")
		}
	}

	// calculate digest of signed info element
	b.Reset()
	EncodeXMLDocument(&b, signedInfo)
	hash.Write(b.Bytes())

	// verify the signature
	if err := rsa.VerifyPKCS1v15(publicKey, hashType, hash.Sum(nil), providedSignature); err != nil {
		return err
	}

	return nil
}
