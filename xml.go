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
	"encoding/xml"
	"errors"
	"io"
	"sort"
)

// return a fully-formatted attribute name (prepend namespace if
// it exists)
func fullAttributeName(attr xml.Attr) string {
	if attr.Name.Space != "" {
		var name bytes.Buffer
		name.WriteString(attr.Name.Space)
		name.WriteRune(':')
		name.WriteString(attr.Name.Local)
		return name.String()
	}

	return attr.Name.Local
}

// Wrapper used to sort element attributes during XML canonicalization
type AttributeList []xml.Attr

func (a AttributeList) Len() int        { return len(a) }
func (a AttributeList) Swap(ii, jj int) { a[ii], a[jj] = a[jj], a[ii] }

// Order attributes based on XML canonicalization rules
func (a AttributeList) Less(ii, jj int) bool {
	isNamespace := func(a xml.Attr) bool {
		return a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns")
	}

	nsI, nsJ := isNamespace(a[ii]), isNamespace(a[jj])
	if nsI && nsJ {
		if a[ii].Name.Space == "" {
			return true
		} else if a[jj].Name.Space == "" {
			return false
		}

		return a[ii].Name.Local < a[jj].Name.Local
	} else if nsI {
		return true
	} else if nsJ {
		return false
	} else {
		return fullAttributeName(a[ii]) < fullAttributeName(a[jj])
	}
}

// Element Wrapper
type Element struct {
	xml.StartElement
	Children  []*Element
	InnerText string
}

// Decode an XML stream into a root XML document
func DecodeXMLDocument(r io.Reader) (*Element, error) {
	decoder := xml.NewDecoder(r)

	var root *Element
	var queue []*Element
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if root == nil {
				return nil, errors.New("Failed to find root element")
			}
			return root, nil
		} else if err != nil {
			return nil, err
		}

		switch t := token.(type) {
		case xml.StartElement:
			e := &Element{
				StartElement: t,
			}

			if len(queue) == 0 {
				root = e
			} else {
				parent := queue[len(queue)-1]
				parent.Children = append(parent.Children, e)
			}

			queue = append(queue, e)

		case xml.EndElement:
			queue = queue[:len(queue)-1]
			if len(queue) == 0 {
				return root, nil
			}

		case xml.CharData:
			if len(queue) > 0 {
				e := queue[len(queue)-1]
				e.InnerText = string(t)
			}
		}
	}
}

func EncodeXMLDocument(b *bytes.Buffer, doc *Element) {
	encodeElement(b, doc, make(map[string]string))
}

func encodeElement(b *bytes.Buffer, element *Element, namespaces map[string]string) {
	// add local namespaces to the map
	for _, attr := range element.Attr {
		if attr.Name.Space == "xmlns" {
			namespaces[attr.Value] = attr.Name.Local
			defer delete(namespaces, attr.Value)
		}
	}

	//output opening tag
	b.WriteRune('<')
	ns := namespaces[element.Name.Space]
	if ns != "" {
		b.WriteString(ns)
		b.WriteRune(':')
	}
	b.WriteString(element.Name.Local)

	// output attrbiutes
	for _, attr := range element.Attr {
		b.WriteRune(' ')
		attrNs := attr.Name.Space
		if attrNs != "xmlns" {
			attrNs = namespaces[attrNs]
		}
		if attrNs != "" {
			b.WriteString(attrNs)
			b.WriteRune(':')
		}
		b.WriteString(attr.Name.Local)
		b.WriteString(`="`)
		xml.EscapeText(b, []byte(attr.Value))
		b.WriteRune('"')
	}

	b.WriteRune('>')

	// output children
	for _, child := range element.Children {
		encodeElement(b, child, namespaces)
	}

	// output inner text
	if element.InnerText != "" {
		b.WriteString(element.InnerText)
	}

	// output closing tag
	b.WriteString("</")
	if ns != "" {
		b.WriteString(ns)
		b.WriteRune(':')
	}
	b.WriteString(element.Name.Local)
	b.WriteString(">")
}

// Canonicalize attributes in the document framgment
func (e *Element) Canonicalize() {
	e.removeUnusedNamespaceAttributes()
	sort.Sort(AttributeList(e.Attr))

	// remove unused namespace declarations
	for _, child := range e.Children {
		child.Canonicalize()
	}
}

// Find a named child in a fragment
func (e *Element) FindChild(name string) (*Element, int) {
	for ii, child := range e.Children {
		if child.Name.Local == name {
			return child, ii
		}
	}

	return nil, -1
}

func (e *Element) isNamespaceUsed(namespace string) bool {
	if e.Name.Space == namespace {
		return true
	}

	for _, attr := range e.Attr {
		if attr.Name.Space == namespace {
			return true
		}
	}

	for _, child := range e.Children {
		if child.isNamespaceUsed(namespace) {
			return true
		}
	}

	return false
}

func (e *Element) removeUnusedNamespaceAttributes() {
	var write int
	for ii, ll := 0, len(e.Attr); ii < ll; ii++ {
		if e.Attr[ii].Name.Space == "xmlns" {
			if !e.isNamespaceUsed(e.Attr[ii].Value) {
				continue // omit this namepsace attribute
			}
		}

		e.Attr[write] = e.Attr[ii]
		write++
	}

	e.Attr = e.Attr[:write]
}

func (e *Element) GetAttributeValue(name string) string {
	for _, attr := range e.Attr {
		if attr.Name.Local == name {
			return attr.Value
		}
	}

	return ""
}
