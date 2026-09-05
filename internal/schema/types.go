package schema

import (
	"errors"
	"strings"
)

// hidden replaces a value completely. Fixed length, so it does not leak the
// length of the original.
const hidden = "***"

type fieldType struct {
	validate func(string) error
	mask     func(string) string
}

// types are the declarable field types. Masks are fixed per type: a mask that
// can be configured is a mask that can be misconfigured.
var types = map[string]fieldType{
	"string": {validate: func(string) error { return nil }, mask: func(string) string { return hidden }},
	"email":  {validate: validateEmail, mask: maskEmail},
	"phone":  {validate: validatePhone, mask: maskPhone},
	"card":   {validate: validateCard, mask: maskCard},
}

func validateEmail(v string) error {
	local, domain, ok := strings.Cut(v, "@")
	if !ok || local == "" || domain == "" || strings.ContainsAny(v, " \t\r\n") || strings.Contains(domain, "@") {
		return errors.New("not an email address")
	}
	return nil
}

// maskEmail keeps the first character and the domain: i***@example.com.
func maskEmail(v string) string {
	local, domain, _ := strings.Cut(v, "@")
	if domain == "" {
		return hidden
	}
	first := ""
	for _, r := range local {
		first = string(r)
		break
	}
	return first + hidden + "@" + domain
}

func validatePhone(v string) error {
	if strings.Trim(v, "0123456789 +-().") != "" {
		return errors.New("not a phone number")
	}
	if n := len(digits(v)); n < 7 || n > 15 {
		return errors.New("not a phone number")
	}
	return nil
}

// maskPhone keeps the last four digits: ***4567.
func maskPhone(v string) string {
	tail := last4(digits(v))
	if tail == "" {
		return hidden
	}
	return hidden + tail
}

func validateCard(v string) error {
	if strings.Trim(v, "0123456789 -") != "" {
		return errors.New("not a card number")
	}
	d := digits(v)
	if len(d) < 13 || len(d) > 19 || !luhn(d) {
		return errors.New("not a card number")
	}
	return nil
}

// maskCard keeps the last four digits: **** **** **** 1234.
func maskCard(v string) string {
	tail := last4(digits(v))
	if tail == "" {
		return hidden
	}
	return "**** **** **** " + tail
}

func digits(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func last4(d string) string {
	if len(d) < 4 {
		return ""
	}
	return d[len(d)-4:]
}

// luhn reports whether d, digits only, passes the Luhn checksum.
func luhn(d string) bool {
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}
