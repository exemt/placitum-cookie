package policy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	StateAbsent  = "absent"
	StatePresent = "present"
	StateInvalid = "invalid"
	StateExpired = "expired"
)

var States = []string{StateAbsent, StatePresent, StateInvalid, StateExpired}

const (
	SignHMAC = "hmac"
	SignNone = "none"
)

const (
	ValueMax      = 256
	MaxLenLimit   = 128
	MaxLenDefault = 64
	RandomMax     = 32
	RandomDefault = 8
	macBytes      = 12
	macChars      = 16
)

var cookieNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

type Recipe struct {
	From    *Operand
	Default string
	Random  int
	MaxLen  int
}

type Cookie struct {
	Name      string
	Path      string
	MaxAge    time.Duration
	MaxAgeSet bool
	Sign      string
	Renew     time.Duration
	Value     Recipe
}

func (c *Cookie) Signed() bool { return c.Sign == SignHMAC }

func (c *Cookie) Issue(src Source, now time.Time, key []byte) (value, tag string, err error) {
	raw := c.Value.Default

	if c.Value.From != nil {
		if values, avail := c.Value.From.Values(src); avail && len(values) > 0 && values[0] != "" {
			raw = values[0]
		}
	}

	limit := c.Value.MaxLen
	if limit <= 0 {
		limit = MaxLenDefault
	}

	tag = sanitizeTag(raw, limit)

	var sb strings.Builder

	sb.WriteString(tag)

	if c.Value.Random > 0 {
		buf := make([]byte, c.Value.Random)

		if _, err := rand.Read(buf); err != nil {
			return "", "", fmt.Errorf("random for cookie %q: %w", c.Name, err)
		}

		if tag != "" {
			sb.WriteByte('~')
		}

		sb.WriteString(hex.EncodeToString(buf))
	}

	value = sb.String()

	if value == "" {
		return "", "", ErrNoValue
	}

	// The value of the cookie as the next request reads it: the number alone when the declaration
	// has nothing else.
	tag = tagOf(value)

	if c.Signed() {
		if len(key) == 0 {
			return "", "", ErrNoSecret
		}

		stamp := strconv.FormatInt(now.Unix(), 36)
		value = value + "." + stamp + "." + mac(key, c.Name, value+"."+stamp)
	}

	if len(value) > ValueMax {
		return "", "", fmt.Errorf("cookie %q: value is %d bytes, over %d",
			c.Name, len(value), ValueMax)
	}

	return value, tag, nil
}

func (c *Cookie) Read(raw string, now time.Time, key []byte) (state, tag string, err error) {
	if raw == "" {
		return StateAbsent, "", nil
	}

	if len(raw) > ValueMax {
		return StateInvalid, "", nil
	}

	if !c.Signed() {
		return StatePresent, tagOf(raw), nil
	}

	if len(key) == 0 {
		return "", "", ErrNoSecret
	}

	rest, sig, ok := cutLast(raw, '.')
	if !ok {
		return StateInvalid, "", nil
	}

	payload, stamp, ok := cutLast(rest, '.')
	if !ok {
		return StateInvalid, "", nil
	}

	if len(sig) != macChars ||
		subtle.ConstantTimeCompare([]byte(sig), []byte(mac(key, c.Name, payload+"."+stamp))) != 1 {
		return StateInvalid, "", nil
	}

	secs, perr := strconv.ParseInt(stamp, 36, 64)
	if perr != nil {
		return StateInvalid, "", nil
	}

	issued := time.Unix(secs, 0)

	if issued.After(now.Add(time.Minute)) {
		return StateInvalid, "", nil
	}

	if c.Renew > 0 && now.Sub(issued) >= c.Renew {
		return StateExpired, tagOf(payload), nil
	}

	return StatePresent, tagOf(payload), nil
}

var ErrNoSecret = fmt.Errorf("cookie signing key is not configured")

// ErrNoValue: the request carries no value for the cookie and the declaration has neither a
// fallback nor a number. It is not a failure: such a client simply gets no cookie.
var ErrNoValue = fmt.Errorf("cookie value is empty")

func mac(key []byte, name, payload string) string {
	derived := hmac.New(sha256.New, key)
	derived.Write([]byte("cookie:" + name))

	h := hmac.New(sha256.New, derived.Sum(nil))
	h.Write([]byte(payload))

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:macBytes])[:macChars]
}

func tagOf(payload string) string {
	if i := strings.IndexByte(payload, '~'); i >= 0 {
		return payload[:i]
	}

	return payload
}

func cutLast(s string, sep byte) (head, tail string, ok bool) {
	i := strings.LastIndexByte(s, sep)
	if i < 0 {
		return "", "", false
	}

	return s[:i], s[i+1:], true
}

func sanitizeTag(raw string, limit int) string {
	if raw == "" {
		return ""
	}

	if limit > MaxLenLimit {
		limit = MaxLenLimit
	}

	out := make([]byte, 0, limit)

	for i := 0; i < len(raw) && len(out) < limit; i++ {
		c := raw[i]

		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}

	return string(out)
}

type fileRecipe struct {
	From    string `yaml:"from"`
	Default string `yaml:"default"`
	Random  *int   `yaml:"random"`
	MaxLen  int    `yaml:"max_len"`
}

type fileCookie struct {
	Name   string      `yaml:"name"`
	Path   string      `yaml:"path"`
	MaxAge string      `yaml:"max_age"`
	Sign   string      `yaml:"sign"`
	Renew  string      `yaml:"renew_after"`
	Value  *fileRecipe `yaml:"value"`
}

func parseCookie(at string, fc fileCookie) (*Cookie, error) {
	c := &Cookie{
		Name: strings.TrimSpace(fc.Name),
		Path: strings.TrimSpace(fc.Path),
		Sign: strings.TrimSpace(fc.Sign),
	}

	if !cookieNameRe.MatchString(c.Name) {
		return nil, fmt.Errorf("%s: name %q is not a cookie name", at, c.Name)
	}

	if c.Path == "" {
		c.Path = "/"
	}

	if !strings.HasPrefix(c.Path, "/") {
		return nil, fmt.Errorf("%s: path %q does not start with /", at, c.Path)
	}

	if c.Sign == "" {
		c.Sign = SignHMAC
	}

	if c.Sign != SignHMAC && c.Sign != SignNone {
		return nil, fmt.Errorf("%s: sign must be %s or %s, got %q",
			at, SignHMAC, SignNone, c.Sign)
	}

	if s := strings.TrimSpace(fc.MaxAge); s != "" {
		d, err := parseTTL(s)
		if err != nil {
			return nil, fmt.Errorf("%s: max_age: %w", at, err)
		}

		if d < time.Second {
			return nil, fmt.Errorf("%s: max_age %q is shorter than a second", at, s)
		}

		c.MaxAge, c.MaxAgeSet = d, true
	}

	if s := strings.TrimSpace(fc.Renew); s != "" {
		d, err := parseTTL(s)
		if err != nil {
			return nil, fmt.Errorf("%s: renew_after: %w", at, err)
		}

		if d < time.Second {
			return nil, fmt.Errorf("%s: renew_after %q is shorter than a second", at, s)
		}

		if c.Sign != SignHMAC {
			return nil, fmt.Errorf("%s: renew_after needs sign: %s -- "+
				"without a signature the cookie carries no issue time", at, SignHMAC)
		}

		if c.MaxAgeSet && d >= c.MaxAge {
			return nil, fmt.Errorf("%s: renew_after %q is not shorter than max_age -- "+
				"the browser drops the cookie before it is renewed", at, s)
		}

		c.Renew = d
	}

	rec := fileRecipe{}
	if fc.Value != nil {
		rec = *fc.Value
	}

	if s := strings.TrimSpace(rec.From); s != "" {
		op, err := ParseOperand(s)
		if err != nil {
			return nil, fmt.Errorf("%s: value.from: %w", at, err)
		}

		c.Value.From = &op
	}

	c.Value.Default = sanitizeTag(strings.TrimSpace(rec.Default), MaxLenLimit)

	c.Value.Random = RandomDefault
	if rec.Random != nil {
		c.Value.Random = *rec.Random
	}

	if c.Value.Random < 0 || c.Value.Random > RandomMax {
		return nil, fmt.Errorf("%s: value.random must be within 0..%d, got %d",
			at, RandomMax, c.Value.Random)
	}

	c.Value.MaxLen = rec.MaxLen
	if c.Value.MaxLen == 0 {
		c.Value.MaxLen = MaxLenDefault
	}

	if c.Value.MaxLen < 1 || c.Value.MaxLen > MaxLenLimit {
		return nil, fmt.Errorf("%s: value.max_len must be within 1..%d, got %d",
			at, MaxLenLimit, c.Value.MaxLen)
	}

	if c.Value.From == nil && c.Value.Default == "" && c.Value.Random == 0 {
		return nil, fmt.Errorf("%s: value has no source: set from, default or random", at)
	}

	return c, nil
}
