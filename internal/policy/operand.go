package policy

import (
	"fmt"
	"regexp"
	"strings"
)

type OperandKind int

const (
	OperandField OperandKind = iota
	OperandHeader
	OperandCookie
	OperandArg
	OperandHeaders
	OperandCookies
	OperandArgs
	OperandVar
)

type Operand struct {
	Raw  string
	Kind OperandKind
	Name string
	All  bool
}

var Fields = []string{
	"uri", "request_uri", "host", "request_method", "scheme", "remote_addr",
}

const (
	selHeaders = "$waf_request_headers."
	selCookies = "$waf_request_cookies."
	selArgs    = "$waf_request_args."
	selVar     = "$waf_var."
)

var varNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

var nginxNameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

func ParseOperand(raw string) (Operand, error) {
	raw = strings.TrimSpace(raw)
	op := Operand{Raw: raw}

	if raw == "" {
		return op, fmt.Errorf("value is empty")
	}

	if !strings.HasPrefix(raw, "$") {
		return op, fmt.Errorf("value %q must start with $", raw)
	}

	for _, sel := range []struct {
		prefix string
		kind   OperandKind
		all    bool
	}{
		{selHeaders, OperandHeaders, true},
		{selCookies, OperandCookies, true},
		{selArgs, OperandArgs, true},
		{selVar, OperandVar, false},
	} {
		if !strings.HasPrefix(raw, sel.prefix) {
			continue
		}

		name := raw[len(sel.prefix):]

		if name == "" {
			return op, fmt.Errorf("value %q has no name after the dot", raw)
		}

		op.Kind = sel.kind

		if name == "*" {
			if !sel.all {
				return op, fmt.Errorf("value %q: * is only for headers, cookies and args", raw)
			}

			op.All = true

			return op, nil
		}

		if sel.kind == OperandVar && !varNameRe.MatchString(name) {
			return op, fmt.Errorf("value %q: field name is not [A-Za-z0-9_.-]", raw)
		}

		if sel.kind == OperandHeaders {
			name = strings.ToLower(name)
		}

		op.Name = name

		return op, nil
	}

	name := raw[1:]

	for _, f := range Fields {
		if name == f {
			op.Kind = OperandField
			op.Name = f

			return op, nil
		}
	}

	for _, p := range []struct {
		prefix string
		kind   OperandKind
	}{
		{"http_", OperandHeader},
		{"cookie_", OperandCookie},
		{"arg_", OperandArg},
	} {
		if !strings.HasPrefix(name, p.prefix) {
			continue
		}

		tail := name[len(p.prefix):]

		if !nginxNameRe.MatchString(tail) {
			return op, fmt.Errorf("value %q: name after %s is not [A-Za-z0-9_]", raw, p.prefix)
		}

		op.Kind = p.kind
		op.Name = tail

		if p.kind == OperandHeader {
			op.Name = strings.ToLower(tail)
		}

		return op, nil
	}

	return op, fmt.Errorf("unknown value %q: expected a field ($uri, $host, $request_method, "+
		"$request_uri, $scheme, $remote_addr), $http_/$cookie_/$arg_<name>, "+
		"$waf_request_headers|cookies|args.<name|*> or $waf_var.<name>", raw)
}

type Pair struct {
	Name  string
	Value string
}

type Source interface {
	Field(name string) string
	Var(name string) (value string, ok bool)
	Headers() (pairs []Pair, ok bool)
	Cookies() (pairs []Pair, ok bool)
	Args() (pairs []Pair, ok bool)
}

func (o *Operand) Values(src Source) (values []string, avail bool) {
	switch o.Kind {
	case OperandField:
		return nonEmpty(src.Field(o.Name)), true

	case OperandVar:
		v, ok := src.Var(o.Name)

		return nonEmpty(v), ok

	case OperandHeader:
		pairs, ok := src.Headers()
		if !ok {
			return nil, false
		}

		for _, p := range pairs {
			if nginxHeaderName(p.Name) == o.Name {
				return nonEmpty(p.Value), true
			}
		}

		return nil, true

	case OperandCookie:
		return first(src.Cookies, o.Name)

	case OperandArg:
		return first(src.Args, o.Name)

	case OperandHeaders:
		pairs, ok := src.Headers()
		if !ok {
			return nil, false
		}

		for _, p := range pairs {
			if (o.All || strings.ToLower(p.Name) == o.Name) && p.Value != "" {
				values = append(values, p.Value)
			}
		}

		return values, true

	case OperandCookies:
		return all(src.Cookies, o)

	case OperandArgs:
		return all(src.Args, o)
	}

	return nil, true
}

func nonEmpty(v string) []string {
	if v == "" {
		return nil
	}

	return []string{v}
}

func first(get func() ([]Pair, bool), name string) ([]string, bool) {
	pairs, ok := get()
	if !ok {
		return nil, false
	}

	for _, p := range pairs {
		if p.Name == name {
			return nonEmpty(p.Value), true
		}
	}

	return nil, true
}

func all(get func() ([]Pair, bool), o *Operand) ([]string, bool) {
	pairs, ok := get()
	if !ok {
		return nil, false
	}

	var values []string

	for _, p := range pairs {
		if (o.All || p.Name == o.Name) && p.Value != "" {
			values = append(values, p.Value)
		}
	}

	return values, true
}

func nginxHeaderName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "-", "_")
}
