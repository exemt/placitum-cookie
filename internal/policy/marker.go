package policy

import (
	"fmt"
	"strings"
)

// A marker is a string with slots in braces, filled from the cookies of the request:
//
//	{value}   the value of the rule's cookie ({tag} is its old name)
//	{cookie}  the whole string of the rule's cookie: value, time and signature
//	{name}    the name of the rule's cookie
//	{<name>}  the value of any cookie of the profile by its name: client_{uid}_{value}
//
// The slots of the rule's cookie win over a cookie that happens to be named value, cookie, name or
// tag.

// Seen is what a request knows of a cookie: the string the client carries (or was just issued) and
// its value.
type Seen struct {
	Raw   string
	Value string
}

func ownSlot(slot string) bool {
	return slot == "value" || slot == "tag" || slot == "cookie" || slot == "name"
}

// CheckMarkerSlots refuses a marker whose slots cannot be filled: a brace without its pair, a name
// that is not a cookie of the profile, a slot of the rule's cookie in a rule without one, or in a
// rule where that cookie has no value (valued is false: on absent or invalid, unless the rule
// issues it).
func CheckMarkerSlots(marker, cookie string, valued bool, p *Profile) error {
	rest := marker

	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			if strings.IndexByte(rest, '}') >= 0 {
				return fmt.Errorf("marker %q has } without {", marker)
			}

			return nil
		}

		if strings.IndexByte(rest[:open], '}') >= 0 {
			return fmt.Errorf("marker %q has } without {", marker)
		}

		end := strings.IndexByte(rest[open:], '}')
		if end < 0 {
			return fmt.Errorf("marker %q has { without }", marker)
		}

		slot := rest[open+1 : open+end]

		switch {
		case ownSlot(slot):
			if cookie == "" {
				return fmt.Errorf("marker %q: {%s} speaks of the rule's cookie, and the rule has none -- name the cookie: {<name>}",
					marker, slot)
			}

			if !valued && slot != "name" {
				return fmt.Errorf("marker %q: {%s} -- here the rule's cookie has no value; keep the marker a plain string or name another cookie",
					marker, slot)
			}
		default:
			if _, ok := p.Cookie(slot); !ok {
				return fmt.Errorf("marker %q: {%s} is not a cookie of the profile -- {value}, {cookie}, {name} or a cookie name",
					marker, slot)
			}
		}

		rest = rest[open+end+1:]
	}
}

// FillMarker fills the slots of a marker. ok is false when a slot names a cookie with no value in
// this request: such a marker is not set at all, so client_{uid} never goes out as client_.
func FillMarker(marker, cookie string, seen map[string]Seen) (out string, ok bool) {
	var b strings.Builder

	rest := marker

	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			b.WriteString(rest)

			return b.String(), true
		}

		end := strings.IndexByte(rest[open:], '}')
		if end < 0 {
			b.WriteString(rest)

			return b.String(), true
		}

		b.WriteString(rest[:open])

		slot := rest[open+1 : open+end]
		v := ""

		switch slot {
		case "value", "tag":
			v = seen[cookie].Value
		case "cookie":
			v = seen[cookie].Raw
		case "name":
			v = cookie
		default:
			v = seen[slot].Value
		}

		if v == "" {
			return "", false
		}

		b.WriteString(v)
		rest = rest[open+end+1:]
	}
}
