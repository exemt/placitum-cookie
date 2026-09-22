package policy

import (
	"crypto/md5"
	"encoding/hex"
)

// ListCheck narrows a rule by the value of its cookie: the value the client presented is (or, with
// Not, is not) in a dynamic list. MD5 marks a list with hash=md5: the value is hashed before the
// lookup, as the list keeps only hashes.
type ListCheck struct {
	List string
	Not  bool
	MD5  bool
}

// Sets answers whether a value is in a dynamic list; ready is false while the mirror has not got
// the list yet.
type Sets interface {
	Contains(name, value string) (ok, ready bool)
}

// Note says where data was missing: a list the mirror has not received yet.
type Note struct {
	List string `json:"list"`
	Why  string `json:"why"`
}

const NoteNotReady = "not_ready"

// in reports whether the presented value is in the list. No value and a list that is not ready
// both answer false: missing data never turns into a match, so "not in" holds for them.
func (t *Target) in(l *ListCheck, value string, out *Outcome) bool {
	if value == "" {
		return false
	}

	if t.Sets == nil {
		out.note(l.List, NoteNotReady)

		return false
	}

	if l.MD5 {
		sum := md5.Sum([]byte(value))
		value = hex.EncodeToString(sum[:])
	}

	ok, ready := t.Sets.Contains(l.List, value)
	if !ready {
		out.note(l.List, NoteNotReady)
	}

	return ok
}

func (o *Outcome) note(list, why string) {
	for _, n := range o.Notes {
		if n.List == list && n.Why == why {
			return
		}
	}

	o.Notes = append(o.Notes, Note{List: list, Why: why})
}
