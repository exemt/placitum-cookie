package policy

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ListCheck narrows a rule by the value of its cookie: the value is (or, with Not, is not) in a
// list. MD5 marks a list with hash=md5: the value is hashed before the lookup, as the list keeps
// only hashes. A dynamic list is looked up in the mirror; a static one (Static) comes with the
// generation and is loaded next to the profiles.
type ListCheck struct {
	List   string
	Not    bool
	MD5    bool
	Static bool
	set    map[string]struct{}
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

// in reports whether the value is in the list. No value and a list that is not ready both answer
// false: missing data never turns into a match, so "not in" holds for them.
func (t *Target) in(l *ListCheck, value string, out *Outcome) bool {
	if value == "" {
		return false
	}

	if l.MD5 {
		sum := md5.Sum([]byte(value))
		value = hex.EncodeToString(sum[:])
	}

	if l.Static {
		_, ok := l.set[value]

		return ok
	}

	if t.Sets == nil {
		out.note(l.List, NoteNotReady)

		return false
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

// ListsDir holds the static lists of a generation next to its profiles, one <name>.txt per list,
// one value per line. The leading dot keeps it out of the profile scan.
const ListsDir = ".lists"

// loadStatic reads the static lists the rules of the profiles look values up in. A list that is
// named by a rule and missing on disk fails the load: the generation came without its data.
func loadStatic(dir string, profiles map[string]*Profile) error {
	sets := map[string]map[string]struct{}{}

	for _, name := range Names(profiles) {
		p := profiles[name]

		for i := range p.Rules {
			l := p.Rules[i].Listed

			if l == nil || !l.Static {
				continue
			}

			set, ok := sets[l.List]

			if !ok {
				var err error

				set, err = readList(filepath.Join(dir, ListsDir, l.List+".txt"))
				if err != nil {
					return fmt.Errorf("%s: %s: static list %q: %w", name, p.Rules[i].Name, l.List, err)
				}

				sets[l.List] = set
			}

			l.set = set
		}
	}

	return nil
}

func readList(path string) (map[string]struct{}, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	set := map[string]struct{}{}
	lines := bufio.NewScanner(bytes.NewReader(raw))
	lines.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for lines.Scan() {
		if v := strings.TrimSpace(lines.Text()); v != "" {
			set[v] = struct{}{}
		}
	}

	if err := lines.Err(); err != nil {
		return nil, err
	}

	return set, nil
}
