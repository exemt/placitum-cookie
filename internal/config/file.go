package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
)

const (
	QueueFullDrop = "drop"
	QueueFullWait = "wait"

	QueueExpandOff = "off"
	QueueExpandAsk = "ask"
)

type queueFile struct {
	Max    *int
	Full   string
	Expand string

	RedisURL string
}

func confPath(envName string) string {
	if v, ok := os.LookupEnv(envName); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}

	for _, candidate := range []string{"inspector.conf", "/app/inspector.conf"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
	}

	return ""
}

func loadQueueFile(path string) (queueFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return queueFile{}, fmt.Errorf("%s: %w", path, err)
	}

	return parseQueueFile(path, string(raw))
}

func parseQueueFile(name, src string) (queueFile, error) {
	var out queueFile
	seen := map[string]bool{}
	block, opened := "", 0

	for i, line := range strings.Split(src, "\n") {
		n := i + 1

		text := confText(line)
		if text == "" {
			continue
		}

		if block != "" {
			if text == "}" {
				block = ""
				continue
			}

			if err := parseRedisKey(&out, seen, text); err != nil {
				return queueFile{}, fmt.Errorf("%s:%d: %w", name, n, err)
			}

			continue
		}

		if text == "}" {
			return queueFile{}, fmt.Errorf("%s:%d: unexpected }", name, n)
		}

		if head, ok := strings.CutSuffix(text, "{"); ok {
			head = strings.TrimSpace(head)
			if head != "redis" {
				return queueFile{}, fmt.Errorf("%s:%d: unknown block %q", name, n, head)
			}

			if seen[head] {
				return queueFile{}, fmt.Errorf("%s:%d: %s block is set twice", name, n, head)
			}

			seen[head] = true
			block, opened = head, n

			continue
		}

		stmt, err := requireSemicolon(text)
		if err != nil {
			return queueFile{}, fmt.Errorf("%s:%d: %w", name, n, err)
		}

		key, value, err := splitDirective(stmt)
		if err != nil {
			return queueFile{}, fmt.Errorf("%s:%d: %w", name, n, err)
		}

		if seen[key] {
			return queueFile{}, fmt.Errorf("%s:%d: %s is set twice", name, n, key)
		}

		seen[key] = true

		switch key {
		case "queue_max":
			v, err := strconv.Atoi(value)
			if err != nil || v < 1 {
				return queueFile{}, fmt.Errorf("%s:%d: queue_max must be a positive integer, got %q",
					name, n, value)
			}

			out.Max = &v

		case "queue_full":
			switch value {
			case QueueFullDrop, QueueFullWait:
				out.Full = value
			default:
				return queueFile{}, fmt.Errorf("%s:%d: queue_full must be drop or wait, got %q",
					name, n, value)
			}

		case "queue_expand":
			switch value {
			case QueueExpandOff, QueueExpandAsk:
				out.Expand = value
			default:
				return queueFile{}, fmt.Errorf("%s:%d: queue_expand must be off or ask, got %q",
					name, n, value)
			}

		default:
			return queueFile{}, fmt.Errorf("%s:%d: unknown directive %q", name, n, key)
		}
	}

	if block != "" {
		return queueFile{}, fmt.Errorf("%s:%d: %s block is not closed", name, opened, block)
	}

	return out, nil
}

func parseRedisKey(out *queueFile, seen map[string]bool, text string) error {
	stmt, err := requireSemicolon(text)
	if err != nil {
		return err
	}

	key, value, err := splitDirective(stmt)
	if err != nil {
		return err
	}

	id := "redis." + key
	if seen[id] {
		return fmt.Errorf("redis %s is set twice", key)
	}

	seen[id] = true

	if key != "url" && key != "internal" {
		return fmt.Errorf("unknown key %q in the redis block, want url or internal", key)
	}

	if !isRedisURL(value) {
		return fmt.Errorf("redis %s must be redis://host:port[/db] or rediss://..., got %q", key, value)
	}

	// internal is accepted for the shared inspector.conf form and ignored: the cookie inspector
	// reads no datasets, so it has nothing to mirror from the internal Redis.
	if key == "url" {
		out.RedisURL = value
	}

	return nil
}

func isRedisURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}

	return u.Scheme == "redis" || u.Scheme == "rediss"
}

func exchangeRedis(file queueFile) string {
	if v, ok := os.LookupEnv("REDIS_URL"); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}

	return file.RedisURL
}

func confText(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}

	return strings.TrimSpace(line)
}

func requireSemicolon(text string) (string, error) {
	if !strings.HasSuffix(text, ";") {
		return "", fmt.Errorf("missing semicolon")
	}

	return strings.TrimSpace(strings.TrimSuffix(text, ";")), nil
}

func splitDirective(stmt string) (string, string, error) {
	stmt = strings.TrimSpace(stmt)
	if stmt == "" {
		return "", "", fmt.Errorf("empty directive")
	}

	key, rest, ok := strings.Cut(stmt, " ")
	if !ok {
		return "", "", fmt.Errorf("directive %q has no value", stmt)
	}

	if !isConfName(key) {
		return "", "", fmt.Errorf("invalid directive name %q", key)
	}

	value := strings.TrimSpace(rest)
	if value == "" || strings.ContainsAny(value, " \t") {
		return "", "", fmt.Errorf("directive %s expects one value", key)
	}

	return key, value, nil
}

func isConfName(s string) bool {
	if s == "" {
		return false
	}

	for _, r := range s {
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}

	return true
}

func applyQueueFile(c *queueSettings, file queueFile) {
	if file.Max != nil {
		c.Max = *file.Max
	}

	if file.Full != "" {
		c.Full = file.Full
	}

	if file.Expand != "" {
		c.Expand = file.Expand
	}
}

type queueSettings struct {
	Max    int
	Full   string
	Expand string
}

func envOverride(name, current string) string {
	if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}

	return current
}
