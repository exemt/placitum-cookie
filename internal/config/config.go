package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/exemt/placitum-shared/loglevel"
)

type Config struct {
	Servers []string
	Subject string
	Name    string
	Queue   string

	ProfilesDir string
	DataDir     string

	ReloadEvery time.Duration

	Workers     int
	QueueDepth  int
	QueueFull   string
	QueueExpand string
	ConfPath    string
	ReserveMS   int
	MinBudgetMS int

	Versions []int
	LogLevel slog.Level

	HeartbeatEvery time.Duration

	RedisURL     string
	InternalURL  string
	InternalFrom string

	GeoAddr    string
	GeoTimeout time.Duration
	GeoNegMax  int

	Secret []byte
}

const RedisTimeout = 20 * time.Millisecond

func Load() (*Config, error) {
	c := &Config{
		Servers:     splitList(env("NATS_URL", "nats://127.0.0.1:4222")),
		Subject:     env("WAF_COOKIE_SUBJECT", "waf.req.cookie"),
		Name:        env("WAF_COOKIE_NAME", "cookie"),
		ProfilesDir: env("WAF_COOKIE_PROFILES", "./profiles"),
		DataDir:     env("WAF_COOKIE_DATA", ""),
		GeoAddr:     env("WAF_COOKIE_GEO_ADDR", ""),
	}

	c.Queue = env("WAF_COOKIE_QUEUE", c.Name)

	var err error

	if c.Workers, err = envInt("WAF_COOKIE_WORKERS", runtime.GOMAXPROCS(0)); err != nil {
		return nil, err
	}

	q := queueSettings{
		Max:    256,
		Full:   QueueFullDrop,
		Expand: QueueExpandOff,
	}

	var file queueFile

	c.ConfPath = confPath("WAF_COOKIE_CONF")
	if c.ConfPath != "" {
		var ferr error
		if file, ferr = loadQueueFile(c.ConfPath); ferr != nil {
			return nil, ferr
		}

		applyQueueFile(&q, file)
	}

	c.RedisURL = exchangeRedis(file)
	c.InternalURL, c.InternalFrom = internalRedis(c.ConfPath, file, c.RedisURL)

	if q.Max, err = envIntIfSet("WAF_COOKIE_QUEUE_DEPTH", q.Max); err != nil {
		return nil, err
	}

	c.QueueDepth = q.Max
	c.QueueFull = envOverride("WAF_COOKIE_QUEUE_FULL", q.Full)
	c.QueueExpand = envOverride("WAF_COOKIE_QUEUE_EXPAND", q.Expand)

	if c.ReserveMS, err = envInt("WAF_COOKIE_RESERVE_MS", 1); err != nil {
		return nil, err
	}

	if c.MinBudgetMS, err = envInt("WAF_COOKIE_MIN_BUDGET_MS", 1); err != nil {
		return nil, err
	}

	if c.Versions, err = envIntList("WAF_COOKIE_VERSIONS", []int{2}); err != nil {
		return nil, err
	}

	if c.LogLevel, err = parseLevel(env("WAF_COOKIE_LOG", "info")); err != nil {
		return nil, err
	}

	if c.HeartbeatEvery, err = envDuration("WAF_HEARTBEAT_EVERY", 4*time.Second); err != nil {
		return nil, err
	}

	if c.ReloadEvery, err = envDuration("WAF_COOKIE_RELOAD_EVERY", time.Second); err != nil {
		return nil, err
	}

	if c.GeoTimeout, err = envDuration("WAF_COOKIE_GEO_TIMEOUT", 500*time.Millisecond); err != nil {
		return nil, err
	}

	if c.GeoNegMax, err = envInt("WAF_COOKIE_GEO_NEG_MAX", 0); err != nil {
		return nil, err
	}

	if c.Secret, err = loadSecret(); err != nil {
		return nil, err
	}

	return c, c.validate()
}

func loadSecret() ([]byte, error) {
	if path := strings.TrimSpace(os.Getenv("WAF_COOKIE_SECRET_FILE")); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("WAF_COOKIE_SECRET_FILE: %w", err)
		}

		return checkSecret(bytes.TrimSpace(raw))
	}

	return checkSecret([]byte(strings.TrimSpace(os.Getenv("WAF_COOKIE_SECRET"))))
}

const SecretMin = 16

func checkSecret(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, nil
	}

	if len(key) < SecretMin {
		return nil, fmt.Errorf("cookie signing key is %d bytes, under %d",
			len(key), SecretMin)
	}

	return key, nil
}

func (c *Config) validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("NATS_URL is empty")
	}

	if c.Subject == "" || c.Name == "" || c.Queue == "" {
		return fmt.Errorf("subject, name and queue must not be empty")
	}

	if c.Workers < 1 {
		return fmt.Errorf("WAF_COOKIE_WORKERS must be positive, got %d", c.Workers)
	}

	if c.QueueDepth < 1 {
		return fmt.Errorf("queue_max must be positive, got %d", c.QueueDepth)
	}

	switch c.QueueFull {
	case QueueFullDrop, QueueFullWait:
	default:
		return fmt.Errorf("queue_full must be drop or wait, got %q", c.QueueFull)
	}

	switch c.QueueExpand {
	case QueueExpandOff, QueueExpandAsk:
	default:
		return fmt.Errorf("queue_expand must be off or ask, got %q", c.QueueExpand)
	}

	if c.ReserveMS < 0 || c.MinBudgetMS < 0 {
		return fmt.Errorf("WAF_COOKIE_RESERVE_MS and WAF_COOKIE_MIN_BUDGET_MS must not be negative")
	}

	if len(c.Versions) == 0 {
		return fmt.Errorf("WAF_COOKIE_VERSIONS is empty")
	}

	abs, err := filepath.Abs(c.ProfilesDir)
	if err != nil {
		return fmt.Errorf("WAF_COOKIE_PROFILES: %w", err)
	}

	st, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("WAF_COOKIE_PROFILES: %w", err)
	}

	if !st.IsDir() {
		return fmt.Errorf("WAF_COOKIE_PROFILES: %s is not a directory", abs)
	}

	c.ProfilesDir = abs

	if c.DataDir == "" {
		c.DataDir = abs + ".applied"
	}

	data, err := filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("WAF_COOKIE_DATA: %w", err)
	}

	c.DataDir = data

	return nil
}

func (c *Config) Supports(v int) bool {
	for _, known := range c.Versions {
		if known == v {
			return true
		}
	}

	return false
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}

func envInt(name string, def int) (int, error) {
	return envIntIfSet(name, def)
}

func envIntIfSet(name string, def int) (int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	return v, nil
}

func envIntList(name string, def []int) ([]int, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	var out []int

	for _, part := range splitList(raw) {
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		out = append(out, v)
	}

	return out, nil
}

func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}

	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	return d, nil
}

func splitList(s string) []string {
	var out []string

	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}

	return out
}

func parseLevel(s string) (slog.Level, error) {
	level, err := loglevel.Parse(s)
	if err != nil {
		return 0, fmt.Errorf("WAF_COOKIE_LOG: %w", err)
	}

	return level, nil
}
