package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/exemt/placitum-cookie/internal/policy"
	"github.com/exemt/placitum-shared/netinfo"
)

type geoWriter interface {
	Write(ctx context.Context, write, addr string) ([]string, error)
}

type listWriter interface {
	AddMany(name string, values []string, ttl time.Duration, reason string) error
	Remove(name, value, reason string) error
}

func writeLists(ctx context.Context, geo geoWriter, lists listWriter, log *slog.Logger,
	rid, addr string, writes []policy.Write, cookies map[string]seen) error {

	var failed error

	for _, w := range writes {
		values, err := subjects(ctx, geo, log, rid, addr, w, cookies)
		if err != nil {
			if failed == nil {
				failed = err
			}

			continue
		}

		if len(values) == 0 {
			continue
		}

		if w.Op == policy.OpRemove {
			for _, v := range values {
				if err := lists.Remove(w.List, v, w.Reason); err != nil {
					log.Warn("list remove failed", "rid", rid, "set", w.List,
						"error", err.Error())
				}
			}

			continue
		}

		if err := lists.AddMany(w.List, values, w.TTL, w.Reason); err != nil {
			log.Warn("list publish failed", "rid", rid, "set", w.List, "error", err.Error())
		}
	}

	return failed
}

func subjects(ctx context.Context, geo geoWriter, log *slog.Logger, rid, addr string,
	w policy.Write, cookies map[string]seen) ([]string, error) {

	// write: value puts the value of the cookie, write: cookie the whole string the client carries.
	if w.Subject == policy.WriteValue || w.Subject == policy.WriteCookie {
		value := cookies[w.Cookie].Value

		if w.Subject == policy.WriteValue {
			value = cookies[w.Cookie].Tag
		}

		if value == "" {
			log.Debug("list write skipped: no cookie value",
				"rid", rid, "set", w.List, "cookie", w.Cookie)

			return nil, nil
		}

		return []string{value}, nil
	}

	if addr == "" {
		return nil, nil
	}

	if !netinfo.Networked(w.Subject) {
		return []string{addr}, nil
	}

	got, err := geo.Write(ctx, w.Subject, addr)
	if err != nil {
		return nil, err
	}

	if len(got) == 0 {
		log.Warn("list write skipped: coder knows nothing about the address",
			"rid", rid, "set", w.List, "write", w.Subject, "addr", addr)

		return nil, nil
	}

	return got, nil
}
