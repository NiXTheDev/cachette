// Plan task 22 fixture: a minimal harness around the *real*
// github.com/tonistiigi/go-actions-cache client (the library buildx uses for
// `type=gha`), vendored under ../gac-reference at a pinned commit so the test
// exercises the upstream client, not a re-implementation.
//
// Usage (ACTIONS_CACHE_URL / ACTIONS_RUNTIME_TOKEN set by the caller):
//
//	go run . miss    <key>
//	go run . save    <key> <payload-path>
//	go run . restore <key> <payload-path>
//
// The client is constructed with the upstream env-aware `TryEnv`, so the
// fixture drives whichever protocol the environment selects:
//
//	v1 (default):     ACTIONS_CACHE_URL + ACTIONS_RUNTIME_TOKEN
//	v2 (CacheService): ACTIONS_CACHE_SERVICE_V2=true (or
//	                  ACTIONS_CACHE_API_FORCE_VERSION=v2) + ACTIONS_RESULTS_URL
//
// The last stdout line is a machine-readable marker the Rust test parses:
//
//	__CACHETTE_JSON__{"command":...,"key":...,"result":...}
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	actionscache "github.com/tonistiigi/go-actions-cache"
)

const marker = "__CACHETTE_JSON__"

func emit(payload map[string]any) {
	encoded, _ := json.Marshal(payload)
	fmt.Printf("%s%s\n", marker, encoded)
}

func fail(payload map[string]any, err error) {
	payload["result"] = "error"
	payload["error"] = err.Error()
	emit(payload)
	os.Exit(1)
}

func newClient() (*actionscache.Cache, error) {
	// Construct via the upstream env-aware `TryEnv` so the fixture exercises
	// exactly the v1/v2 selection logic buildx and the actions toolkit use.
	// The upstream client parses+validates the bearer token as a JWT before it
	// ever issues a request, so the fixture needs a real (well-formed) token.
	opt := actionscache.Opt{
		Client:  http.DefaultClient,
		Timeout: 4 * time.Minute,
	}
	// cachette's binary serves TLS-only with a self-signed identity cert; the
	// harness opts into skipping verification against the loopback fixture.
	if os.Getenv("CACHETTE_INSECURE_TLS") == "1" {
		opt.Client = &http.Client{
			Timeout: 4 * time.Minute,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback test fixture
			},
		}
	}
	c, err := actionscache.TryEnv(opt)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("no cache token in the environment (set ACTIONS_RUNTIME_TOKEN)")
	}
	return c, nil
}

func sha256File(path string) (string, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data)), nil
}

func main() {
	if len(os.Args) < 3 {
		fail(map[string]any{"command": ""}, fmt.Errorf("usage: gac <miss|save|restore> <key> [path]"))
	}
	command := os.Args[1]
	key := os.Args[2]

	c, err := newClient()
	if err != nil {
		fail(map[string]any{"command": command, "key": key}, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	switch command {
	case "miss":
		entry, err := c.Load(ctx, key)
		if err != nil {
			fail(map[string]any{"command": command, "key": key}, err)
		}
		result := "miss"
		if entry != nil {
			result = "hit"
		}
		emit(map[string]any{"command": command, "key": key, "result": result})
	case "save":
		if len(os.Args) < 4 {
			fail(map[string]any{"command": command, "key": key}, fmt.Errorf("save requires a payload path"))
		}
		payload := os.Args[3]
		sum, size, err := sha256File(payload)
		if err != nil {
			fail(map[string]any{"command": command, "key": key}, err)
		}
		if err := c.Save(ctx, key, actionscache.NewBlob(mustRead(payload))); err != nil {
			fail(map[string]any{"command": command, "key": key}, err)
		}
		emit(map[string]any{"command": command, "key": key, "result": "saved", "sha256": sum, "size": size})
	case "restore":
		if len(os.Args) < 4 {
			fail(map[string]any{"command": command, "key": key}, fmt.Errorf("restore requires a payload path"))
		}
		payload := os.Args[3]
		entry, err := c.Load(ctx, key)
		if err != nil {
			fail(map[string]any{"command": command, "key": key}, err)
		}
		if entry == nil {
			emit(map[string]any{"command": command, "key": key, "result": "miss"})
			return
		}
		file, err := os.Create(payload)
		if err != nil {
			fail(map[string]any{"command": command, "key": key}, err)
		}
		writeErr := entry.WriteTo(ctx, file)
		closeErr := file.Close()
		if writeErr != nil {
			fail(map[string]any{"command": command, "key": key}, writeErr)
		}
		if closeErr != nil {
			fail(map[string]any{"command": command, "key": key}, closeErr)
		}
		sum, size, err := sha256File(payload)
		if err != nil {
			fail(map[string]any{"command": command, "key": key}, err)
		}
		emit(map[string]any{"command": command, "key": key, "result": "restored", "sha256": sum, "size": size})
	default:
		fail(map[string]any{"command": command, "key": key}, fmt.Errorf("unknown command: %s", command))
	}
}

func mustRead(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fail(map[string]any{"command": "save"}, err)
	}
	return data
}
