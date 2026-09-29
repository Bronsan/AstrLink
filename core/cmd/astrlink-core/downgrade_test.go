package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// previousCoreEnv names the Core binary of the release before local data
// protection. The CI downgrade job builds it; without it the smoke skips.
const previousCoreEnv = "ASTRLINK_PREVIOUS_CORE"

const (
	// previousSchemaVersion is the last migration of that release, where
	// unseal leaves the database.
	previousSchemaVersion = 41
	downgradeControlToken = "downgrade-smoke-control-token-0123456789"
	downgradeAPISecret    = "SMOKE-downgrade-api-secret"
)

// smokeUpstream is a provider that answers every chat request and records
// the credential it was sent.
type smokeUpstream struct {
	*httptest.Server
	mu            sync.Mutex
	authorization []string
}

func newSmokeUpstream(t *testing.T) *smokeUpstream {
	t.Helper()
	upstream := &smokeUpstream{}
	upstream.Server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstream.mu.Lock()
		upstream.authorization = append(upstream.authorization, request.Header.Get("Authorization"))
		upstream.mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"id":"chatcmpl-smoke","object":"chat.completion","created":1,"model":"model-smoke",`+
			`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],`+
			`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	t.Cleanup(upstream.Close)
	return upstream
}

// takeAuthorization returns the credentials received since the last call.
func (upstream *smokeUpstream) takeAuthorization() []string {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	received := upstream.authorization
	upstream.authorization = nil
	return received
}

type smokeCore struct {
	t                  *testing.T
	command            *exec.Cmd
	exited             chan error
	logPath            string
	control, inference string
	stopped            bool
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func startSmokeCore(t *testing.T, binary, directory string) *smokeCore {
	t.Helper()
	core := &smokeCore{
		t: t, exited: make(chan error, 1), logPath: filepath.Join(t.TempDir(), "core.log"),
		control: freeLoopbackAddress(t), inference: freeLoopbackAddress(t),
	}
	logFile, err := os.Create(core.logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	core.command = exec.Command(binary, "--data-dir", directory, "--control-token-stdin", "--outbound-proxy", "direct",
		"--inference-listen", core.inference, "--control-listen", core.control)
	core.command.Stdin = strings.NewReader(downgradeControlToken + "\n")
	core.command.Stdout, core.command.Stderr = logFile, logFile
	if err := core.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { core.exited <- core.command.Wait() }()
	// A failed check must not leave Core holding the data directory.
	t.Cleanup(func() {
		if !core.stopped {
			_ = core.command.Process.Kill()
			<-core.exited
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case err := <-core.exited:
			core.stopped = true
			t.Fatalf("%s exited before it was ready: %v\n%s", filepath.Base(binary), err, core.log())
		default:
		}
		if status, _ := core.call(http.MethodGet, core.controlURL("/control/v1/services"), downgradeControlToken, nil); status == http.StatusOK {
			return core
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not become ready\n%s", filepath.Base(binary), core.log())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (core *smokeCore) log() string {
	contents, _ := os.ReadFile(core.logPath)
	return string(contents)
}

func (core *smokeCore) controlURL(path string) string   { return "http://" + core.control + path }
func (core *smokeCore) inferenceURL(path string) string { return "http://" + core.inference + path }

func (core *smokeCore) call(method, url, token string, body any) (int, []byte) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			core.t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		core.t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return 0, nil
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		core.t.Fatal(err)
	}
	return response.StatusCode, contents
}

func (core *smokeCore) mustControl(method, path string, want int, body, into any) {
	core.t.Helper()
	status, contents := core.call(method, core.controlURL(path), downgradeControlToken, body)
	if status != want {
		core.t.Fatalf("%s %s = HTTP %d, want %d: %s\n%s", method, path, status, want, contents, core.log())
	}
	if into != nil {
		if err := json.Unmarshal(contents, into); err != nil {
			core.t.Fatalf("decode %s %s: %v", method, path, err)
		}
	}
}

// chat sends one request through Core and checks the provider received the
// stored credential.
func (core *smokeCore) chat(upstream *smokeUpstream, accessToken string) {
	core.t.Helper()
	upstream.takeAuthorization()
	status, contents := core.call(http.MethodPost, core.inferenceURL("/v1/chat/completions"), accessToken, map[string]any{
		"model": "model-smoke", "messages": []map[string]string{{"role": "user", "content": "hello"}},
	})
	if status != http.StatusOK {
		core.t.Fatalf("chat = HTTP %d: %s\n%s", status, contents, core.log())
	}
	if received := upstream.takeAuthorization(); len(received) != 1 || received[0] != "Bearer "+downgradeAPISecret {
		core.t.Fatal("the provider did not receive the stored API key")
	}
	if status, _ := core.call(http.MethodPost, core.inferenceURL("/v1/chat/completions"), "wrong-access-token", map[string]any{
		"model": "model-smoke", "messages": []map[string]string{{"role": "user", "content": "hello"}},
	}); status != http.StatusUnauthorized || len(upstream.takeAuthorization()) != 0 {
		core.t.Fatalf("chat with a wrong access token = HTTP %d", status)
	}
}

func (core *smokeCore) stop() {
	core.t.Helper()
	if err := core.command.Process.Signal(syscall.SIGTERM); err != nil {
		core.t.Fatal(err)
	}
	select {
	case err := <-core.exited:
		core.stopped = true
		if err != nil {
			core.t.Fatalf("Core stopped with %v\n%s", err, core.log())
		}
	case <-time.After(30 * time.Second):
		core.t.Fatalf("Core did not stop\n%s", core.log())
	}
}

func assertNoPlaintextSecret(t *testing.T, directory string) {
	t.Helper()
	for _, name := range []string{"astrlink.db", "astrlink.db-wal"} {
		contents, err := os.ReadFile(filepath.Join(directory, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(contents, []byte(downgradeAPISecret)) {
			t.Fatalf("%s holds the API key in plaintext", name)
		}
	}
}

// TestDowngradeSmoke walks one data directory from the previous release
// through this build and unseal back to the previous release (plan §8 item 6).
func TestDowngradeSmoke(t *testing.T) {
	previous := os.Getenv(previousCoreEnv)
	if previous == "" {
		t.Skipf("set %s to the previous release's Core binary", previousCoreEnv)
	}
	if runtime.GOOS == "windows" {
		t.Skip("stopping Core cleanly needs SIGTERM")
	}
	current := filepath.Join(t.TempDir(), "astrlink-core")
	if output, err := exec.Command("go", "build", "-o", current, ".").CombinedOutput(); err != nil {
		t.Fatalf("build Core: %v\n%s", err, output)
	}
	upstream := newSmokeUpstream(t)
	directory := t.TempDir()

	// 1. The previous release creates the data directory.
	core := startSmokeCore(t, previous, directory)
	core.mustControl(http.MethodPost, "/control/v1/services", http.StatusCreated, map[string]any{
		"name": "Smoke API", "kind": "openai", "models": []string{"model-smoke"},
		"http": map[string]any{
			"base_url": upstream.URL + "/v1", "auth": map[string]string{"scheme": "bearer"},
			"credential": map[string]string{"secret": downgradeAPISecret},
		},
		"capabilities": []map[string]any{{"protocol": "openai.chat", "mode": "native", "streaming": true}},
	}, nil)
	var created struct {
		Token       struct{ ID string }
		AccessToken string `json:"access_token"`
	}
	core.mustControl(http.MethodPost, "/control/v1/access-tokens", http.StatusCreated, map[string]string{"name": "Smoke"}, &created)
	if created.Token.ID == "" || created.AccessToken == "" {
		t.Fatal("the previous release returned no access token")
	}
	core.chat(upstream, created.AccessToken)
	core.stop()
	if version := offlineSchemaVersion(t, directory); version != previousSchemaVersion {
		t.Fatalf("%s is at migration %d; unseal targets %d", previousCoreEnv, version, previousSchemaVersion)
	}

	// 2. This build upgrades the directory and seals every secret.
	core = startSmokeCore(t, current, directory)
	core.chat(upstream, created.AccessToken)
	var status struct {
		UnreadableCredentials  int  `json:"unreadable_credentials"`
		UnreadableAccessTokens int  `json:"unreadable_access_tokens"`
		AuditKeyMissing        bool `json:"audit_key_missing"`
	}
	core.mustControl(http.MethodGet, "/control/v1/local-data", http.StatusOK, nil, &status)
	if status.UnreadableCredentials != 0 || status.UnreadableAccessTokens != 0 || status.AuditKeyMissing {
		t.Fatalf("local data after the upgrade = %+v", status)
	}
	core.stop()
	if version := offlineSchemaVersion(t, directory); version <= previousSchemaVersion {
		t.Fatalf("this build left the schema at migration %d", version)
	}
	assertNoPlaintextSecret(t, directory)

	// 3. Unseal rolls the directory back.
	output, err := exec.Command(current, "unseal", "--data-dir", directory, "--yes").CombinedOutput()
	if err != nil || !strings.Contains(string(output), fmt.Sprintf("matches migration %d", previousSchemaVersion)) {
		t.Fatalf("unseal: %v\n%s", err, output)
	}
	if version := offlineSchemaVersion(t, directory); version != previousSchemaVersion {
		t.Fatalf("unseal left the schema at migration %d", version)
	}

	// 4. The previous release opens it with every secret intact.
	core = startSmokeCore(t, previous, directory)
	core.chat(upstream, created.AccessToken)
	var revealed struct {
		AccessToken string `json:"access_token"`
	}
	core.mustControl(http.MethodGet, "/control/v1/access-tokens/"+created.Token.ID+"/secret", http.StatusOK, nil, &revealed)
	if revealed.AccessToken != created.AccessToken {
		t.Fatal("the previous release reveals a different access token")
	}
	core.stop()
}
