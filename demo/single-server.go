package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// singleServer spins up one process that serves the UI plus both secure (/api/*)
// and intentionally insecure (/vuln/*) endpoints for quick local testing.
func main() {
	mux := http.NewServeMux()

	// UI (embedded HTML)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, uiHTML)
	})

	// Secure-ish endpoints (return sanitized/blocked responses)
	mux.HandleFunc("/api/xss", func(w http.ResponseWriter, r *http.Request) {
		echo := strings.ReplaceAll(r.FormValue("input"), "<", "&lt;")
		fmt.Fprintf(w, `{"status":"sanitized","echo":"%s"}`, echo)
	})
	mux.HandleFunc("/api/sqli", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"blocked","reason":"parameterized queries only"}`)
	})
	mux.HandleFunc("/api/ssrf", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"blocked","reason":"egress allowlist"}`)
	})
	mux.HandleFunc("/api/path", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"blocked","reason":"path traversal denied"}`)
	})
	mux.HandleFunc("/api/cmd", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"blocked","reason":"no shell exec on untrusted input"}`)
	})
	mux.HandleFunc("/api/idor", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"blocked","reason":"requires subject=resource owner"}`)
	})
	mux.HandleFunc("/api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		// Minimal RS256 demo token using a hardcoded key for local testing only.
		claims := jwt.MapClaims{
			"sub": r.FormValue("user"),
			"iss": "securego",
			"exp": time.Now().Add(10 * time.Minute).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, _ := token.SignedString([]byte("demo-securego-key"))
		fmt.Fprintf(w, `{"access_token":"%s","token_type":"bearer","note":"HS for demo only"}`, signed)
	})
	mux.HandleFunc("/api/oauth/validate", func(w http.ResponseWriter, r *http.Request) {
		raw := r.FormValue("token")
		if raw == "" {
			raw = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if raw == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
			return []byte("demo-securego-key"), nil
		})
		if err != nil || !tok.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"status":"valid"}`)
	})

	// Insecure endpoints (VulnGo-like)
	users := map[string]struct {
		Email   string
		Balance int
	}{
		"admin": {"admin@example.com", 100000},
		"user":  {"user@example.com", 500},
		"alice": {"alice@example.com", 200},
	}
	const weakSecret = "insecure-secret"

	mux.HandleFunc("/vuln/xss", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello %s", r.FormValue("input"))
	})
	mux.HandleFunc("/vuln/sqli", func(w http.ResponseWriter, r *http.Request) {
		u := r.FormValue("user")
		for name := range users {
			if u == "" || name == u {
				fmt.Fprintf(w, "%s,%s\n", name, users[name].Email)
			}
		}
	})
	mux.HandleFunc("/vuln/ssrf", func(w http.ResponseWriter, r *http.Request) {
		target := r.FormValue("url")
		resp, err := http.Get(target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	})
	mux.HandleFunc("/vuln/path", func(w http.ResponseWriter, r *http.Request) {
		path := r.FormValue("file")
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})
	mux.HandleFunc("/vuln/cmd", func(w http.ResponseWriter, r *http.Request) {
		host := r.FormValue("host")
		out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
		w.Write(out)
	})
	mux.HandleFunc("/vuln/idor", func(w http.ResponseWriter, r *http.Request) {
		u := r.FormValue("user")
		if u == "" {
			u = "user"
		}
		info, ok := users[u]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, "user=%s,email=%s,balance=%d\n", u, info.Email, info.Balance)
	})
	mux.HandleFunc("/vuln/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("user")
		claims := jwt.MapClaims{"sub": user, "iss": "vuln", "exp": time.Now().Add(2 * time.Hour).Unix()}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, _ := token.SignedString([]byte(weakSecret))
		fmt.Fprintf(w, `{"access_token":"%s","token_type":"bearer"}`, signed)
	})
	mux.HandleFunc("/vuln/oauth/validate", func(w http.ResponseWriter, r *http.Request) {
		raw := r.FormValue("token")
		if raw == "" {
			raw = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if raw == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}
		// No signature verification: intentional vuln.
		tok, _ := jwt.Parse(raw, nil, jwt.WithoutClaimsValidation())
		fmt.Fprintf(w, "token accepted: %v\n", tok.Claims)
	})

	addr := ":8080"
	log.Printf("Single demo server listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

// uiHTML is a trimmed version of the lab console, targeting /api or /vuln.
const uiHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SecureGO Lab Console</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 1000px; margin: 2rem auto; padding: 0 1rem; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    .card { border: 1px solid #ddd; border-radius: 6px; padding: 1rem; box-shadow: 0 2px 6px rgba(0,0,0,0.05); }
    pre { background: #f6f8fa; color: #24292e; padding: 1rem; border-radius: 6px; border: 1px solid #e0e0e0; min-height: 180px; white-space: pre-wrap; word-break: break-word; }
    select, input, button, textarea { padding: 0.5rem; font-size: 14px; }
    .row { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>SecureGO Lab Console</h1>
      <p>Pick a vulnerability test, target (SecureGo or VulnGo), tweak payloads, and view request/response like a mini Repeater.</p>
    </div>
  </header>
  <div class="card">
    <div class="row">
      <div>
        <label for="bug">Vulnerability</label>
        <select id="bug"></select>
      </div>
      <div>
        <label for="target">Target</label>
        <select id="target">
          <option value="/api">SecureGo</option>
          <option value="/vuln">VulnGo</option>
        </select>
      </div>
    </div>
    <div class="row" style="margin-top:0.5rem;">
      <label for="payload">Payload</label>
      <textarea id="payload" rows="1" style="flex:1; resize: vertical;"></textarea>
      <button id="send">Send</button>
    </div>
    <small id="bug-desc"></small>
  </div>
  <div class="grid" style="margin-top:1rem;">
    <div class="card">
      <h3>Request</h3>
      <pre id="req-view"></pre>
    </div>
    <div class="card">
      <h3>Response</h3>
      <pre id="res-view"></pre>
    </div>
  </div>
  <script>
    const bugs = [
      { id: 'xss', name: 'XSS', method: 'POST', path: '/xss', param: 'input', payload: '<script>alert(1)<\\/script>', desc: 'Reflected input rendered without escaping.' },
      { id: 'sqli', name: 'SQLi', method: 'POST', path: '/sqli', param: 'user', payload: "admin' OR 1=1 --", desc: 'User parameter concatenated into SQL.' },
      { id: 'ssrf', name: 'SSRF', method: 'POST', path: '/ssrf', param: 'url', payload: 'http://127.0.0.1:22', desc: 'Unvalidated outbound fetch.' },
      { id: 'path', name: 'Path Traversal', method: 'POST', path: '/path', param: 'file', payload: '../../../../etc/passwd', desc: 'Reads arbitrary filesystem path.' },
      { id: 'cmd', name: 'Command Injection', method: 'POST', path: '/cmd', param: 'host', payload: '127.0.0.1;ls', desc: 'Shell exec with untrusted input.' },
      { id: 'idor', name: 'IDOR', method: 'POST', path: '/idor', param: 'user', payload: 'alice', desc: 'No authz check on user resource.' },
      { id: 'oauth-token', name: 'OAuth Weak Token', method: 'POST', path: '/oauth/token', param: 'user', payload: 'alice', desc: 'Mints HS256 token with weak secret, no client auth.' },
      { id: 'oauth-validate', name: 'OAuth No Sig Check', method: 'POST', path: '/oauth/validate', param: 'token', payload: 'paste-token-here', desc: 'Accepts token without verifying signature.' }
    ];

    const bugSelect = document.getElementById('bug');
    const targetSelect = document.getElementById('target');
    const payloadInput = document.getElementById('payload');
    const descEl = document.getElementById('bug-desc');
    const reqView = document.getElementById('req-view');
    const resView = document.getElementById('res-view');

    bugs.forEach(b => {
      const opt = document.createElement('option');
      opt.value = b.id;
      opt.textContent = b.name;
      bugSelect.appendChild(opt);
    });
    if (bugs.length) bugSelect.value = bugs[0].id;

    function currentBug() {
      return bugs.find(b => b.id === bugSelect.value) || bugs[0];
    }

    function updateUI() {
      const bug = currentBug();
      payloadInput.value = bug.payload;
      descEl.textContent = bug.desc;
    }

    bugSelect.addEventListener('change', updateUI);
    targetSelect.addEventListener('change', updateUI);
    updateUI();

    document.getElementById('send').addEventListener('click', async () => {
      const bug = currentBug();
      const base = targetSelect.value;
      const method = bug.method;
      let url = base + bug.path;
      let bodyText = '';
      const headers = {};
      if (bug.param) {
        // Raw application/x-www-form-urlencoded body without encoding payload.
        bodyText = bug.param + '=' + payloadInput.value;
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
      }
      const urlObj = new URL(url, window.location.origin);
      const reqLines = [`${method} ${urlObj.pathname}${urlObj.search} HTTP/1.1`, `Host: ${urlObj.host || window.location.host}`];
      Object.entries(headers).forEach(([k, v]) => reqLines.push(`${k}: ${v}`));
      if (bodyText) { reqLines.push(''); reqLines.push(bodyText); }
      reqView.textContent = reqLines.join('\\n');
      try {
        const res = await fetch(url, { method, headers, credentials: 'include', body: bodyText || null });
        const text = await res.text();
        const resLines = [`HTTP/1.1 ${res.status} ${res.statusText}`];
        res.headers.forEach((value, key) => resLines.push(`${key}: ${value}`));
        resLines.push('');
        resLines.push(text);
        resView.textContent = resLines.join('\\n');
      } catch (e) {
        resView.textContent = 'Error: ' + e;
      }
    });
  </script>
</body>
</html>`
