package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// WARNING: This server is intentionally vulnerable for testing.
func main() {
	users := []struct {
		ID       int
		Username string
		Password string
	}{
		{1, "admin", "secret"},
		{2, "user", "password"},
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Vuln-Go: intentionally insecure demo. Endpoints: /xss?input=, /sqli?user=, /path?file=, /ssrf?url=, /cmd?host=, /upload (POST file)")
	})

	// Reflected XSS
	http.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		in := r.URL.Query().Get("input")
		fmt.Fprintf(w, "Hello %s", in) // no escaping
	})

	// SQLi (string concat)
	http.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		for _, u := range users {
			if user == "" || u.Username == user {
				fmt.Fprintf(w, "%d,%s,%s\n", u.ID, u.Username, u.Password)
			}
		}
	})

	// Path traversal
	http.HandleFunc("/path", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		data, err := os.ReadFile(file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	// SSRF
	http.HandleFunc("/ssrf", func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		resp, err := http.Get(url)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	})

	// Command injection
	http.HandleFunc("/cmd", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		out, err := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(out)
	})

	// Upload (no validation)
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fmt.Fprintln(w, `<form method="POST" enctype="multipart/form-data"><input type="file" name="file"/><input type="submit"/></form>`)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()
		dst := filepath.Join(os.TempDir(), header.Filename)
		out, err := os.Create(dst)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer out.Close()
		io.Copy(out, file)
		fmt.Fprintf(w, "saved to %s\n", dst)
	})

	log.Println("Vuln-Go running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
