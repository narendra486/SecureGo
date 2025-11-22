# Vulnerable Lab Regression Harness (Plan)

Targets:
- authlab
- secDevLabs / owasp-top10-2017-apps
- govwa
- go-test-bench
- damn-vulnerable-golang
- go-dvwa
- Vulnerability-goapp
- vuln-go

Approach:
1) Deploy each lab locally (docker-compose where available).
2) For each vulnerability class, craft requests that exploit the lab endpoints.
3) Proxy the same requests through an app built on this framework; assert the exploit fails (e.g., CSRF blocked, SQLi blocked due to prepared statements, SSRF blocked by client, XSS prevented by headers/encoding).
4) Automate with `go test` + HTTP clients and golden responses; run under `-race` and include WAF/rate-limit enabled configs.

Status:
- Not implemented here to avoid pulling large lab deps; this README captures the test plan to be scripted per environment.
