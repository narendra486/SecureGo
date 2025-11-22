# encoding
Purpose: safe escaping for output contexts.
When to use: before placing untrusted data in HTML, attributes, or URLs.
Mitigates: XSS and broken links caused by unescaped data.

- `HTMLEscape` for HTML bodies.
- `AttributeEscape` for HTML attribute values.
- `URLEncode` for query parameters/URLs.

Pair with `html/template` for templating; avoid raw string concatenation into HTML.
