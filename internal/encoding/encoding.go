package encoding

import (
	"html"
	"net/url"
)

// HTMLEscape escapes untrusted text for HTML contexts.
func HTMLEscape(s string) string {
	return html.EscapeString(s)
}

// AttributeEscape escapes for HTML attribute values.
func AttributeEscape(s string) string {
	return html.EscapeString(s)
}

// URLEncode safely encodes a string for use in query parameters.
func URLEncode(s string) string {
	return url.QueryEscape(s)
}
