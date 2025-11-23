package auth

import "strings"

// RolePolicy maps resources/actions to allowed roles.
type RolePolicy struct {
	// Key format: resource:action (e.g., "account:read").
	Permissions map[string][]string
}

// AuthorizeRBAC returns true when any of the subjectRoles is allowed for the resource/action.
func AuthorizeRBAC(subjectRoles []string, resource, action string, policy RolePolicy) bool {
	if len(policy.Permissions) == 0 {
		return false
	}
	key := resource + ":" + action
	allowed := policy.Permissions[key]
	if len(allowed) == 0 {
		return false
	}
	roleSet := make(map[string]struct{}, len(subjectRoles))
	for _, r := range subjectRoles {
		roleSet[strings.ToLower(r)] = struct{}{}
	}
	for _, ar := range allowed {
		if _, ok := roleSet[strings.ToLower(ar)]; ok {
			return true
		}
	}
	return false
}

// ABACPolicy evaluates attributes (e.g., owner, department, clearance).
type ABACPolicy struct {
	// Require that subjectAttr[key] == value
	Equals map[string]string
	// Allow subjectAttr[key] to contain any of the values (comma-separated or slice-like)
	Contains map[string][]string
}

// AuthorizeABAC enforces attribute-based checks using simple string matching.
func AuthorizeABAC(subjectAttr map[string]string, policy ABACPolicy) bool {
	for k, v := range policy.Equals {
		if subjectAttr[strings.ToLower(k)] != v {
			return false
		}
	}
	for k, vals := range policy.Contains {
		got := subjectAttr[strings.ToLower(k)]
		for _, expect := range vals {
			if strings.Contains(strings.ToLower(got), strings.ToLower(expect)) {
				goto next
			}
		}
		return false
	next:
	}
	return true
}
