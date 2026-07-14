package rbacsync

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
)

// SubjectsEqual reports whether a and b contain the same subjects,
// irrespective of order.
func SubjectsEqual(a, b []rbacv1.Subject) bool {
	if len(a) != len(b) {
		return false
	}

	sortedA := sortedSubjects(a)
	sortedB := sortedSubjects(b)

	for i := range sortedA {
		if sortedA[i] != sortedB[i] {
			return false
		}
	}
	return true
}

func sortedSubjects(subjects []rbacv1.Subject) []rbacv1.Subject {
	out := make([]rbacv1.Subject, len(subjects))
	copy(out, subjects)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// previewCap bounds how many resolved members get echoed into a binding's
// status.membersPreview, to keep the object small for large AD groups - the
// managed RoleBinding/ClusterRoleBinding's own subjects remain the
// authoritative full list.
const previewCap = 20

// PreviewMembers returns a bounded, sorted sample of members plus whether it
// was truncated. Callers are expected to pass an already-sorted members
// slice (ldapclient.Client.GetGroupMembers guarantees this).
func PreviewMembers(members []string) (preview []string, truncated bool) {
	if len(members) <= previewCap {
		return members, false
	}
	return members[:previewCap], true
}

// MembersHash summarizes the full member set so callers can detect drift
// without diffing potentially large lists on every reconcile.
func MembersHash(members []string) string {
	sum := sha256.Sum256([]byte(strings.Join(members, "\n")))
	return hex.EncodeToString(sum[:])
}

// MemberCount converts a member count into the CRD status field's int32,
// clamping rather than wrapping in the (never realistically reachable, but
// structurally possible) case of a group with more than MaxInt32 members.
func MemberCount(members []string) int32 {
	return memberCount(len(members))
}

func memberCount(count int) int32 {
	if count > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(count) //nolint:gosec // guarded by the bounds check above
}
