package rbacsync

import (
	"math"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	ldaprbacv1alpha1 "github.com/d3dov/directory-rbac-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSubjects(t *testing.T) {
	got := Subjects([]string{"alice", "bob"})
	want := []rbacv1.Subject{
		{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"},
		{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "bob"},
	}
	if len(got) != len(want) {
		t.Fatalf("Subjects() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Subjects()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSubjectsEqualIgnoresOrder(t *testing.T) {
	a := Subjects([]string{"alice", "bob"})
	b := Subjects([]string{"bob", "alice"})

	if !SubjectsEqual(a, b) {
		t.Fatalf("expected subjects to be equal regardless of order: %v vs %v", a, b)
	}
}

func TestSubjectsEqualDetectsDifference(t *testing.T) {
	a := Subjects([]string{"alice", "bob"})
	b := Subjects([]string{"alice", "carol"})

	if SubjectsEqual(a, b) {
		t.Fatalf("expected subjects to differ: %v vs %v", a, b)
	}
}

func TestSubjectsEqualDetectsLengthDifference(t *testing.T) {
	if SubjectsEqual(Subjects([]string{"alice"}), Subjects([]string{"alice", "bob"})) {
		t.Fatal("expected subjects of different lengths to differ")
	}
}

func TestSubjectsEqualSortsAllSubjectFields(t *testing.T) {
	a := []rbacv1.Subject{
		{Kind: rbacv1.GroupKind, Name: "admins"},
		{Kind: rbacv1.UserKind, Namespace: "b", Name: "alice"},
		{Kind: rbacv1.UserKind, Namespace: "a", Name: "bob"},
	}
	b := []rbacv1.Subject{
		{Kind: rbacv1.UserKind, Namespace: "a", Name: "bob"},
		{Kind: rbacv1.UserKind, Namespace: "b", Name: "alice"},
		{Kind: rbacv1.GroupKind, Name: "admins"},
	}
	if !SubjectsEqual(a, b) {
		t.Fatalf("expected subjects to compare equal: %v vs %v", a, b)
	}
}

func TestPreviewMembersTruncates(t *testing.T) {
	members := make([]string, 25)
	for i := range members {
		members[i] = string(rune('a' + i))
	}

	preview, truncated := PreviewMembers(members)
	if !truncated {
		t.Fatalf("expected truncated=true for %d members", len(members))
	}
	if len(preview) != previewCap {
		t.Fatalf("expected preview length %d, got %d", previewCap, len(preview))
	}
}

func TestPreviewMembersNoTruncation(t *testing.T) {
	members := []string{"alice", "bob"}

	preview, truncated := PreviewMembers(members)
	if truncated {
		t.Fatalf("did not expect truncation for %d members", len(members))
	}
	if len(preview) != len(members) {
		t.Fatalf("expected preview to contain all members")
	}
}

func TestMembersHashStableAndOrderSensitive(t *testing.T) {
	h1 := MembersHash([]string{"alice", "bob"})
	h2 := MembersHash([]string{"alice", "bob"})
	if h1 != h2 {
		t.Fatalf("expected identical input to hash identically")
	}

	h3 := MembersHash([]string{"bob", "alice"})
	if h1 == h3 {
		t.Fatalf("expected differently ordered input to hash differently (callers must sort first)")
	}
}

func TestBuildRoleBinding(t *testing.T) {
	binding := &ldaprbacv1alpha1.RBACGroupBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "data-team-edit", Namespace: "data-platform"},
		Spec: ldaprbacv1alpha1.RBACGroupBindingSpec{
			RoleRef: ldaprbacv1alpha1.RoleRef{Kind: "Role", Name: "edit"},
		},
	}

	rb := BuildRoleBinding(binding, []string{"alice"})

	if rb.Name != binding.Name || rb.Namespace != binding.Namespace {
		t.Fatalf("expected RoleBinding named/namespaced after the CR, got %s/%s", rb.Namespace, rb.Name)
	}
	if rb.RoleRef.Kind != "Role" || rb.RoleRef.Name != "edit" {
		t.Fatalf("unexpected RoleRef: %+v", rb.RoleRef)
	}
	if len(rb.Subjects) != 1 || rb.Subjects[0].Name != "alice" {
		t.Fatalf("unexpected Subjects: %+v", rb.Subjects)
	}
}

func TestBuildClusterRoleBinding(t *testing.T) {
	binding := &ldaprbacv1alpha1.ClusterRBACGroupBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "platform-admins"},
		Spec:       ldaprbacv1alpha1.ClusterRBACGroupBindingSpec{ClusterRoleRef: "cluster-admin"},
	}

	got := BuildClusterRoleBinding(binding, []string{"alice"})
	if got.Name != binding.Name || got.RoleRef.Kind != "ClusterRole" || got.RoleRef.Name != "cluster-admin" {
		t.Fatalf("unexpected ClusterRoleBinding: %+v", got)
	}
	if len(got.Subjects) != 1 || got.Subjects[0].Name != "alice" {
		t.Fatalf("unexpected subjects: %+v", got.Subjects)
	}
}

func TestMemberCount(t *testing.T) {
	if got := MemberCount([]string{"alice", "bob"}); got != 2 {
		t.Fatalf("MemberCount() = %d, want 2", got)
	}
	if got := memberCount(math.MaxInt32 + 1); got != math.MaxInt32 {
		t.Fatalf("memberCount() = %d, want MaxInt32", got)
	}
}
