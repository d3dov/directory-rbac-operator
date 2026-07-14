package ldapclient

import "testing"

func TestMembershipFilterUsesMatchingRuleOnlyForActiveDirectory(t *testing.T) {
	const groupDN = "cn=data-team,ou=groups,dc=corp,dc=local"
	wantPlain := "(memberOf=" + groupDN + ")"
	wantMatchingRule := "(memberOf:" + MatchingRuleInChainOID + ":=" + groupDN + ")"

	tests := []struct {
		name          string
		directoryType DirectoryType
		want          string
	}{
		{"zero value defaults like OpenLDAP", "", wantPlain},
		{"OpenLDAP", DirectoryTypeOpenLDAP, wantPlain},
		{"ActiveDirectory", DirectoryTypeActiveDirectory, wantMatchingRule},
		// FreeIPA gets the plain filter too, not by falling through a
		// catch-all default but as an explicit case: 389-ds's MemberOf
		// plugin computes memberOf recursively server-side, so a plain
		// equality filter already sees flattened nested-group membership
		// there. Applying the AD matching rule against it would either be
		// rejected (FreeIPA doesn't index that matching rule) or, at best,
		// be redundant with what the server already did.
		{"FreeIPA", DirectoryTypeFreeIPA, wantPlain},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(Config{DirectoryType: tt.directoryType})
			if got := c.membershipFilter(groupDN); got != tt.want {
				t.Fatalf("membershipFilter() = %q, want %q", got, tt.want)
			}
		})
	}
}
