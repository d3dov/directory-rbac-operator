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
