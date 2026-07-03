#!/usr/bin/env bash
# End-to-end smoke test: real kind cluster, real docker-compose OpenLDAP, real
# Helm install. Mirrors the README quickstart exactly, plus the two behaviors
# that matter most and that envtest can't prove (no garbage collector, no real
# network partition): fail-safe on an LDAP outage, and owner-ref garbage
# collection on delete.
set -euo pipefail

NAMESPACE=data-platform
OPERATOR_NAMESPACE=ldaprbac-system

wait_for() {
	local desc="$1" cmd="$2" timeout="${3:-90}" waited=0
	until eval "$cmd" >/dev/null 2>&1; do
		waited=$((waited + 3))
		if [ "$waited" -ge "$timeout" ]; then
			echo "TIMEOUT waiting for: $desc"
			eval "$cmd" || true
			return 1
		fi
		sleep 3
	done
	echo "OK: $desc"
}

echo "== creating namespaces and secret =="
kubectl create namespace "$OPERATOR_NAMESPACE"
kubectl create namespace "$NAMESPACE"
kubectl create secret generic ldap-bind-credentials -n "$OPERATOR_NAMESPACE" \
	--from-literal=password=admin

echo "== installing chart =="
helm install ldaprbac charts/directory-rbac-operator -n "$OPERATOR_NAMESPACE" \
	--set image.repository=directory-rbac-operator --set image.tag=e2e

wait_for "operator deployment available" \
	"[ \"\$(kubectl -n $OPERATOR_NAMESPACE get deploy/ldaprbac -o jsonpath='{.status.availableReplicas}')\" = '1' ]"

LDAP_IP=$(docker inspect directory-rbac-operator-openldap \
	--format '{{ (index .NetworkSettings.Networks "directory-rbac-operator_default").IPAddress }}')
echo "LDAP_IP=$LDAP_IP"

echo "== applying LDAPProvider and RBACGroupBinding =="
cat <<EOF | kubectl apply -f -
apiVersion: ldaprbac.io/v1alpha1
kind: LDAPProvider
metadata:
  name: corp-ad
spec:
  url: "ldap://${LDAP_IP}:389"
  bindDN: "cn=admin,dc=corp,dc=local"
  bindPasswordSecretRef:
    name: ldap-bind-credentials
    key: password
  insecureSkipTLS: true
  userSearchBase: "ou=people,dc=corp,dc=local"
  groupSearchBase: "ou=groups,dc=corp,dc=local"
  syncInterval: 15s
  usernameAttribute: uid
---
apiVersion: ldaprbac.io/v1alpha1
kind: RBACGroupBinding
metadata:
  name: data-team-edit
  namespace: ${NAMESPACE}
spec:
  providerRef: corp-ad
  groupDN: "cn=data-team,ou=groups,dc=corp,dc=local"
  roleRef:
    kind: ClusterRole
    name: edit
EOF

wait_for "LDAPProvider Ready" \
	"kubectl get ldapprovider corp-ad -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"

wait_for "RBACGroupBinding Ready with 2 members" \
	"[ \"\$(kubectl -n $NAMESPACE get rbacgroupbinding data-team-edit -o jsonpath='{.status.memberCount}')\" = '2' ]"

echo "== verifying RoleBinding subjects =="
subjects=$(kubectl -n "$NAMESPACE" get rolebinding data-team-edit -o jsonpath='{.subjects[*].name}')
echo "subjects: $subjects"
echo "$subjects" | grep -q alice
echo "$subjects" | grep -q bob

echo "== mutating LDAP group membership =="
docker compose exec -T openldap ldapmodify -x -H ldap://localhost \
	-D "cn=admin,dc=corp,dc=local" -w admin <<EOF
dn: cn=data-team,ou=groups,dc=corp,dc=local
changetype: modify
add: member
member: uid=carol,ou=people,dc=corp,dc=local
EOF

wait_for "RBACGroupBinding picks up carol" \
	"[ \"\$(kubectl -n $NAMESPACE get rbacgroupbinding data-team-edit -o jsonpath='{.status.memberCount}')\" = '3' ]"

echo "== stopping OpenLDAP: fail-safe check =="
docker compose stop openldap

wait_for "RBACGroupBinding goes Degraded" \
	"kubectl -n $NAMESPACE get rbacgroupbinding data-team-edit -o jsonpath='{.status.conditions[?(@.type==\"Degraded\")].status}' | grep -q True"

subjects_after_outage=$(kubectl -n "$NAMESPACE" get rolebinding data-team-edit -o jsonpath='{.subjects[*].name}')
echo "$subjects_after_outage" | grep -q alice
echo "$subjects_after_outage" | grep -q bob
echo "$subjects_after_outage" | grep -q carol
echo "OK: RoleBinding subjects survived the outage unchanged"

echo "== restarting OpenLDAP: recovery check =="
docker compose start openldap

wait_for "RBACGroupBinding recovers to Ready" \
	"kubectl -n $NAMESPACE get rbacgroupbinding data-team-edit -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"

echo "== deleting RBACGroupBinding: owner-ref garbage collection check =="
kubectl -n "$NAMESPACE" delete rbacgroupbinding data-team-edit

wait_for "RoleBinding garbage collected" \
	"! kubectl -n $NAMESPACE get rolebinding data-team-edit"

echo "== all checks passed =="
