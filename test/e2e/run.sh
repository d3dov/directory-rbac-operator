#!/usr/bin/env bash
# End-to-end smoke test: real kind cluster, real docker-compose OpenLDAP, real
# Helm install. Mirrors the README quickstart exactly, plus the two behaviors
# that matter most and that envtest can't prove (no garbage collector, no real
# network partition): fail-safe on an LDAP outage, and owner-ref garbage
# collection on delete.
set -euo pipefail

NAMESPACE=data-platform
OPERATOR_NAMESPACE=ldaprbac-system
E2E_BACKEND="${E2E_BACKEND:-openldap}"

case "$E2E_BACKEND" in
	openldap)
		LDAP_CONTAINER=directory-rbac-operator-openldap
		LDAP_BIND_DN="cn=admin,dc=corp,dc=local"
		LDAP_PASSWORD=admin
		LDAP_USER_SEARCH_BASE="ou=people,dc=corp,dc=local"
		LDAP_GROUP_SEARCH_BASE="ou=groups,dc=corp,dc=local"
		LDAP_USERNAME_ATTRIBUTE=uid
		LDAP_GROUP_DN="cn=data-team,ou=groups,dc=corp,dc=local"
		LDAP_DIRECTORY_TYPE=OpenLDAP
		;;
	samba-ad)
		LDAP_CONTAINER=ldaprbac-samba-ad
		LDAP_BIND_DN="CN=Administrator,CN=Users,DC=corp,DC=local"
		LDAP_PASSWORD=Passw0rd!123
		LDAP_USER_SEARCH_BASE="CN=Users,DC=corp,DC=local"
		LDAP_GROUP_SEARCH_BASE="DC=corp,DC=local"
		LDAP_USERNAME_ATTRIBUTE=sAMAccountName
		LDAP_GROUP_DN="CN=data-team,CN=Users,DC=corp,DC=local"
		LDAP_DIRECTORY_TYPE=ActiveDirectory
		;;
	freeipa)
		LDAP_CONTAINER=ldaprbac-freeipa
		LDAP_BIND_DN="uid=admin,cn=users,cn=accounts,dc=corp,dc=local"
		LDAP_PASSWORD=Passw0rd!123
		LDAP_USER_SEARCH_BASE="cn=users,cn=accounts,dc=corp,dc=local"
		LDAP_GROUP_SEARCH_BASE="cn=groups,cn=accounts,dc=corp,dc=local"
		LDAP_USERNAME_ATTRIBUTE=uid
		LDAP_GROUP_DN="cn=data-team,cn=groups,cn=accounts,dc=corp,dc=local"
		LDAP_DIRECTORY_TYPE=FreeIPA
		E2E_WAIT_TIMEOUT=180
		;;
	*)
		echo "unsupported E2E_BACKEND: $E2E_BACKEND" >&2
		exit 2
		;;
esac

wait_for() {
	local desc="$1" cmd="$2" timeout="${3:-${E2E_WAIT_TIMEOUT:-90}}" waited=0
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
	--from-literal=password="$LDAP_PASSWORD"

echo "== installing chart =="
helm install ldaprbac charts/directory-rbac-operator -n "$OPERATOR_NAMESPACE" \
	--set image.repository=directory-rbac-operator --set image.tag=e2e

wait_for "operator deployment available" \
	"[ \"\$(kubectl -n $OPERATOR_NAMESPACE get deploy/ldaprbac -o jsonpath='{.status.availableReplicas}')\" = '1' ]"

LDAP_IP=$(docker inspect "$LDAP_CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "LDAP_IP=$LDAP_IP"

echo "== applying LDAPProvider and RBACGroupBinding =="
cat <<EOF | kubectl apply -f -
apiVersion: ldaprbac.io/v1alpha1
kind: LDAPProvider
metadata:
  name: corp-ad
spec:
  url: "ldap://${LDAP_IP}:389"
  bindDN: "${LDAP_BIND_DN}"
  bindPasswordSecretRef:
    name: ldap-bind-credentials
    key: password
  insecureSkipTLS: true
  userSearchBase: "${LDAP_USER_SEARCH_BASE}"
  groupSearchBase: "${LDAP_GROUP_SEARCH_BASE}"
  syncInterval: 15s
  usernameAttribute: ${LDAP_USERNAME_ATTRIBUTE}
  directoryType: ${LDAP_DIRECTORY_TYPE}
---
apiVersion: ldaprbac.io/v1alpha1
kind: RBACGroupBinding
metadata:
  name: data-team-edit
  namespace: ${NAMESPACE}
spec:
  providerRef: corp-ad
  groupDN: "${LDAP_GROUP_DN}"
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
if [ "$E2E_BACKEND" = openldap ]; then
	docker compose exec -T openldap ldapmodify -x -H ldap://localhost \
		-D "$LDAP_BIND_DN" -w "$LDAP_PASSWORD" <<EOF
dn: cn=data-team,ou=groups,dc=corp,dc=local
changetype: modify
add: member
member: uid=carol,ou=people,dc=corp,dc=local
EOF
	elif [ "$E2E_BACKEND" = samba-ad ]; then
		docker exec "$LDAP_CONTAINER" samba-tool group addmembers data-team carol
	else
		docker exec "$LDAP_CONTAINER" ipa group-add-member data-team --users=carol
	fi

wait_for "RBACGroupBinding picks up carol" \
	"[ \"\$(kubectl -n $NAMESPACE get rbacgroupbinding data-team-edit -o jsonpath='{.status.memberCount}')\" = '3' ]"

echo "== stopping LDAP backend: fail-safe check =="
if [ "$E2E_BACKEND" = openldap ]; then
	docker compose stop openldap
else
	docker stop "$LDAP_CONTAINER"
fi

wait_for "RBACGroupBinding goes Degraded" \
	"kubectl -n $NAMESPACE get rbacgroupbinding data-team-edit -o jsonpath='{.status.conditions[?(@.type==\"Degraded\")].status}' | grep -q True"

subjects_after_outage=$(kubectl -n "$NAMESPACE" get rolebinding data-team-edit -o jsonpath='{.subjects[*].name}')
echo "$subjects_after_outage" | grep -q alice
echo "$subjects_after_outage" | grep -q bob
echo "$subjects_after_outage" | grep -q carol
echo "OK: RoleBinding subjects survived the outage unchanged"

echo "== restarting LDAP backend: recovery check =="
if [ "$E2E_BACKEND" = openldap ]; then
	docker compose start openldap
else
	docker start "$LDAP_CONTAINER"
fi

wait_for "RBACGroupBinding recovers to Ready" \
	"kubectl -n $NAMESPACE get rbacgroupbinding data-team-edit -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"

echo "== deleting RBACGroupBinding: owner-ref garbage collection check =="
kubectl -n "$NAMESPACE" delete rbacgroupbinding data-team-edit

wait_for "RoleBinding garbage collected" \
	"! kubectl -n $NAMESPACE get rolebinding data-team-edit"

echo "== all checks passed =="
