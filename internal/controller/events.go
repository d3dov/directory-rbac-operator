package controller

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
)

// eventAction is used for every Event this package records. The
// events.k8s.io/v1 API distinguishes a short "action" verb from the more
// specific "reason" string; since every event here is emitted from a
// reconcile, one constant action covers all of them.
const eventAction = "Sync"

// recordWarning and recordSuccessf wrap events.EventRecorder.Eventf, which
// replaced the deprecated record.EventRecorder.Event/Eventf pair used by
// mgr.GetEventRecorderFor. Every warning this package emits is a plain
// message and every success is a formatted one, so - unlike the old
// Event/Eventf split, which varied by argument count - these split by event
// type, which is what actually varies at the call sites.
func recordWarning(recorder events.EventRecorder, obj runtime.Object, reason, message string) {
	// message is passed through a literal "%s" rather than as the format
	// string itself, since callers (error messages, LDAP diagnostics) don't
	// control its content and it may contain unescaped '%' characters.
	recorder.Eventf(obj, nil, corev1.EventTypeWarning, reason, eventAction, "%s", message)
}

func recordSuccessf(recorder events.EventRecorder, obj runtime.Object, reason, format string, args ...any) {
	recorder.Eventf(obj, nil, corev1.EventTypeNormal, reason, eventAction, format, args...)
}
