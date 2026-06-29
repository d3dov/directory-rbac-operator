{{- define "directory-rbac-operator.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "directory-rbac-operator.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "directory-rbac-operator.labels" -}}
app.kubernetes.io/name: {{ include "directory-rbac-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "directory-rbac-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "directory-rbac-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "directory-rbac-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "directory-rbac-operator.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "directory-rbac-operator.secretNamespace" -}}
{{- default .Release.Namespace .Values.secretNamespace -}}
{{- end -}}
