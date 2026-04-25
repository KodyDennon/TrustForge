{{/*
Common helpers for the tf-admission-webhook chart.
*/}}

{{- define "tf-admission-webhook.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tf-admission-webhook.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "tf-admission-webhook.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "tf-admission-webhook.labels" -}}
app.kubernetes.io/name: {{ include "tf-admission-webhook.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: trustforge
{{- end -}}

{{- define "tf-admission-webhook.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tf-admission-webhook.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
