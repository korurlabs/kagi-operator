{{/*
Expand the name of the chart.
*/}}
{{- define "kagi-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name. Truncated to 63 chars because some
Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "kagi-operator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version as used by the chart label.
*/}}
{{- define "kagi-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kagi-operator.labels" -}}
helm.sh/chart: {{ include "kagi-operator.chart" . }}
{{ include "kagi-operator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kagi-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kagi-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the ServiceAccount to use.
*/}}
{{- define "kagi-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kagi-operator.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The image reference for the manager/operator container.
*/}}
{{- define "kagi-operator.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Name of the default Kagi PAT Secret the operator reads via
--default-token-secret, or an empty string when neither auth.existingSecret
nor auth.token is set (in which case --default-token-secret/-namespace are
omitted entirely and every KagiSecret/KagiCertificate must carry its own
spec.tokenSecret).
*/}}
{{- define "kagi-operator.tokenSecretName" -}}
{{- if .Values.auth.existingSecret -}}
{{ .Values.auth.existingSecret }}
{{- else if .Values.auth.token -}}
{{ include "kagi-operator.fullname" . }}-token
{{- end -}}
{{- end }}

{{/*
Namespace of the default token Secret. Defaults to the release namespace.
*/}}
{{- define "kagi-operator.tokenSecretNamespace" -}}
{{- .Values.auth.namespace | default .Release.Namespace -}}
{{- end }}

{{/*
Name of the webhook Service.

Truncated AFTER the suffix is appended, not before. A Service name is a DNS
LABEL and is capped at 63 characters; fullname is already trimmed to 63, so
appending "-webhook" to a long release name produced a 71-character name that
the API server rejects outright -- and, worse, the same string is what the
operator bakes into the certificate SAN and what the API server dials, so a
silently different truncation on either side would yield a SAN that can never
match. One truncation, in one place, keeps them identical.

No working installation changes: a release name long enough to reach the cap
could not install at all before this.
*/}}
{{- define "kagi-operator.webhookServiceName" -}}
{{- printf "%s-webhook" (include "kagi-operator.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Name of the Secret holding the webhook's TLS serving certificate.

Default: an operator-owned Secret. This chart does NOT create it -- the operator
creates, populates and rotates it itself (--webhook-cert-secret, see
internal/certs). The chart only names it, so the Deployment can mount it
(optional: true -- it does not exist yet on a fresh install) and pass the same
name to the operator.

When injection.existingCertSecret is set, that Secret wins: the user owns it,
the operator only reads it, and the Deployment mounts it with optional: false.
Routing both cases through one helper is what keeps the Deployment's volume
wiring and the --webhook-cert-secret flag from ever disagreeing about which
Secret is in play.
*/}}
{{- define "kagi-operator.webhookCertSecretName" -}}
{{- if .Values.injection.existingCertSecret -}}
{{ .Values.injection.existingCertSecret }}
{{- else -}}
{{ printf "%s-webhook-server-cert" (include "kagi-operator.fullname" .) }}
{{- end -}}
{{- end }}
