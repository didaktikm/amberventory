{{/*
Expand the name of the chart.
*/}}
{{- define "amberventory.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "amberventory.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "amberventory.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "amberventory.selectorLabels" -}}
app.kubernetes.io/name: {{ include "amberventory.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "amberventory.labels" -}}
helm.sh/chart: {{ include "amberventory.chart" . }}
{{ include "amberventory.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: amberventory
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Merge resource-specific annotations with .Values.commonAnnotations.
Usage: include "amberventory.mergedAnnotations" (list . .Values.service.annotations) | fromYaml
*/}}
{{- define "amberventory.mergedAnnotations" -}}
{{- $root := index . 0 -}}
{{- $extra := index . 1 | default dict -}}
{{- toYaml (merge (deepCopy $extra) (deepCopy $root.Values.commonAnnotations)) -}}
{{- end }}

{{/*
Name of the ServiceAccount to use
*/}}
{{- define "amberventory.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "amberventory.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Container image reference: digest wins over tag, tag defaults to appVersion
*/}}
{{- define "amberventory.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
Does the chart need to render its own Secret?
*/}}
{{- define "amberventory.createSecret" -}}
{{- if or (and .Values.auth.enabled (not .Values.auth.existingSecret)) (and .Values.nvd.apiKey (not .Values.nvd.existingSecret)) -}}
true
{{- end -}}
{{- end }}

{{/*
Name of the Secret with the credentials
*/}}
{{- define "amberventory.authSecretName" -}}
{{- default (include "amberventory.fullname" .) .Values.auth.existingSecret }}
{{- end }}

{{/*
Name of the Secret with the NVD API key
*/}}
{{- define "amberventory.nvdSecretName" -}}
{{- default (include "amberventory.fullname" .) .Values.nvd.existingSecret }}
{{- end }}

{{/*
Name of the PersistentVolumeClaim
*/}}
{{- define "amberventory.pvcName" -}}
{{- default (include "amberventory.fullname" .) .Values.persistence.existingClaim }}
{{- end }}

{{/*
DNS policy: pods in the host network need ClusterFirstWithHostNet to resolve cluster names
*/}}
{{- define "amberventory.dnsPolicy" -}}
{{- if .Values.dnsPolicy }}
{{- .Values.dnsPolicy }}
{{- else if .Values.hostNetwork }}
{{- print "ClusterFirstWithHostNet" }}
{{- end }}
{{- end }}
