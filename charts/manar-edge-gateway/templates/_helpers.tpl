{{- define "gw.selectorLabels" -}}
app.kubernetes.io/name: manar-edge-gateway
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "gw.labels" -}}
{{ include "gw.selectorLabels" . }}
app.kubernetes.io/part-of: manar
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}
