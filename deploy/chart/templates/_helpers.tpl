{{- define "participation.image" -}}
{{- if not (regexMatch "^sha256:[a-f0-9]{64}$" .Values.image.digest) -}}
{{- fail "image.digest must be a real sha256 digest, never a tag" -}}
{{- end -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- end -}}
{{- define "participation.helmLabels" -}}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "participation.adapterKind" -}}
{{- $kind := dig "adapter" "kind" "" .Values.policy -}}
{{- if not $kind -}}
{{- fail "policy must contain the complete validated public policy" -}}
{{- end -}}
{{- $kind -}}
{{- end -}}
