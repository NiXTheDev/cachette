#!/usr/bin/env bash
# Generate the Forgejo release body for a version.
#
# If release-notes/<version>.md exists it is the canonical body and is emitted
# verbatim. Otherwise the body is composed from that version's CHANGELOG.md
# section plus the shared framing in scripts/release-body.template.md.
set -euo pipefail

version="${1:?usage: release-body.sh <version>}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
changelog="${CHANGELOG_PATH:-$root/CHANGELOG.md}"
template="${RELEASE_TEMPLATE:-$root/scripts/release-body.template.md}"
override="$root/release-notes/${version}.md"

if [[ -f "$override" ]]; then
  cat "$override"
  exit 0
fi

section="$(awk -v v="$version" '
  $0 ~ "^## \\[" v "\\]" { found = 1; next }
  found && /^## \[/ { exit }
  found { print }
' "$changelog" | tr -d '\r')"

if [[ -z "$section" ]]; then
  echo "release-body.sh: no CHANGELOG section for $version" >&2
  exit 1
fi

tagline="$(printf '%s\n' "$section" | sed -n 's/^\*\([^*]*\)\*$/\1/p' | head -n1)"
release_name="$(printf '%s\n' "$section" | sed -n 's/^\*\*Release name: \(.*\)\*\*$/\1/p' | head -n1)"

lead="$(printf '%s\n' "$section" | awk '
  /^### / { exit }
  /^\*[^*]*\*$/ { next }
  /^\*\*Release name:/ { next }
  /^$/ { next }
  { lead = lead (lead == "" ? "" : "\n") $0 }
  END { print lead }
')"

notes="$(printf '%s\n' "$section" | awk '
  /^### Upgrading/ { stop = 1 }
  stop { next }
  /^### / { in_notes = 1; next }
  in_notes { notes = notes (notes == "" ? "" : "\n") $0 }
  END { print notes }
')"

upgrading="$(printf '%s\n' "$section" | awk '
  /^### Upgrading/ { in_up = 1; next }
  /^### / { in_up = 0 }
  in_up { up = up (up == "" ? "" : "\n") $0 }
  END { print up }
')"

awk -v name="$release_name" -v tag="$tagline" -v lead="$lead" -v notes="$notes" -v up="$upgrading" -v ver="$version" '
function prefix(text, p,   n, arr, i, out) {
  if (text == "") return ""
  n = split(text, arr, "\n")
  for (i = 1; i <= n; i++) out = out (i > 1 ? "\n" : "") p arr[i]
  return out
}
function replace(line, ph, val,   pos) {
  pos = index(line, ph)
  if (pos == 0) return line
  return substr(line, 1, pos - 1) val substr(line, pos + length(ph))
}
{
  if (tag == "" && index($0, "{{TAGLINE}}") > 0) next
  if (name == "" && index($0, "{{RELEASE_NAME}}") > 0) next
  line = $0
  line = replace(line, "{{RELEASE_NAME}}", "# " name)
  line = replace(line, "{{TAGLINE}}", tag)
  line = replace(line, "{{LEAD}}", prefix(lead, "> "))
  line = replace(line, "{{NOTES}}", prefix(notes, "> "))
  line = replace(line, "{{UPGRADING}}", prefix(up, "> "))
  line = replace(line, "{{VERSION}}", ver)
  print line
}
' "$template"
