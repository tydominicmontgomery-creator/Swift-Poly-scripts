#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
STATE=/var/lib/chomper-hardening; RULES="$STATE/initial-firewall-rules.tsv"
[[ -s "$RULES" ]] || { echo "No recorded initial rules; run 02 first."; exit 1; }
firewall-cmd --state >/dev/null || exit 1
LOG=/var/log/chomper-hardening; install -d -m 0700 "$LOG"
exec > >(tee -a "$LOG/lockdown-$(date +%Y%m%d-%H%M%S).log") 2>&1
declare -A CIDR=()
while IFS=$'\t' read -r zone fam port svc; do
 [[ -n "$zone" ]] || continue
 if [[ ! ${CIDR[$svc]+set} ]]; then
  case $svc in
   DATABASE) prompt="Verified source CIDR(s) for DB scoring client AND external app server(s), comma-separated; blank leaves broad";;
   SSH) prompt="Verified SSH administrator source CIDR; blank leaves broad";;
   HTTP) prompt="Verified HTTP client source CIDR; blank leaves broad";;
  esac
  read -r -p "$prompt: " value; CIDR[$svc]=$value
 fi
 value=${CIDR[$svc]}
 [[ -n "$value" ]] || { echo "[WARN] $svc remains broad."; continue; }
 IFS=, read -ra nets <<< "$value"
 matched=0
 for net in "${nets[@]}"; do
  python3 - "$net" "$fam" <<'PY'
import ipaddress,sys
try:
 n=ipaddress.ip_network(sys.argv[1].strip(),strict=False)
except ValueError:
 raise SystemExit(2)
raise SystemExit(0 if n.version == (4 if sys.argv[2]=="ipv4" else 6) else 1)
PY
  rc=$?
  [[ $rc == 2 ]] && { echo "Invalid CIDR: $net"; exit 2; }
  [[ $rc == 0 ]] && matched=1
 done
 if [[ $matched == 0 ]]; then echo "[INFO] No $fam CIDR supplied for $svc; its $fam broad rule will remain."; fi
 echo "[PLAN] $svc TCP/$port -> $value"
done < "$RULES"
echo "DB allowlist must include scoring clients and any remote HTTP/application host connecting to Chomper."
read -r -p "Type LOCKDOWN to add narrow rules and remove only this toolkit's broad rules: " ok
[[ "$ok" == LOCKDOWN ]] || exit 0
tmp="$RULES.tmp"; : > "$tmp"; chmod 0600 "$tmp"
while IFS=$'\t' read -r zone fam port svc; do
 [[ -n "$zone" ]] || continue; value=${CIDR[$svc]:-}
 if [[ -z "$value" ]]; then printf '%s\t%s\t%s\t%s\n' "$zone" "$fam" "$port" "$svc" >> "$tmp"; continue; fi
 broad=0.0.0.0/0; [[ $fam == ipv6 ]] && broad=::/0
 old="rule family=\"$fam\" source address=\"$broad\" port port=\"$port\" protocol=\"tcp\" accept"
 IFS=, read -ra nets <<< "$value"
 matched=0
 for net in "${nets[@]}"; do
  net=$(echo "$net" | xargs)
  ver=$(python3 - "$net" <<'PY'
import ipaddress,sys
print(ipaddress.ip_network(sys.argv[1],strict=False).version)
PY
)
  [[ ($fam == ipv4 && $ver == 4) || ($fam == ipv6 && $ver == 6) ]] || continue
  matched=1
  new="rule family=\"$fam\" source address=\"$net\" port port=\"$port\" protocol=\"tcp\" accept"
  firewall-cmd --zone="$zone" --query-rich-rule="$new" >/dev/null || firewall-cmd --zone="$zone" --add-rich-rule="$new"
  firewall-cmd --permanent --zone="$zone" --query-rich-rule="$new" >/dev/null || firewall-cmd --permanent --zone="$zone" --add-rich-rule="$new"
 done
 if [[ $matched == 1 ]]; then
  firewall-cmd --zone="$zone" --remove-rich-rule="$old" || true
  firewall-cmd --permanent --zone="$zone" --remove-rich-rule="$old" || true
  echo "[LOCKED] $svc TCP/$port $fam -> matching CIDR(s)"
 else
  printf '%s\t%s\t%s\t%s\n' "$zone" "$fam" "$port" "$svc" >> "$tmp"
  echo "[WARN] $svc TCP/$port $fam remains broad; no matching-family CIDR supplied."
 fi
done < "$RULES"
mv "$tmp" "$RULES"
echo "[DONE] Only exact broad rules recorded by this toolkit were removed."
echo "Inspect existing service/port allows: firewall-cmd --zone=ZONE --list-all and --permanent --list-all."
echo "Test new SSH session, scored DB transaction, dependent HTTP app, and denied unauthorized source."
