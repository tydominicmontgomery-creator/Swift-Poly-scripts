#!/usr/bin/env bash
# Temporary broad inbound access for detected listeners. Follow with 03 lockdown.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null || { echo "firewalld must already be running; not enabling blindly."; exit 1; }
STATE=/var/lib/chomper-hardening; LOG=/var/log/chomper-hardening
install -d -m 0700 "$STATE" "$LOG"
zones=($(firewall-cmd --get-active-zones | awk '/^[^ \t]+$/{print $1}'))
((${#zones[@]})) || { echo "No active zone."; exit 1; }
if ((${#zones[@]}==1)); then zone=${zones[0]}; else
 printf 'Active zones: %s\n' "${zones[*]}"; read -r -p "Zone for Chomper primary interface: " zone
 printf '%s\n' "${zones[@]}" | grep -Fxq "$zone" || exit 1
fi
echo "Host addresses:"; ip -brief address
echo "Team 15 expected team-facing IP: 172.16.15.53 (verify; this is not the scoring-client source)."
declare -A found=()
while read -r addr line; do
 port=${addr##*:}; [[ "$port" =~ ^[0-9]+$ ]] || continue
 [[ "$line" =~ sshd ]] && found["$port:SSH"]=1
 [[ "$line" =~ (mysqld|mariadbd|postgres|mongod|redis-server|cockroach|influxd|couchdb|sqlservr) ]] && found["$port:DATABASE"]=1
 [[ "$line" =~ (httpd|apache2|nginx|caddy|lighttpd) ]] && found["$port:HTTP"]=1
done < <(ss -H -ltnp 2>/dev/null | awk '{print $4, $0}')
if ! printf '%s\n' "${!found[@]}" | grep -q ':DATABASE$'; then
 echo "[WARN] No recognizable database listener detected."
 read -r -p "Enter verified DB TCP port, or Enter to skip: " p
 if [[ -n "$p" ]]; then [[ "$p" =~ ^[0-9]+$ ]] && ((10#$p>0 && 10#$p<=65535)) || exit 2; found["$p:DATABASE"]=1; fi
fi
echo "Active zone: $zone"
echo "Detected listeners (temporary broad allow from all sources):"
for k in "${!found[@]}"; do echo "  ${k#*:} TCP/${k%%:*}"; done
echo "This includes HTTP only if an HTTP server is listening on Chomper."
echo "This broad policy is temporary; run 03 as soon as source CIDRs are confirmed."
read -r -p "Type OPEN to add rules: " ok; [[ "$ok" == OPEN ]] || exit 0
RULES="$STATE/initial-firewall-rules.tsv"; touch "$RULES"; chmod 0600 "$RULES"
for k in "${!found[@]}"; do
 p=${k%%:*}; svc=${k#*:}
 for fam in ipv4 ipv6; do src=0.0.0.0/0; [[ $fam == ipv6 ]] && src=::/0
  rule="rule family=\"$fam\" source address=\"$src\" port port=\"$p\" protocol=\"tcp\" accept"
  if ! firewall-cmd --zone="$zone" --query-rich-rule="$rule" >/dev/null; then
   firewall-cmd --zone="$zone" --add-rich-rule="$rule"
   printf '%s\t%s\t%s\t%s\n' "$zone" "$fam" "$p" "$svc" >> "$RULES"
  fi
  firewall-cmd --permanent --zone="$zone" --query-rich-rule="$rule" >/dev/null || firewall-cmd --permanent --zone="$zone" --add-rich-rule="$rule"
 done
 echo "[OPENED] $svc TCP/$p (IPv4 and IPv6)"
done
echo "[DONE] Initial reachability rules installed. Temporary broad exposure; follow with 03."
