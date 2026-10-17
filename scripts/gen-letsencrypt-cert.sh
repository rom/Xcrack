#!/usr/bin/env bash
# Obtain a Let's Encrypt (ACME) TLS certificate for a public xcrackd endpoint,
# using certbot, and lay the result out for xcrackd's --tls-cert/--tls-key.
#
# Prerequisites:
#   * certbot installed (https://certbot.eff.org/).
#   * A public DNS name pointing at this host.
#   * For --mode standalone: inbound TCP/80 reachable and free while issuing
#     (certbot runs its own temporary web server for the HTTP-01 challenge).
#   * For --mode webroot: an already-running web server that serves WEBROOT at
#     http://DOMAIN/.well-known/acme-challenge/.
#   Running certbot and reading /etc/letsencrypt usually needs root.
#
# Usage:
#   scripts/gen-letsencrypt-cert.sh -d DOMAIN -m EMAIL [options]
#
#   -d DOMAIN     certificate domain (repeat -d for SAN entries)      (required)
#   -m EMAIL      contact email for expiry notices                   (required)
#   --mode M      challenge method: standalone (default) | webroot
#   -w WEBROOT    document root for --mode webroot
#   -o DIR        copy the issued cert/key here as server.crt/server.key
#   --staging     use Let's Encrypt staging (untrusted; for dry runs)
#   --help
#
# After issuance the live PEMs are at:
#   /etc/letsencrypt/live/DOMAIN/fullchain.pem   (certificate chain)
#   /etc/letsencrypt/live/DOMAIN/privkey.pem     (private key)
# Point xcrackd straight at those (it reads them at startup):
#   xcrackd --tls-cert /etc/letsencrypt/live/DOMAIN/fullchain.pem \
#           --tls-key  /etc/letsencrypt/live/DOMAIN/privkey.pem --addr :443
#
# Renewal: `certbot renew` rotates the files in place (run it from cron/systemd);
# add `--deploy-hook 'systemctl restart xcrackd'` so xcrackd reloads the new cert
# (it reads the files only at startup). With -o, re-run this script after a
# renewal, or make the deploy hook copy the files.
set -euo pipefail

domains=()
email=""
mode="standalone"
webroot=""
outdir=""
staging=0

while [ $# -gt 0 ]; do
  case "$1" in
    -d) domains+=("$2"); shift 2 ;;
    -m) email="$2"; shift 2 ;;
    --mode) mode="$2"; shift 2 ;;
    -w) webroot="$2"; shift 2 ;;
    -o) outdir="$2"; shift 2 ;;
    --staging) staging=1; shift ;;
    --help|-\?) sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "${#domains[@]}" -gt 0 ] || { echo "at least one -d DOMAIN is required" >&2; exit 2; }
[ -n "$email" ] || { echo "-m EMAIL is required" >&2; exit 2; }
command -v certbot >/dev/null 2>&1 || { echo "certbot not found in PATH (see https://certbot.eff.org/)" >&2; exit 1; }

args=(certonly --non-interactive --agree-tos -m "$email" --keep-until-expiring)
for d in "${domains[@]}"; do args+=(-d "$d"); done
case "$mode" in
  standalone) args+=(--standalone) ;;
  webroot)
    [ -n "$webroot" ] || { echo "--mode webroot requires -w WEBROOT" >&2; exit 2; }
    args+=(--webroot -w "$webroot") ;;
  *) echo "unknown --mode $mode (standalone|webroot)" >&2; exit 2 ;;
esac
[ "$staging" -eq 1 ] && args+=(--staging)

echo "+ certbot ${args[*]}"
certbot "${args[@]}"

primary="${domains[0]}"
live="/etc/letsencrypt/live/${primary}"
echo "certificate issued; live files under ${live}/"

if [ -n "$outdir" ]; then
  mkdir -p "$outdir"
  cp "${live}/fullchain.pem" "$outdir/server.crt"
  cp "${live}/privkey.pem" "$outdir/server.key"
  chmod 600 "$outdir/server.key"
  echo "copied to $outdir/server.crt and $outdir/server.key"
  echo "run: xcrackd --tls-cert $outdir/server.crt --tls-key $outdir/server.key --addr :443"
else
  echo "run: xcrackd --tls-cert ${live}/fullchain.pem --tls-key ${live}/privkey.pem --addr :443"
fi
