#!/usr/bin/env bash
# Generate a self-signed TLS certificate for xcrackd (HTTPS), or a full mutual-TLS
# kit (a local CA + a server certificate + a client certificate) for the
# --tls-client-ca path. Uses OpenSSL (1.1.1+ / 3.x).
#
# Usage:
#   scripts/gen-selfsigned-cert.sh [-o DIR] [-h HOSTS] [-d DAYS] [-c CN] [-m]
#
#   -o DIR     output directory                 (default: ./tls)
#   -h HOSTS   comma-separated DNS/IP SANs       (default: localhost,127.0.0.1,::1)
#   -d DAYS    validity in days                  (default: 825)
#   -c CN      certificate common name           (default: the first host)
#   -m         also emit a CA + client cert for mutual TLS
#   --help     show this help
#
# Default (server only) writes:
#   DIR/server.crt  DIR/server.key
# With -m it additionally writes:
#   DIR/ca.crt  DIR/ca.key  DIR/client.crt  DIR/client.key
#
# Then:
#   xcrackd --tls-cert DIR/server.crt --tls-key DIR/server.key
#   # the xcrack client trusts the self-signed server cert via --tls-ca:
#   xcrack --server https://HOST:8080 --tls-ca DIR/server.crt ...
#
#   # mutual TLS (-m):
#   xcrackd --tls-cert DIR/server.crt --tls-key DIR/server.key --tls-client-ca DIR/ca.crt
#   xcrack  --server https://HOST:8080 --tls-ca DIR/ca.crt \
#           --tls-cert DIR/client.crt --tls-key DIR/client.key ...
#
# Self-signed certificates are for testing and closed/internal deployments. For a
# public endpoint use scripts/gen-letsencrypt-cert.sh instead.
set -euo pipefail

outdir="./tls"
hosts="localhost,127.0.0.1,::1"
days=825
cn=""
mtls=0

while [ $# -gt 0 ]; do
  case "$1" in
    -o) outdir="$2"; shift 2 ;;
    -h) hosts="$2"; shift 2 ;;
    -d) days="$2"; shift 2 ;;
    -c) cn="$2"; shift 2 ;;
    -m) mtls=1; shift ;;
    --help|-\?) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v openssl >/dev/null 2>&1 || { echo "openssl not found in PATH" >&2; exit 1; }
mkdir -p "$outdir"

# Build the subjectAltName string: IP:… for addresses, DNS:… otherwise.
san=""
IFS=',' read -ra items <<< "$hosts"
for h in "${items[@]}"; do
  h="$(echo "$h" | tr -d '[:space:]')"
  [ -z "$h" ] && continue
  if [[ "$h" =~ ^[0-9.]+$ || "$h" == *:* ]]; then
    san="${san}${san:+,}IP:${h}"
  else
    san="${san}${san:+,}DNS:${h}"
  fi
done
[ -z "$cn" ] && cn="$(echo "${items[0]}" | tr -d '[:space:]')"

newkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 600 "$1"; }

if [ "$mtls" -eq 0 ]; then
  # Single self-signed server certificate.
  newkey "$outdir/server.key"
  openssl req -x509 -new -key "$outdir/server.key" -out "$outdir/server.crt" -days "$days" \
    -subj "/CN=${cn}" \
    -addext "subjectAltName=${san}" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"
  echo "wrote $outdir/server.crt and $outdir/server.key (CN=${cn}, SAN=${san}, ${days}d)"
  exit 0
fi

# Mutual-TLS kit: a local CA that signs a server cert and a client cert.
newkey "$outdir/ca.key"
openssl req -x509 -new -key "$outdir/ca.key" -out "$outdir/ca.crt" -days "$days" \
  -subj "/CN=Xcrack Test CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

sign() { # $1=name $2=CN $3=eku $4=san(optional)
  local name="$1" cnn="$2" eku="$3" s="${4:-}"
  newkey "$outdir/${name}.key"
  openssl req -new -key "$outdir/${name}.key" -out "$outdir/${name}.csr" -subj "/CN=${cnn}"
  local ext; ext="$(mktemp)"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=${eku}"
    [ -n "$s" ] && echo "subjectAltName=${s}"
  } > "$ext"
  openssl x509 -req -in "$outdir/${name}.csr" -CA "$outdir/ca.crt" -CAkey "$outdir/ca.key" \
    -CAcreateserial -out "$outdir/${name}.crt" -days "$days" -extfile "$ext" 2>/dev/null
  rm -f "$ext" "$outdir/${name}.csr"
}

sign server "$cn" serverAuth "$san"
sign client "xcrack-client" clientAuth
rm -f "$outdir/ca.srl"
echo "wrote $outdir/{ca,server,client}.{crt,key} (server CN=${cn}, SAN=${san}, ${days}d)"
echo "server : xcrackd --tls-cert $outdir/server.crt --tls-key $outdir/server.key --tls-client-ca $outdir/ca.crt"
echo "client : xcrack --tls-ca $outdir/ca.crt --tls-cert $outdir/client.crt --tls-key $outdir/client.key --server https://${cn}:8080"
