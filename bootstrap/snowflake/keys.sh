#!/usr/bin/env bash
# Generate encrypted RSA key pairs for the 6 Snowflake service users, OUTSIDE the repo.
# Prints the ALTER USER statements to paste into Snowsight.
# Works in macOS Terminal, Linux, WSL and Git Bash on Windows.
set -euo pipefail

OUT="${SNOWFLAKE_KEY_DIR:-$HOME/.snowflake-keys}"
mkdir -p "$OUT" && chmod 700 "$OUT"
SQL="$OUT/alter_users.sql"
: > "$SQL"

for env in dev prod; do
  for svc in deployer loader reporter; do
    name="svc_vuln_${svc}_${env}"
    key="$OUT/$name.p8"; pass="$OUT/$name.pass"; pub="$OUT/$name.pub"
    if [[ ! -f "$key" ]]; then
      openssl rand -base64 24 | tr -d '\n' > "$pass"
      openssl genrsa 2048 2>/dev/null \
        | openssl pkcs8 -topk8 -v2 aes-256-cbc -inform PEM -out "$key" -passout "file:$pass"
      openssl rsa -in "$key" -passin "file:$pass" -pubout -out "$pub" 2>/dev/null
      chmod 600 "$key" "$pass" "$pub"
      echo "created $key"
    else
      echo "exists  $key (kept)"
    fi
    user=$(echo "$name" | tr '[:lower:]' '[:upper:]')
    body=$(grep -v -- '-----' "$pub" | tr -d '\n')
    echo "ALTER USER $user SET RSA_PUBLIC_KEY = '$body';" >> "$SQL"
  done
done

echo
echo "Keys + passphrases are in: $OUT   (never copy them into the repo)"
echo "Paste these into Snowsight as SECURITYADMIN:"
echo "-------------------------------------------------------------"
echo "USE ROLE SECURITYADMIN;"
cat "$SQL"
