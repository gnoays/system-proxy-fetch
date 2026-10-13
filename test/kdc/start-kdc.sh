#!/usr/bin/env bash
# Starts a throwaway MIT Kerberos realm, TEST.LOCAL, for `test/kerberos.e2e.mjs`: a KDC on
# 127.0.0.1, a user `alice` whose ticket is in a file cache, and a keytab for the proxy's
# principal HTTP/proxy.test. Everything lives in the directory given as $1, and the
# environment the test reads is written to $1/env, to be sourced.
#
# MIT's tools come from KRB5_PREFIX (Homebrew's krb5 on macOS), else from PATH and
# /usr/sbin. The client side is whatever GSSAPI the `kerberos` package links: MIT on Linux,
# the system's own on macOS. Only aes256-cts-hmac-sha1-96 is used, which both take.
# `proxy.test` must resolve to 127.0.0.1. KDC_PORT moves the KDC off 18088.
set -euo pipefail

mkdir -p "$1"
dir=$(cd "$1" && pwd)
port=${KDC_PORT:-18088}

tool() {
  local name=$1 candidate
  for candidate in ${KRB5_PREFIX:+"$KRB5_PREFIX/sbin/$name" "$KRB5_PREFIX/bin/$name"} "$(command -v "$name" || true)" "/usr/sbin/$name"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      echo "$candidate"
      return
    fi
  done
  echo "start-kdc.sh: $name not found" >&2
  exit 1
}

cat > "$dir/krb5.conf" <<EOF
[libdefaults]
  default_realm = TEST.LOCAL
  dns_canonicalize_hostname = false
  rdns = false
  dns_lookup_kdc = false
  dns_lookup_realm = false
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96
  permitted_enctypes = aes256-cts-hmac-sha1-96
[realms]
  TEST.LOCAL = {
    kdc = 127.0.0.1:$port
  }
[domain_realm]
  proxy.test = TEST.LOCAL
EOF

cat > "$dir/kdc.conf" <<EOF
[kdcdefaults]
  kdc_ports = $port
  kdc_tcp_ports = $port
[realms]
  TEST.LOCAL = {
    database_name = $dir/principal
    key_stash_file = $dir/stash
    acl_file = $dir/kadm5.acl
    master_key_type = aes256-cts-hmac-sha1-96
    supported_enctypes = aes256-cts-hmac-sha1-96:normal
  }
EOF
: > "$dir/kadm5.acl"

export KRB5_CONFIG="$dir/krb5.conf" KRB5_KDC_PROFILE="$dir/kdc.conf" KRB5CCNAME="FILE:$dir/cc"
"$(tool kdb5_util)" create -s -r TEST.LOCAL -P master-password > /dev/null
kadmin=$(tool kadmin.local)
# kadmin.local warns on stderr that no password policy applies; its exit status still
# stops the script.
"$kadmin" -q 'addprinc -pw user-password alice' > /dev/null 2>&1
"$kadmin" -q 'addprinc -randkey HTTP/proxy.test' > /dev/null 2>&1
"$kadmin" -q "ktadd -k $dir/http.keytab HTTP/proxy.test" > /dev/null 2>&1
# Without -n the KDC detaches once it listens.
"$(tool krb5kdc)" -P "$dir/kdc.pid"
echo user-password | "$(tool kinit)" alice > /dev/null

cat > "$dir/env" <<EOF
KRB5_CONFIG=$dir/krb5.conf
KRB5CCNAME=FILE:$dir/cc
KRB5_KTNAME=FILE:$dir/http.keytab
SYSTEM_PROXY_FETCH_KDC=1
EOF
echo "TEST.LOCAL is up on 127.0.0.1:$port; source $dir/env"
