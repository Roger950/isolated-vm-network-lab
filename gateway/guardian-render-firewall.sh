#!/bin/sh
# Extract only endpoint fields inside the gateway; never print authentication data.
set -eu
umask 077
server=$(jsonfilter -i /etc/mihomo/config.yaml -e '@.proxies[0].server' 2>/dev/null || true)
port=$(jsonfilter -i /etc/mihomo/config.yaml -e '@.proxies[0].port' 2>/dev/null || true)
endpoint=''
if printf '%s\n' "$server" | awk -F. 'NR!=1 || NF!=4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i+0>255) exit 1} END {if(NR!=1) exit 1}' &&
   test -n "$port" && test "$port" -ge 1 2>/dev/null && test "$port" -le 65535 2>/dev/null; then
    case "$port" in *[!0-9]*) ;; *) endpoint="$server . $port" ;; esac
fi
# An invalid/missing endpoint produces an empty allow-list, not a bypass.
if test -n "$endpoint"; then
    sed "s/__ENDPOINT__/$endpoint/" /usr/share/guardian-gateway/guardian-gateway.nft.in
else
    sed '/__ENDPOINT__/d' /usr/share/guardian-gateway/guardian-gateway.nft.in
fi
