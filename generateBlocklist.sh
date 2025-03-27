#!/bin/bash

TARGET_IP="0.0.0.0"

URLS=(
  "https://adaway.org/hosts.txt"
  "https://v.firebog.net/hosts/AdguardDNS.txt"
  "https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt"
  "https://small.oisd.nl/domainswild"
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
  "http://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&mimetype=plaintext"
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
)

TMP_FILE=$(mktemp)

process_url() {
  curl -s "$1" | grep -vE '^\s*#' | while read -r line; do
    for word in $line; do
      # Only accept valid domains, including wildcard subdomains
      if [[ "$word" =~ ^\*?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then
        echo "$word"
      fi
    done
  done >> "$TMP_FILE"
}

for url in "${URLS[@]}"; do
  #echo "Processing $url"
  process_url "$url"
done

sort -u "$TMP_FILE" | awk -v ip="$TARGET_IP" '{ print $1, "A", ip }'

rm "$TMP_FILE"
