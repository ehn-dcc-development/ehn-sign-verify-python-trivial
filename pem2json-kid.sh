#!/bin/sh
set -e

if [ $# != 1 ]; then
	echo "Syntax: $0 <pem-file>"
	exit 1
fi

KID=$(openssl x509 -fingerprint -sha256 -in "$1" -noout | sed -e 's/.*=//' -e 's/://g' | cut -c 1-16)
RAW=$(echo `openssl x509 -in "$1" -noout -pubkey | openssl pkey  -pubin -text | grep '^ '` | sed -e 's/[: ]*//g')

if ! echo $RAW | grep -q ^04; then
	echo $1 is not a raw/uncompressed curve. sorry.
	exit 1
fi

RAW=$(echo $RAW | sed -e 's/^04//')
X=$(echo $RAW | cut -c 1-64)
Y=$(echo $RAW | cut -c 65-128)

(
printf "{"
printf "  \"kid\": \"$KID\","
echo  "  \"coord\": [ \"$X\", \"$Y\" ]"
echo "}"
) | json_pp
