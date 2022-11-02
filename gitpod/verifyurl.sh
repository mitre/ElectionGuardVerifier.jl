#! /bin/sh

wget -O record.zip $1
unzip record.zip -d record
exec julia --threads=auto --eval '
using ElectionGuardVerifier

er = load("./record");

println(check(er, "vr.json"))' "$@"
