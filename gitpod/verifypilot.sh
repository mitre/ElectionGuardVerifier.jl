#! /bin/sh

echo "Cannot verify: pilot election has not occurred yet!"
echo "Try a different option instead, such as 'verify example'"
exit 1


wget https://cdn.enhancedresults.com/results/elections/b2a78ab6-7b74-4135-916a-ad678f2c6983/election-record.zip

mkir pilot
unzip election-record.zip -d pilot

exec julia --threads=auto --eval '
using ElectionGuardVerifier

er = load("./pilot");

println(check(er, "vr.json"))'
