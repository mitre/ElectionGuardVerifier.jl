#! /bin/sh

exec julia --threads=auto --eval '
if length(ARGS) == 0
  path = "."
else
  path = ARGS[1]
end

using ElectionGuardVerifier

er = load(path);

println(check(er, "vr.json"))' "$@"
