#!/bin/bash
# Replaces Wazuh's default dashboard/indexer "admin" password (Docker single-node).
# Run via change-password.ps1 - it asks for the password on screen and never echoes it.
set -e
cd ~/wazuh-docker/single-node

echo "Password rules: 8-64 characters, with upper case, lower case, a number and one of . * + ? -"
read -rsp "New admin password: " P; echo
read -rsp "Type it again:      " P2; echo
[ "$P" = "$P2" ] || { echo "Passwords differ - nothing changed."; exit 1; }
if [ ${#P} -lt 8 ] || ! [[ $P =~ [A-Z] && $P =~ [a-z] && $P =~ [0-9] && $P =~ [.*+?-] ]] || [[ $P =~ [^A-Za-z0-9.*+?-] ]]; then
  echo "Password doesn't meet the rules above - nothing changed."; exit 1
fi

IMG=$(docker inspect --format '{{.Config.Image}}' single-node-wazuh.indexer-1)
echo "Hashing with $IMG ..."
HASH=$(docker run --rm "$IMG" bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$P" 2>/dev/null | tail -n 1)
[[ $HASH == \$2* ]] || { echo "Could not generate the hash - nothing changed."; exit 1; }

cp config/wazuh_indexer/internal_users.yml config/wazuh_indexer/internal_users.yml.bak
cp docker-compose.yml docker-compose.yml.bak
HASH="$HASH" NEWPW="$P" python3 - <<'PY'
import os, re
h, p = os.environ["HASH"], os.environ["NEWPW"]
f = "config/wazuh_indexer/internal_users.yml"
t = open(f).read()
t, n = re.subn(r'(^admin:\s*\n\s*hash:\s*)"[^"]*"', lambda m: m.group(1) + '"' + h + '"', t, count=1, flags=re.M)
assert n == 1, "admin hash not found"
open(f, "w").write(t)
f = "docker-compose.yml"
t = open(f).read()
t, n = re.subn(r'INDEXER_PASSWORD=\S+', 'INDEXER_PASSWORD=' + p, t)
assert n >= 1, "INDEXER_PASSWORD not found"
open(f, "w").write(t)
print("Config updated.")
PY
unset P P2

echo "Restarting Wazuh (about 2 minutes)..."
docker compose down
docker compose up -d
# Wait until the indexer answers HTTP (401 = up, security active), then push the new hash.
for i in $(seq 1 36); do
  code=$(docker exec single-node-wazuh.indexer-1 curl -sk -o /dev/null -w '%{http_code}' https://localhost:9200 2>/dev/null)
  [ "$code" = "401" ] || [ "$code" = "200" ] && break
  sleep 5
done
sleep 10

echo "Applying the new password to the indexer..."
docker exec single-node-wazuh.indexer-1 bash -c '
  D=/usr/share/wazuh-indexer; export JAVA_HOME=$D/jdk
  bash $D/plugins/opensearch-security/tools/securityadmin.sh -cd $D/config/opensearch-security/ -nhnv \
    -cacert $D/config/certs/root-ca.pem -cert $D/config/certs/admin.pem -key $D/config/certs/admin-key.pem -p 9200 -icl' 2>&1 \
  | grep -E "Done with success|ERR|Exception|FAIL" | head -n 10
echo "If you don't see 'Done with success' above, run .\\apply-password.ps1"

rm -f config/wazuh_indexer/internal_users.yml.bak docker-compose.yml.bak
echo "Done. Log in to the dashboard as 'admin' with your new password."
