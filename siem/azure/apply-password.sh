#!/bin/bash
# Pushes internal_users.yml (with the new admin hash) into the running Wazuh indexer.
# Safe to re-run. Waits until the indexer's security layer is answering first.
C=single-node-wazuh.indexer-1
echo "Waiting for the indexer..."
for i in $(seq 1 36); do
  code=$(docker exec $C curl -sk -o /dev/null -w '%{http_code}' https://localhost:9200 2>/dev/null)
  [ "$code" = "401" ] || [ "$code" = "200" ] && break
  sleep 5
done
echo "Indexer answered HTTP $code. Applying security config..."
docker exec $C bash -c '
  D=/usr/share/wazuh-indexer; export JAVA_HOME=$D/jdk
  bash $D/plugins/opensearch-security/tools/securityadmin.sh -cd $D/config/opensearch-security/ -nhnv \
    -cacert $D/config/certs/root-ca.pem -cert $D/config/certs/admin.pem -key $D/config/certs/admin-key.pem -p 9200 -icl' 2>&1 \
  | grep -E "Done with success|ERR|Exception|Will update|FAIL" | head -n 15
