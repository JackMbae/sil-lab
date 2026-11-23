# Copies the three custom rule files into the Wazuh manager and restarts it.
# Usage:  .\load-rules.ps1 -VmIp <public IP>
param([Parameter(Mandatory = $true)][string]$VmIp)
$ErrorActionPreference = "Stop"
$rules = Get-ChildItem "$PSScriptRoot\..\*.xml"
scp $rules.FullName "azureuser@${VmIp}:/tmp/"

$remote = @'
set -e
C=single-node-wazuh.manager-1
for f in ai_proxy_rules.xml shadow_ai_rules.xml ransomware_rules.xml; do
  docker cp /tmp/$f $C:/var/ossec/etc/rules/$f
  docker exec $C chown wazuh:wazuh /var/ossec/etc/rules/$f
done
echo "--- built-in Sysmon parents the custom rules rely on (expect 61603 and 61650):"
docker exec $C grep -nE 'rule id="(61603|61650)"' /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml || echo "!! parent IDs differ in this version - tell Claude"
docker exec $C /var/ossec/bin/wazuh-control restart >/dev/null
sleep 5
docker exec $C /var/ossec/bin/wazuh-control status | grep -E "analysisd|remoted"
echo "--- logtest: AI proxy rule (expect 100402, level 8)"
echo '{"service":"ai-proxy","event":"blocked","user":"reception-03","findings":["PHI:KE_PHONE"]}' | docker exec -i $C /var/ossec/bin/wazuh-logtest 2>&1 | grep -E "id:|level:|description:" | tail -3
'@
ssh "azureuser@$VmIp" ($remote -replace "`r", "")
