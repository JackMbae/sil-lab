# Re-applies the admin password inside Wazuh (use if change-password.ps1's last step failed).
# Usage:  .\apply-password.ps1 -VmIp <public IP>
param([Parameter(Mandatory = $true)][string]$VmIp)
scp "$PSScriptRoot\apply-password.sh" "azureuser@${VmIp}:/tmp/apply-password.sh"
ssh "azureuser@$VmIp" "tr -d '\r' < /tmp/apply-password.sh > /tmp/ap.sh && bash /tmp/ap.sh; rm -f /tmp/ap.sh /tmp/apply-password.sh"
