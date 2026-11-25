# Changes the Wazuh dashboard "admin" password. You type it on screen; it is never echoed or saved here.
# Usage:  .\change-password.ps1 -VmIp <public IP>
param([Parameter(Mandatory = $true)][string]$VmIp)
scp "$PSScriptRoot\change-password.sh" "azureuser@${VmIp}:/tmp/change-password.sh"
ssh -t "azureuser@$VmIp" "tr -d '\r' < /tmp/change-password.sh > /tmp/cp.sh && bash /tmp/cp.sh; rm -f /tmp/cp.sh /tmp/change-password.sh"
