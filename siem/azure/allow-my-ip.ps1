# Run this whenever your network changes - e.g. at the SIL office on interview day.
# It points the firewall rule at your CURRENT public IP (the old IP loses access).
param([string]$ResourceGroup = "sil-lab-rg", [string]$VmName = "wazuh-siem")
$myIp = (Invoke-RestMethod -Uri "https://api.ipify.org").Trim()
az network nsg rule update -g $ResourceGroup --nsg-name "${VmName}NSG" -n allow-my-ip `
  --source-address-prefixes $myIp -o none
Write-Host "Firewall now allows only $myIp"
