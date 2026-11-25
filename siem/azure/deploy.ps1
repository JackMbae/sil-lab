# Rebuilds the Wazuh SIEM VM on Azure (Section 1B Q1/Q3).
# Run from PowerShell in this folder after `az login`.
# Example:  .\deploy.ps1 -WazuhVersion 4.12.0
# Use the SAME version as your laptop agent (see README step 1) - an agent newer than the manager won't connect.
param(
  [Parameter(Mandatory = $true)][string]$WazuhVersion,
  [string]$Location = "southafricanorth",
  [string]$Size = "Standard_B2ms",          # 2 vCPU / 8 GB. Use Standard_B4ms if the dashboard is slow.
  [string]$ResourceGroup = "sil-lab-rg",
  [string]$VmName = "wazuh-siem"
)
$ErrorActionPreference = "Stop"

$myIp = (Invoke-RestMethod -Uri "https://api.ipify.org").Trim()
Write-Host "Your public IP: $myIp (only this IP will be allowed in)"

(Get-Content "$PSScriptRoot\cloud-init.yaml" -Raw).Replace("__WAZUH_VERSION__", $WazuhVersion) |
  Set-Content -Encoding ascii "$env:TEMP\wazuh-cloud-init.yaml"

az group create -n $ResourceGroup -l southafricanorth -o none   # group location is only metadata; the VM goes to -Location

az vm create -g $ResourceGroup -n $VmName `
  --image Canonical:ubuntu-24_04-lts:server:latest `
  --size $Size --os-disk-size-gb 64 `
  --admin-username azureuser --generate-ssh-keys `
  --public-ip-sku Standard --nsg-rule NONE `
  -l $Location --custom-data "$env:TEMP\wazuh-cloud-init.yaml" -o none
if ($LASTEXITCODE -ne 0) { Write-Host "VM creation failed - see the error above. Try another -Size or -Location." -ForegroundColor Red; exit 1 }

# SSH, dashboard, agent events, agent enrolment - from YOUR IP only. Nothing open to the internet.
az network nsg rule create -g $ResourceGroup --nsg-name "${VmName}NSG" -n allow-my-ip `
  --priority 100 --access Allow --protocol Tcp --direction Inbound `
  --source-address-prefixes $myIp --destination-port-ranges 22 443 1514 1515 -o none
if ($LASTEXITCODE -ne 0) { exit 1 }

$vmIp = az vm show -d -g $ResourceGroup -n $VmName --query publicIps -o tsv
Write-Host ""
Write-Host "VM created: $vmIp"
Write-Host "Wazuh takes ~10 minutes to install. Check with:"
Write-Host "  ssh azureuser@$vmIp `"ls ~/WAZUH_READY && docker ps`""
Write-Host "Dashboard: https://$vmIp  (certificate warning is expected - self-signed)"
