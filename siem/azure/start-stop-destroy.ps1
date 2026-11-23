# Cost control. A deallocated VM costs only its disk (a few shillings a day); the public IP stays the same.
#   .\start-stop-destroy.ps1 stop      -> after each practice session
#   .\start-stop-destroy.ps1 start     -> before practice / on interview morning (give Wazuh 3-5 minutes)
#   .\start-stop-destroy.ps1 destroy   -> after the interview: deletes everything
param(
  [Parameter(Mandatory = $true)][ValidateSet("start", "stop", "destroy")][string]$Action,
  [string]$ResourceGroup = "sil-lab-rg", [string]$VmName = "wazuh-siem"
)
switch ($Action) {
  "start"   { az vm start -g $ResourceGroup -n $VmName; az vm show -d -g $ResourceGroup -n $VmName --query publicIps -o tsv }
  "stop"    { az vm deallocate -g $ResourceGroup -n $VmName }
  "destroy" { az group delete -n $ResourceGroup --yes --no-wait; Write-Host "Deleting $ResourceGroup in the background." }
}
