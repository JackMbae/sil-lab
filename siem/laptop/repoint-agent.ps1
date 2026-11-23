# Points the Wazuh agent on this laptop at the NEW manager and re-enrols it.
# Run in PowerShell AS ADMINISTRATOR:  .\repoint-agent.ps1 -VmIp <public IP>
param([Parameter(Mandatory = $true)][string]$VmIp, [string]$AgentName = "jack-laptop")
$ErrorActionPreference = "Stop"
$dir  = "C:\Program Files (x86)\ossec-agent"
$conf = "$dir\ossec.conf"

Stop-Service WazuhSvc
Copy-Item $conf "$conf.bak-$(Get-Date -Format yyyyMMdd-HHmm)"
(Get-Content $conf -Raw) -replace '<address>[^<]*</address>', "<address>$VmIp</address>" |
  Set-Content -Encoding ascii $conf

# Old key belongs to the deleted manager - enrol again
& "$dir\agent-auth.exe" -m $VmIp -A $AgentName
Start-Service WazuhSvc

Write-Host "`nAgent version (manager must be the same or newer):" (Get-Content "$dir\VERSION*" -ErrorAction SilentlyContinue)
Write-Host "Is the AI proxy log still collected?"
Select-String -Path $conf -Pattern "ai-proxy" | ForEach-Object { "  " + $_.Line.Trim() }
