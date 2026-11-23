# Wazuh SIEM rebuild on Azure (siem/) - for the SIL walkthrough (Fri 27 Nov)

What runs where on interview day:

| Piece | Runs on | Needs |
|---|---|---|
| Wazuh manager + dashboard | Azure VM (this kit) | Internet; firewall set to your current IP |
| Wazuh agent + Sysmon | Your laptop (already installed) | Re-pointed to the new VM |
| AI proxy writing `C:\sil-logs\ai-proxy.log` | Your laptop (one small uvicorn process) | Started before the demo |

Total time: about 45 minutes, most of it waiting for Wazuh to install.

## 1. Check your laptop agent version (2 min)

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\VERSION*"
```

Use that version number (for example `4.12.0`) for the manager below. **The manager must be the same version or newer than the agent**, or the agent will not connect.

## 2. Azure account (5 min)

```powershell
az login
az account show --query "{name:name, state:state}" -o table
```

If you closed the subscription, re-enable it or create a Pay-As-You-Go one. **Cost:** a `Standard_B2ms` VM is roughly US$0.10 an hour while running. Stop it between practice sessions (step 7) and the whole week should cost a few dollars.

## 3. Create the VM (2 min + ~10 min install)

```powershell
cd D:\Projects\sil-lab\siem\azure
.\deploy.ps1 -WazuhVersion 4.12.0      # your version from step 1
```

Wait about 10 minutes, then check:

```powershell
ssh azureuser@<VM_IP> "ls ~/WAZUH_READY && docker ps --format '{{.Names}}'"
```

You should see three containers: `manager`, `indexer` and `dashboard`. Open `https://<VM_IP>` and click through the certificate warning (it is self-signed).

**Before the interview, change the default dashboard password.** The developers may ask about it. Follow Wazuh's guide "Changing the default password of Wazuh users" for the Docker single-node deployment. Never put the password in chat, in git or in screenshots.

## 4. Load the custom rules (2 min)

```powershell
.\load-rules.ps1 -VmIp <VM_IP>
```

Expect three results:
- Both parent rule IDs (61603 and 61650) are listed.
- `wazuh-analysisd is running`.
- The logtest shows **rule 100402, level 8**.

Rule files live in `siem/`:

| File | Rules | Detects |
|---|---|---|
| `ai_proxy_rules.xml` | 100400-100406 | New log source: AI guardrail blocks, PHI, injection, secrets, bulk-PHI correlation (level 12) |
| `shadow_ai_rules.xml` | 100200 | DNS lookups to consumer AI services (Sysmon event 22) |
| `ransomware_rules.xml` | 100300-100301 | Backup and shadow-copy destruction before encryption (Sysmon event 1), level 12 |

The Shadow AI and ransomware rules are **recreations**: the originals lived only on the deleted VM. Compare their descriptions with your screenshots `1B-Q3_01` and `1B-Q3_03`, and tell Claude if anything differs.

## 5. Re-point the laptop agent (3 min)

Open PowerShell **as Administrator**:

```powershell
cd D:\Projects\sil-lab\siem\laptop
.\repoint-agent.ps1 -VmIp <VM_IP>
```

In the dashboard, open **Agents**. `jack-laptop` should show **Active** within a minute.

If the script prints no `ai-proxy` line, the AI proxy log is not being collected. Add this block inside `<ossec_config>` in `C:\Program Files (x86)\ossec-agent\ossec.conf`, then run `Restart-Service WazuhSvc`:

```xml
<localfile>
  <location>C:\sil-logs\ai-proxy.log</location>
  <log_format>json</log_format>
</localfile>
```

## 6. Demo script - test all three detections (5 min)

```powershell
# a) Shadow AI -> rule 100200, level 10
Resolve-DnsName chatgpt.com; Resolve-DnsName claude.ai

# b) Ransomware precursor -> rule 100301, level 12
#    SAFE: "echo" only prints the text. Nothing is deleted.
cmd /c echo vssadmin delete shadows /all /quiet

# c) New log source -> 100402 PHI blocks, then 100406 level 12 bulk PHI
#    (start the AI proxy first, from the sil-lab folder)
python -u -m uvicorn main:app --app-dir ai-proxy --port 8090 >> C:\sil-logs\ai-proxy.log
python scripts\ai_traffic.py      # in a second window
```

To see the results, open the dashboard and go to **Threat Hunting**. Filter on `rule.groups:shadow_ai`, `rule.groups:ransomware` or `rule.groups:ai_guardrail`.

## 7. Cost control and interview day

```powershell
.\start-stop-destroy.ps1 stop     # after each practice
.\start-stop-destroy.ps1 start    # interview morning, at least 15 min before
.\allow-my-ip.ps1                 # AT SIL - your IP will be different there
```

**At SIL, use your phone hotspot rather than office wifi.** You control the hotspot, and running `allow-my-ip.ps1` takes 10 seconds. Re-run it if the hotspot reconnects.

**Fallback if the internet fails:** walk through the screenshots in `D:\screenshots\evidence` and the GitHub Actions history (cache the run pages in your browser beforehand).

**After the interview:** `.\start-stop-destroy.ps1 destroy`.
