# Identity & Configuration Findings

Consolidated, read-only scan results from local PC filesystem, registry, and Windows Credential Manager. No passwords or secret values were extracted — only account identifiers, server endpoints, and artifact locations.

_Last updated: 2026-09-18_

## Confirmed Email Identities
- `Oscar.Kiss@hotmail.com` (primary)
- `oscar.kiss@outlook.com` (alias)
- `pianist_oscer@outlook.com`
- `michellekiss2026@outlook.com`
- `private-love@private-love.com`

## Findings by Category

| Category | Detail | Source |
|---|---|---|
| Azure | AzureStorageAccounts.csv export - header only, no storage accounts present | OneDrive\Documents\AzureStorageAccounts.csv |
| Azure Activity | QueryResult.csv - Azure Activity Log query result, header only, no events | OneDrive\Documents\QueryResult.csv |
| Credential Manager | MicrosoftAccount SSO_POP_User: michellekiss2026@outlook.com | cmdkey /list |
| Credential Manager | MicrosoftAccount SSO_POP_User: Oscar.Kiss@hotmail.com | cmdkey /list |
| Credential Manager | SSO_POP_Device user: 02tpenhoakvugqlv | cmdkey /list |
| Credential Manager | LegacyGeneric MicrosoftAccount: michellekiss2026@outlook.com (machine persistence) | cmdkey /list |
| Credential Manager | LegacyGeneric MicrosoftAccount: oscar.kiss@hotmail.com (machine persistence) | cmdkey /list |
| Credential Manager | LegacyGeneric MicrosoftAccount: pianist_oscer@outlook.com (machine persistence) | cmdkey /list |
| Credential Manager | LegacyGeneric MicrosoftAccount: oscar.kiss@outlook.com (machine persistence, new alias) | cmdkey /list |
| Credential Manager | WindowsLive virtualapp/didlogical user 02tpenhoakvugqlv | cmdkey /list |
| Credential Manager | MicrosoftOffice16_Data live:cid=dc95a94aad6842c9 | cmdkey /list |
| Credential Manager | Firefox Encrypted Storage (local machine persistence) | cmdkey /list |
| Credential Manager | Olk/PushNotificationsKey and PushNotificationsBackupKey (Outlook push creds) | cmdkey /list |
| Credential Manager | Domain credential target=OZ, user=OZ | cmdkey /list |
| Credential Manager | Domain credential target=192.168.137.10, user=oz (local network device) | cmdkey /list |
| Credential Manager | github-copilot-app credential GUID 92531aa2-ce8e-47c7-bbbd-70db41520b0e | cmdkey /list |
| Exchange Config | AutoDiscover redirect servers: autodiscover-s.outlook.com, autodiscover.hotmail.com | HKCU Office 16.0 Outlook AutoDiscover |
| iCloud | MobileSync Backup folder present but empty of device backups; only iMazing.Versions marker - iCloud for Windows not installed | AppData\Roaming\Apple Computer\MobileSync |
| iCloud | Apple Mobile Device Service logs show repeated iPhone/iPad connections Aug-Sep 2026 | AppData\Roaming\Apple Computer\Logs |
| Intune / MDM | Monitoring csv is Intune/Endpoint Manager report catalog (App config, install status, licenses, protection policies) - confirms MDM admin activity | OneDrive\Documents\Monitoring_2026-09-06T12_49_59.630Z.csv |
| Microsoft Learn | MS Learn profile: upn=oscar.kiss@hotmail.com, MSA auth, tenantId=9188040d-6c67-4c5b-b112-36a304b66dad (consumer tenant), added 2026-06-01 | OneDrive\Documents\download data login microsoft.json |
| Network Tooling | vendorMacs.xml - MAC vendor DB used by network scanner tool, ties to LAN device 192.168.137.10 in Credential Manager | OneDrive\Documents\vendorMacs.xml |
| Outlook Profile | Active profile NewOutlook-ProfileForPstFiles-Iter1 with 6 MAPI account GUID entries (binary, needs MFCMAPI to decode) | HKCU Office 16.0 Outlook Profiles |
| Telemetry | SessionID.xml - VS/Office telemetry session GUID AF97C5ED-7E3A-48B2-B160-338A2BC98563 | OneDrive\Documents\SessionID.xml |
| Unindexed Files | New files found in deep scan: vendorMacs.xml, QueryResult.csv, Clipchamp preferences.json, Google auth XML captures (drive.google, www.google, googleadservices) | OneDrive\Documents\ & Apps\ |

## Prior Session Highlights (earlier scans)
- `AppRegistrationList.csv` — Azure/Entra app registration export (identity/platform admin activity)
- `ExportData.json` — Microsoft account profile export (userPrincipalName, birth date, tenant/directory IDs)
- `squarespace_backup_codes_private-love@private-love.com.txt` — Squarespace 2FA backup codes, generated 2026-04-29
- `Oscar.Kiss@hotmail.com.pst` — primary Outlook email archive (271 KB)
- `ArtworkDB` — oldest dated artifact (2020-11-25), Public Suffix List domain rules
- Edge `Local State` — encrypted profile/sync/auth keys, multiple browser profiles

## Open Follow-ups
- Decode 6 MAPI GUIDs in Outlook profile via MFCMAPI to reveal linked accounts
- Identify LAN device at `192.168.137.10`
- Cross-reference Edge encrypted keys with Credential Manager entries
