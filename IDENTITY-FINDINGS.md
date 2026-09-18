# Identity & Configuration Findings

Consolidated, read-only scan results from local PC filesystem, registry, and Windows Credential Manager. No passwords or secret values were extracted — only account identifiers, server endpoints, and artifact locations.

_Last updated: 2026-09-18_

## Confirmed Email Identities
- `Oscar.Kiss@hotmail.com` (primary)
- `oscar.kiss@outlook.com` (alias)
- `pianist_oscer@outlook.com`
- `michellekiss2026@outlook.com`
- `private-love@private-love.com`
- `andrea.lakatos@windowslive.com` (found in IdentityCRL registry)
- `OszkarKiss@MyWorkSpace67.onmicrosoft.com` (workplace tenant identity)
- `Admin@OscarKisshotmail465.onmicrosoft.com` (workplace tenant identity)

## Second Windows Profile: C:\Users\oscar
A second local Windows user profile was discovered and confirmed by the user as self-owned/self-inspected. It contains a pre-existing, well-designed self-inspection toolkit (`IdentityEvidenceCollector.ps1`, `DeepIdentityDriveCollector.ps1`) plus generated evidence bundles and Wireshark packet captures of the user's own iPhone traffic.

### Workplace-Joined Tenants (from `dsregcmd /status` + registry)
| Tenant ID | Display Name | Linked Email | Device Cert Validity |
|---|---|---|---|
| `14711b58-546b-466f-97d6-38528f6a109c` | MyWorkSpace | OszkarKiss@MyWorkSpace67.onmicrosoft.com | 2026-07-11 → 2036-07-11 (TPM-protected) |
| `c194dd61-7e9f-432c-b107-a45c8f0a7af0` | Default Directory | Admin@OscarKisshotmail465.onmicrosoft.com | 2026-07-14 → 2036-07-14 (TPM-protected) |

### Browser Profiles (Edge)
- Profile 1: `oscar.kiss@hotmail.com` (Oscar Kiss)
- Profile 2: `Admin@OscarKisshotmail465.onmicrosoft.com` (Admin)

### Local Windows Accounts on DESKTOP-V1BDUNP
Administrator, CodexSandboxOffline, CodexSandboxOnline, DefaultAccount, Guest, LENOVO, oscar, WDAGUtilityAccount, WsiAccount

### Notable Installed Identity/Cloud Apps
Microsoft.AzureVpn, Microsoft.OutlookForWindows, AppleInc.iCloud, MSTeams, Microsoft.MicrosoftOfficeHub, Microsoft.OneDriveSync

### Other Artifacts
- OAuth app "outlook gemini": clientId `595cd25b-78f9-4580-85c8-67ff961dc327`, secretId `f8ba1288-e43b-48bb-b231-64ebf10980ab` (secret values redacted in source file)
- Expired Apple iPhone Device CA certificate (exp. 1/24/2020)
- Duplicate PST files (`Outlook1.pst`, `Oscar.Kiss@hotmail.com.pst`, both 271KB)
- Suspicious `.eml`: "Re_ Important_ your vehicle is no longer taxed" — potential phishing, recommend review/deletion
- 15 Wireshark `.pcapng` captures of self-owned devices (largest 90.9MB), ETW system trace logs — self-inspection network tooling

## Deep Scan Pass (2026-09-18): Network Device + Fresh Re-scan

### LAN Device Identification
- `192.168.137.10` is **not reachable** on the current network (current subnet: `192.168.2.x` via `mynetwork.home`).
- `192.168.137.x` is the **default Windows Mobile Hotspot / ICS subnet** — this credential likely originates from a past mobile-hotspot/tethering session, not a persistent LAN device.

### GitHub CLI Authentication
- Logged in as **`oscarkiss-dot`**, scopes: `gist`, `project`, `read:org`, `repo`, `user`, `workflow`
- Global git `user.name`/`user.email`/`credential.helper` are all unset

### Third iOS Management Tool Discovered: 3uTools
- Found at `C:\3uToolsV3` with `Backup`, `SocialBackup`, `CustomizedBackup`, `Firmware`/`Firmcache` folders
- Confirms a third parallel iPhone management/backup toolchain (alongside iMazing and PhoneRescue)
- **OneDrive Personal account UserFolder** registry value unusually points to `C:\3uToolsV3\OneDrive`

### OneDrive Business Account Slot
- Registry shows an empty `Business1` account slot configured under OneDrive Accounts (capability present, not populated with active details in this export)

## App Center Root Org Trace - CONFIRMED (Exact Match + Visual Proof)

A fourth, previously unseen tenant was discovered and directly confirmed via Azure CLI login, resolving the original App Center object ID with an exact match. This was further confirmed visually via a user-provided screenshot of the App Center portal itself.

| Field | Value |
|---|---|
| App Center Object ID | `faf4a9e5-1e7f-44c4-85b8-e0ebb46313dd` - exact match to original request |
| Root Org (Tenant ID) | `c8553249-62c8-409b-9e73-b496ed042686` |
| Subscription ID | `f2aa2ed7-9c32-4b6d-9fa5-cd3284de9ceb` (matches user-provided portal screenshot) |
| Domain | `OscarKisshotmail201.onmicrosoft.com` |
| Authenticated account | `Oscar.Kiss@hotmail.com` (primary identity) |
| App owner org (Microsoft's own tenant) | `f8cdef31-a31e-4b4a-93e4-5f571e91255a` |
| Service principal created | 2026-09-07T05:43:01Z |
| Publisher | Microsoft Corporation (verified), multi-tenant app (`AzureADMultipleOrgs`) |
| App Center Organization Name | "Osie Black" - `https://appcenter.ms/orgs/Osie-Black` |

### App Center Organizations Visible Under This Account (from screenshot)
| Entity | Type |
|---|---|
| Oscar Kiss | Personal account |
| MyWorkSpace | Organization |
| Osie Black | Organization (confirmed root org for the App Center trace) |
| osie black (lowercase) | Separate entity, distinct icon - likely another personal account; not yet fully identified |

Resolution notes:
- This tenant (`c8553249-...`) enforces Security Defaults / Conditional Access, which blocked the standard device-code flow (`AADSTS530035`) and required an interactive browser login instead.
- Local browser settings cache (`settings.json`) independently corroborated this: a saved Azure Portal resource filter named "Osie Black" (`subscriptionName contains "Osie Black"`) tied to the same tenant ID, plus search history entries "Osie black", "Godaddy", "Mai", "Oz".
- No Azure resource groups or management groups are named "Osie Black" in this tenant - confirms it is purely an App Center-level organization, not an Azure resource.
- An earlier elimination-based guess incorrectly pointed to "MyWorkSpace" - corrected here with direct proof.
- Open item: the separate lowercase `osie black` entity in the App Center sidebar has not yet been identified - recommend clicking into it to check its Settings page the same way.
- Visual Studio App Center itself was retired 3/31/2025 (Analytics/Diagnostics supported until 3/31/2027) - org still exists but the product is in wind-down.

### Osie Black Org - Apps, Ownership, and Azure Links (CONFIRMED via portal screenshots)

**Apps in this org:**
| Name | OS | Release Type | Role |
|---|---|---|---|
| Mac | macOS | - | Collaborator |
| TextPlus | iOS | Enterprise | Collaborator |

This **resolves the earlier "TextPlus" search** (previously not found in Entra app registrations or local installs): TextPlus is an App Center-managed iOS app project under the Osie Black org, not a locally installed program or Entra app registration.

**Collaborators (People > Collaborator):**
| Name | Email | Role |
|---|---|---|
| Oscar Kiss | Oscar.Kiss@hotmail.com | Admin |

Only one member exists on this org - **confirms Osie Black is solely owned/controlled by the user**, not a shared or third-party organization.

**Linked Azure Subscriptions (Manage > Azure):**
| Subscription Name | Subscription ID | Tenant |
|---|---|---|
| Azure subscription 1 | `f2aa2ed7-9c32-4b6d-9fa5-cd3284de9ceb` | `c8553249-...` (domain 201) |
| Azure subscription 1 | `57c25f8f-b37a-4455-bae8-6991b87c7213` | `c194dd61-...` (domain 465) |

**Important cross-link:** this confirms both previously-separate Entra tenants (`c8553249-...` and `c194dd61-...`) are linked to the *same* App Center organization ("Osie Black"), both under the user's own control. Azure AD is not yet "Connected" for this org (button available but unused).

### FINAL RESOLUTION - Osie Black is a self-created test artifact (user-confirmed)

User confirmed directly: "Osie Black" is an org **they created themselves** while experimenting with App Center, and the linked email (`Oscar.Kiss@hotmail.com`) is their own personal email - not a third party, breach, or unknown actor. User intends to delete the apps ("Mac", "TextPlus") and the org itself as cleanup.

**Status: RESOLVED / NOT A SECURITY CONCERN.** No further investigation needed on this org unless new evidence emerges. Cleanup steps (for user reference): delete each app under Settings > Delete app, then Manage > Settings > Delete organization.
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
- Identify the separate lowercase `osie black` entity in the App Center sidebar (distinct icon from "Osie Black" org) - not yet clicked into
- ~~Resolve "Osie Black" App Center org and "TextPlus" app~~ **RESOLVED**: user-confirmed self-created test org/app, scheduled for deletion, not a security concern
