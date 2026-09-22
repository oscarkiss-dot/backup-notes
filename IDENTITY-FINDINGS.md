# Identity & Configuration Findings

Consolidated, read-only scan results from local PC filesystem, registry, and Windows Credential Manager. No passwords or secret values were extracted — only account identifiers, server endpoints, and artifact locations.

_Last updated: 2026-09-19_

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

**Important cross-link:** this confirms both previously-separate Entra tenants (`c8553249-...` and `c194dd61-...`) are linked to the *same* App Center organization ("Osie Black"), both under the user's own control. App Center shows its Azure Active Directory integration as not connected; the existing subscription links remain visible independently.

### FINAL RESOLUTION - Osie Black is a self-created test artifact (user-confirmed)

User confirmed directly: "Osie Black" is an org **they created themselves** while experimenting with App Center, and the linked email (`Oscar.Kiss@hotmail.com`) is their own personal email - not a third party, breach, or unknown actor. User intends to delete the apps ("Mac", "TextPlus") and the org itself as cleanup.

**Security assessment: no third-party activity found.** The user later reported losing the sign-in route they used to reach this org. Screenshots dated 2026-09-22 subsequently confirmed the session can again open the organization settings and Azure-link pages, so **App Center access is currently restored**. Do not delete the org or its apps until any needed data is exported.

### Current App Center Access-Recovery Anchor (2026-09-22)

The strongest supported recovery route is the Microsoft consumer account `Oscar.Kiss@hotmail.com`:

| Evidence | What it establishes |
|---|---|
| App Center People page | `Oscar.Kiss@hotmail.com` is the only displayed collaborator and has the **Admin** role on Osie Black. |
| Azure CLI account context | The same address remains authenticated for subscription `f2aa2ed7-9c32-4b6d-9fa5-cd3284de9ceb` in tenant `c8553249-62c8-409b-9e73-b496ed042686`. |
| Azure Portal settings cache | The tenant remains the default directory: `OscarKisshotmail201.onmicrosoft.com`. |
| Microsoft profile export and Edge profile metadata | The account is a Microsoft consumer account (MSA), is locally cached in Edge Profile 1, and has a profile record dating to 2021-10-06. |
| Microsoft Support case `2608290040000285` | Support confirmed the subscription owner is the tenant's external representation of this same address: `Oscar.Kiss_hotmail.com#EXT#@OscarKisshotmail201.onmicrosoft.com`. |

**Important distinction:** the `#EXT#` address is not a separate mailbox or a different person. It is the Entra guest/external representation of the personal Hotmail account. Recent Azure CLI attempts to obtain Microsoft Graph/ARM tokens returned `AADSTS50020`; this indicates that the consumer account is not eligible for that tenant's direct directory token flow. It does **not** show that the Hotmail account, subscription, or App Center org was deleted.

**Recovery status:** the account/session can currently browse `https://appcenter.ms/orgs/Osie-Black/manage/settings` and `/manage/azure`, including the organization settings and linked subscription list. Preserve this working session and export any needed app data before cleanup. Do not create a replacement App Center organization.

### App-Level Access Discovery (2026-09-22)

The **Mac** app's Collaborators page shows:

| Collaborator | Type | Role |
|---|---|---|
| Osie Black Admins | App Center group | Manager |

The people picker contained `pianist_oscer@icloud.com`, but the screenshot does not establish that this address was added or invited. Do not send a new invitation merely to test access; first inspect the **Osie Black Admins** group and its membership from the App Center UI.

### Org-Level Collaborator List Confirmed (2026-09-22)

`appcenter.ms/orgs/Osie-Black/people/collaborators` (org level, distinct from the Mac app's collaborator list) shows **5 Admins**:

| Collaborator | Status |
|---|---|
| Oscar.Kiss@hotmail.com | Active (currently signed in) |
| andrea.lakatos@windowslive.com | Invited (pending) |
| oscar.kiss@icloud.com | Invited (pending) |
| Oszkar@OscarKisshotmail465.onmicrosoft.com | Invited (pending) |
| pianist_oscer@icloud.com | Invited (pending) |

All four pending invitations are the user's own previously-identified aliases; no third-party address is present. This explains the "invites fail" symptom: the invitations were sent successfully (status = Invited) but were never accepted, most likely because the destination alias mailbox was never opened to accept them. A **Teams** sub-page also exists (`.../people/teams`) showing one team named "OS" with 1 member and 1 app, separate from the app-level "Osie Black Admins" group found earlier.

**Action needed to resolve "invites fail":** sign into each alias mailbox (andrea.lakatos@windowslive.com, oscar.kiss@icloud.com, Oszkar@OscarKisshotmail465.onmicrosoft.com, pianist_oscer@icloud.com) and look for/accept the App Center invitation email, or re-send from the Osie Black collaborator list if the original invite expired.

### Why Osie Black Never Appears as an Azure "Resource" (2026-09-22)

An App Center **organization** is not an Azure Resource Manager (ARM) object. It will never show up in `az resource list`, the Azure Portal's Resource Groups blade, or the "All resources" view, regardless of Admin role in App Center. The only Azure-side artifacts tied to Osie Black are the two **linked subscriptions** visible under App Center's Manage > Azure page (`f2aa2ed7-...` and `57c25f8f-...`). Being Admin on the App Center org does not, by itself, grant Azure RBAC roles on those subscriptions/resources — those are separate permission systems. This is most likely the source of the "I'm Admin but don't see it in my resources" contradiction, not a broken/lost account.

### "Connect to Azure AD" Failure — ROOT CAUSE CONFIRMED (2026-09-22)

Full error text captured from `appcenter.ms/orgs/Osie-Black/manage/azure/connect-tenant`:

> "Oops. Something went wrong. Please try again."
> "Failed to link Org to an AAD tenant, you likely do not have access to the home tenant because you are logged in with a personal account."

Critically, the "Connect your tenant" picker offered **only one option**: `Default Directory` — tenant `c194dd61-7e9f-432c-b107-a45c8f0a7af0` (the `...465` tenant). It did **not** offer `c8553249` (the Osie Black anchor tenant that actually holds the two linked subscriptions `f2aa2ed7-...` and `57c25f8f-...`).

**Confirmed root cause (two compounding issues):**
1. The browser/account session's *default* tenant resolves to `c194dd61`, not `c8553249` — consistent with this PC's `dsregcmd` WorkplaceJoin also pointing at `c194dd61`. App Center is offering to link to the wrong tenant entirely.
2. Even disregarding (1), `Oscar.Kiss@hotmail.com` is a **personal/consumer Microsoft Account (MSA)**, not a native work/school account, in that tenant's directory — and AAD-tenant linking requires a native member account with directory permissions, not an MSA/guest identity. This matches the exact wording of the error.

**No further action recommended without care**: forcing a link to `c194dd61` would attach Osie Black to a tenant that does not hold its subscriptions. Resolving this properly would require either (a) creating/using a native work account inside tenant `c8553249` with sufficient rights, or (b) accepting that Osie Black may simply remain unlinked to any AAD tenant (App Center works fine without this optional feature — it only enables AAD-group-based access management, which is not required for basic org/app administration).

### Correction: Azure DevOps IS Linked (service-level, not local machine)

Earlier this session it was concluded "not connected to DevOps" based on local CLI/Credential Manager checks. New evidence narrows this: the **TextPlus app's Settings > Services** page (App Center service integrations, stored server-side — a different scope than the local-PC check) shows three linked accounts:

| Service | Account |
|---|---|
| GitHub (Bug tracker) | pianist_oscer@hotmail.com |
| Azure DevOps | Oscar.Kiss@hotmail.com |
| GitHub | oscar.kiss@hotmail.com |

So Azure DevOps **is** linked as an App Center service integration for the TextPlus app specifically. This does not contradict the earlier local-machine finding (no `dev.azure.com` entries in Credential Manager, no DevOps CLI extension) — those two facts describe different things: a server-side App Center integration vs. this PC's local credential cache. Also newly observed alias: `pianist_oscer@hotmail.com` (a third variant alongside the previously known `@icloud.com` and `@outlook.com` forms).

The Data Export dialog (Settings > Export > New Export) was also inspected — its "Instrumentation key" / "Connection string" fields are both empty placeholders; no export pipeline has actually been configured. This is an unused feature, not evidence of an active data flow.

### Device Issue — Clarified (2026-09-22)

The user's tracked "device issue" is: the **physical device previously used to complete GitHub advanced/two-factor authentication has been lost**. That device/method had originally been set up specifically to recover a lockout on `pianist_oscer@hotmail.com` (GitHub's device-based recovery succeeded at the time). Without that device, GitHub 2FA/recovery can no longer be completed. Separately, an **Apple ID verification code was passed successfully**, but Apple's account flow still demands an additional trusted-device verification step that cannot be completed without the lost device.

**Recommended recovery path (safe, no destructive actions taken):**
- GitHub: use saved recovery codes if any exist ("Use a recovery code" at login); otherwise file GitHub's account-recovery request (requires identity/billing proof, may take several days). Once regained, immediately remove the lost device's 2FA registration and add a current device/authenticator.
- Apple ID: use `appleid.apple.com` → "Forgot Apple ID or password?" → **Account Recovery**, which does not require the old device but involves a multi-day security-review hold.

### Guidance: Do Not Delete Oscar.Kiss@hotmail.com from Osie Black

User asked whether to delete `Oscar.Kiss@hotmail.com` from App Center and replace it with a work account, to try to resolve the AAD-connect failure. **Advised against deleting first** — it is the only currently-confirmed-working Admin identity on Osie Black; removing it before a replacement is added and verified risks a full, unrecoverable lockout, mirroring the same failure pattern as the lost 2FA devices above. Correct sequence: add a native/work account as an additional Admin, confirm it can fully load and operate Osie Black, and only then evaluate removing the personal account. Note also that a generic work email alone will not fix the AAD-connect failure — it must specifically be a native member of tenant `c8553249` with adequate directory rights.

### Additional Entra Tenant Observed (2026-09-22)

A separate Default Directory was visible in the Entra/Billing screenshots:

| Field | Value |
|---|---|
| Tenant ID | `23ed74b0-4708-4f7b-814d-89aa25583f9` |
| Initial domain | `OscarKisshotmail482.onmicrosoft.com` |
| User shown | `Oscar.Kiss_hotmail.com#EXT#@OscarKisshotmail482.onmicrosoft.com` |
| User type | Member |
| Billing/subscriptions shown | No subscriptions in that directory |

This is distinct from the domain-201 and domain-465 tenants. It does not establish a new App Center link. The Entra **Invite external user** page and Azure **elevated access/MFA** page are not recovery steps for Osie Black; do not send an invitation, grant elevated access, or change MFA settings solely for this investigation.

### Admin Activity Trace (Azure Activity Log + Entra Audit Log, tenant `c8553249-...`)

Traced via `az monitor activity-log list` and Microsoft Graph `auditLogs/directoryAudits` since only one Admin exists on this org (the user):

| Source | Finding |
|---|---|
| Azure Activity Log | Repeated attempts (2026-09-16) to grant **Contributor** role on subscription `f2aa2ed7-...` to the App Center service principal (`faf4a9e5-...`) - failed with `RoleAssignmentExists` (already granted) |
| Role Assignment (current) | App Center's app (`6201c56d-46d7-4152-bdb6-e0c77193784b`) currently holds **Contributor** on subscription `f2aa2ed7-...` - granted via App Center's "Connect to Azure AD" feature |
| Cognitive Services Resource | `oscarkiss-2382-resource` (AI Services / Azure OpenAI-type, SKU S0, `westus3`) in `rg-oscar.kiss-2088`, created 2026-08-17 by `Oscar.Kiss@hotmail.com`; key-retrieval actions logged 2026-09-14 |
| Entra Directory Audit Log | All recent actions (MFA policy updates, company info changes, app/service principal updates, app consents) initiated exclusively by `Oscar.Kiss@hotmail.com` / `live.com#Oscar.Kiss@hotmail.com` - **no third-party or unknown initiators found** |

**Conclusion:** the reviewed activity sample traces to the user's known Microsoft identity; no unknown initiator was found in that sample. The one actionable item is that App Center retains broad **Contributor** access to the subscription from an old integration action. Revoke it only after confirming that the App Center access-recovery/export work is complete.
## Findings by Category

| Category | Detail | Source |
|---|---|---|
| Azure | AzureStorageAccounts.csv export - header only, no storage accounts present | OneDrive\Documents\AzureStorageAccounts.csv |
| Azure Activity | QueryResult.csv - Azure Activity Log query result, header only, no events | OneDrive\Documents\QueryResult.csv |
| **Azure Foundry / AI Services** | **oscarkiss-2382-resource** (Foundry type, AI inference service), westus3, created 2026-08-17 by Oscar.Kiss@hotmail.com, subscription f2aa2ed7-..., resource group rg-oscar.kiss-2088. API Keys (KEY 1, KEY 2), Endpoint: https://oscarkiss-2382-resource.services.azure.com/. Standard Agent light-weight config. | Azure Portal 2026-09-19 |
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
- Export any required Osie Black app data now that current App Center access is confirmed, then decide whether cleanup is still wanted
- Inspect the existing **Osie Black Admins** App Center group and document its membership before changing invitations or roles

## Investigation Scope & Standing Directive (2026-09-18)

**Anchor identity:** "Osie Black" (App Center org, `appcenter.ms/orgs/Osie-Black`) and the broader Oscar Kiss / Oszkar / OZ alias cluster remain the central reference point for this entire investigation. Every new finding, across every provider, should be checked for association/relevancy back to this identity before being logged.

**Standing directive:** maintain persistent, cross-device memory of all findings. This file (`IDENTITY-FINDINGS.md`, pushed to `oscarkiss-dot/backup-notes`) is the durable source of truth across sessions/devices. Continue appending here as investigation expands.

**Planned scope expansion (not yet started):**
| Provider | Status | Notes |
|---|---|---|
| Microsoft / Azure / Entra / App Center | Active | Root anchor - tenant `c8553249-...`, subscription `f2aa2ed7-...`, App Center org "Osie Black" |
| Google Workspace | Planned | Check for a linked Workspace/GSuite tenant or migration tied to same identity/aliases |
| AWS | Planned | Check for IAM users/accounts tied to same email aliases or Osie Black identity |
| Oracle Cloud | Planned | Check for OCI accounts tied to same identity |
| Other (GitHub orgs, Apple/iCloud, etc.) | Reserved | Add as they come up; cross-reference against the same alias cluster |
