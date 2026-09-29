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

## Prioritized Action Plan (2026-09-22)

After extensive tracing, the Osie Black origin investigation is **closed** — it is fully explained as self-created and self-named by the user, with no external or malicious actor involved. Remaining open items were re-prioritized honestly by actual impact:

1. **GitHub 2FA/account recovery** (highest priority, longest lead time) — start GitHub's account-recovery request now if no saved recovery codes exist; can take several days.
2. **Apple ID device-verification recovery** (equal priority) — start Account Recovery at appleid.apple.com now; also a multi-day hold.
3. **Add a second working Admin to Osie Black** — accept one of the already-pending self-owned App Center invites, as a redundancy safety net against single-point-of-failure lockout.
4. **App Center "Connect to Azure AD" fix — deprioritized.** This only enables AAD-group-based permission management in App Center; it is not required for current full Admin access via Oscar.Kiss@hotmail.com. Not worth the effort/risk of provisioning a new native Global Admin user solely for this.
5. **General caution going forward:** avoid clicking unfamiliar Azure Portal actions outside an explicitly agreed step list — the "Change directory" incident earlier was a near-miss that could have disrupted subscription 57c25f8f's RBAC.

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

### Subscription-to-Domain Trace (2026-09-22)

The two Azure subscriptions linked under Osie Black's Manage > Azure page belong to **two different tenants**, not one:

| Subscription ID | Tenant ID | Domain |
|---|---|---|
| `f2aa2ed7-9c32-4b6d-9fa5-cd3284de9ceb` | `c8553249-62c8-409b-9e73-b496ed042686` | `OscarKisshotmail201.onmicrosoft.com` (primary/anchor — holds the App Center service principal, its Contributor role assignment, and the Foundry AI resource) |
| `57c25f8f-b37a-4455-bae8-6991b87c7213` | `c194dd61-7e9f-432c-b107-a45c8f0a7af0` | `OscarKisshotmail465.onmicrosoft.com` |

This dual-tenant split is precisely why "Connect to Azure AD" fails: App Center can only link to one tenant, and its connect dialog defaults to `c194dd61`/`...465` — which is not the tenant holding the primary App Center-linked Azure activity. **Any new account added to resolve this should be a native (non-guest) member specifically of tenant `c8553249` / `OscarKisshotmail201.onmicrosoft.com`** — an account native only to `...465` would not cover the primary subscription.

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

## Windows Credential Manager / Device Certificate Decode (2026-09-28)

The selected certificate in the Windows **Add a Certificate-Based Credential** form is:

| Field | Value |
|---|---|
| Issued to / device ID | `bc56ad1d-742c-46ab-bf65-b9a989a8eb7d` |
| Issued by | `MS-Organization-Access` |
| Validity | 2026-09-18 through 2036-09-18 |

Read-only local checks confirm `dsregcmd /status` reports `WorkplaceJoined: YES`, `WorkplaceDeviceId: bc56ad1d-742c-46ab-bf65-b9a989a8eb7d`, and `WorkplaceTenantId: c194dd61-7e9f-432c-b107-a45c8f0a7af0` (`...465` tenant); `AzureAdJoined: NO`. The certificate's subject matches this PC's workplace device ID, so this is the **current PC's Entra workplace-registration/device-auth certificate**, not the lost GitHub 2FA device or a GitHub credential. The certificate-credential form has a blank network address and was not submitted; do not use it to create a GitHub credential. Do not delete or export the certificate/private key.

The Credential Manager screenshot also shows cached account/app entries, including a generic target beginning `92531aa2-...github-cop...`. The name is consistent with a GitHub Copilot app credential, but the target label alone does not establish which GitHub account it authenticates or whether it can recover access to `pianist_oscer@hotmail.com`. Password/token contents were not read or exposed; do not copy, export, or share them. The visible Microsoft-account and `virtualapp/didlogical` entries are local cached credentials, not proof of current tenant permissions or GitHub 2FA recovery.

### `OZ` and `virtualapp/didlogical` Credential Identification

Read-only `cmdkey /list` inspection confirms:

| Credential target | Type | Username | What can be established |
|---|---|---|---|
| `Domain:target=OZ` | Domain Password | `OZ` | A saved Windows network/domain credential whose target and username are both `OZ`. The current PC hostname is `DESKTOP-V1BDUNP`, so `OZ` is not this PC's current hostname. The target alone does not identify the remote host, person, or account service. |
| `Domain:target=192.168.137.10` | Domain Password | `oz` | A separate saved network credential for that IP, also using username `oz`. It could be related to the `OZ` entry, but that cannot be established from Credential Manager alone. |
| `WindowsLive:target=virtualapp/didlogical` | Generic | `02tpenhoakvugqlv` | A legacy Windows Live/Microsoft-services credential target used for saved sign-in/SSO. The username is an opaque identifier, not an email address or an identified human account. The same username appears under `SSO_POP_Device`, which suggests a device/SSO-related cached identity but does not identify the Microsoft account behind it. |

No active SMB mapping or connection was returned for `OZ` during the read-only check. These entries do not identify a particular Microsoft account, GitHub identity, or lost physical device. To identify `OZ` further, compare the target with historical router/DHCP device names, NAS/printer/network-share configuration, or the device that was previously accessed using username `oz`. Do not delete the entries or reveal/export their secret values while tracing them.

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

## GoDaddy / Domain Registrar Search — No Evidence Found (2026-09-28)
Searched DNS logs (`dns log.csv`, 7.4MB capture), domain category rollups (`category-domains-4.csv`), mailbox rule exports, and contact lists for GoDaddy or any other registrar (Namecheap, IONOS/1&1, Network Solutions, Bluehost, HostGator). **Zero matches anywhere.** `category-domains-4.csv` shows only consumer categories (Microsoft, Apple, telemetry, general web) — no registrar/hosting traffic ever recorded. Bulk tenant lookup (`tenantidlookup_bulk_2026-07-08...csv`) confirms `osieblack` returns "Invalid tenant ID or domain" — it was never a real registered domain, consistent with the earlier closed finding that it is a self-created nickname/saved-filter name only.

## Mailbox Forwarding Rule — Benign Self-Forward
Found `InboxRules.txt` (Exchange mailbox rule export). One `OP_FORWARD` rule exists, decoded from binary: forwards `oscar.kiss@hotmail.com` → `oscar.kiss@hotmail.com` (itself). This is a standard loop-prevention/self rule, **not** external exfiltration. No third-party forwarding address found in any mailbox export.

## "OZ" Credential — FULLY RESOLVED (Own Old Acer Desktop)
`DeviceHash_OZ.csv` (Windows Autopilot hardware-hash export) identifies the actual hardware behind the `OZ` Credential Manager entry:
- Serial: `PTSCM0200194900C933000`
- System: **Acer Aspire X1301** desktop (Phoenix BIOS, Acer WMCP78M motherboard, AMD Athlon II X2 240 CPU, NVIDIA GeForce 9200 GPU — circa 2009–2011 hardware)

**`OZ` = short for "Oszkar"** (`oszkar.kiss@hotmail.com` alias). Corroborated by a prior self-inspection AI session log (`copilot-activity-history.csv`) that independently reconstructed this same device as the user's early Canada-period computer (post-UK, pre-Apple-ecosystem), registered under `oszkar.kiss@hotmail.com`. Both Credential Manager entries — `Domain:target=OZ` and `Domain:target=192.168.137.10` (username `oz`) — point to this same physical device. **Confirmed self-owned, not foreign/third-party.** (That same log also references a `rosie.black@live.ca` alias tied to Xbox/App Center metadata — separate from the already-closed Osie Black investigation, noted for awareness only.)

## Google Workspace Migration Attempt Found
Installed software "Google Workspace Migration for Microsoft Exchange 5.2.42.0" (installed 2026-07-06) plus `GoogleIDPMetadata.xml` (Google SAML IdP metadata, valid until 2031-07-05) found in `C:\Users\oscar\Downloads`. Concrete evidence of an attempt to migrate mail from Microsoft 365/Exchange to Google Workspace and/or set up Google as a SAML SSO provider — intent/outcome not yet confirmed with user.

## Microsoft Support Case #2608290040000285 — Effectively Answered
Found the full email thread saved as `.eml` in OneDrive Documents. Support (Tobi Adesoye / Samuel Odunlade, Azure Subscription Management Support) confirmed: subscription `f2aa2ed7-9c32-4b6d-9fa5-cd3284de9ceb` owner is `Oscar.Kiss_hotmail.com#EXT#@OscarKisshotmail201.onmicrosoft.com` (guest), Tenant ID `c8553249-62c8-409b-9e73-b496ed042686`. Microsoft Support **cannot** retrieve further historical tenant/mailbox/billing details beyond what the tenant's own Global Admin (the user) can already see. Case may auto-close due to inactivity — effectively resolved, no further action needed unless user wants to formally reply/close it.

## oscar.kiss@hotmail.com — Full Mail/Exchange Evidence Scan (2026-09-28)
Read-only, metadata-only scan of all mail-related files (.pst/.ost/.eml/.msg) across the entire C: drive.

**PST files (4 found)**: All exactly ~271KB — this is the standard size of an **empty** Outlook data file with zero stored messages, not real historical archives. No bulk mail content exists in any of them.

**Genuine Microsoft Entra security alert found**: "Microsoft Entra ID Protection Weekly Digest" (dated 2026-07-07, from `MSSecurity-noreply@microsoft.com`, verified legitimate via SPF pass + correct cross-tenant headers) reported **"New risky users detected"** and **"New risky sign-ins detected"** for tenant `MyWorkSpace67.onmicrosoft.com`. This is a real, actionable alert — recommend logging into entra.microsoft.com for that tenant and reviewing Identity Protection > Risky sign-ins / Risky users, since specifics aren't visible in the static digest email itself.

**Historical display name confirmed**: A 2021-06-11 bounce email shows display name "Oszkar Kiss" `<Oscar.Kiss@hotmail.com>` used with Adecco (staffing agency) — confirms "Oszkar" as a genuine historical display-name variant on this mailbox, consistent with the earlier OZ/Oszkar credential finding. Also found account-existence proof back to 2014 (an "Automatically update your contacts" Outlook onboarding email).

**Phishing email flagged (no action beyond awareness)**: A 2024-02-02 email spoofing "Government Gateway" (vehicle tax scam) using Unicode lookalike characters, sent from a compromised/unrelated third-party tenant (`snohomishcountyweddings.onmicrosoft.com`). This is spam received by the user, not evidence of the user's own account being compromised.

**Unrelated personal correspondence**: 2021 Adecco job-assessment onboarding emails — not identity-security relevant.

---

# DEEP FORENSIC IDENTITY RECONSTRUCTION (2026-09-29)

_Investigation scope: authorized self-audit of this PC's own Microsoft/Windows identity history. Read-only. No secrets extracted. Evidence confidence levels used throughout: VERIFIED / CORROBORATED / INFERRED / UNRESOLVED / DISPROVEN._

## Executive Finding
This machine's OneAuth/identity caches, Exchange mailbox rule export, and a prior Microsoft Support case thread together establish **at least two genuinely distinct Microsoft identities** used by the same person: the personal MSA `Oscar.Kiss@hotmail.com`, and a separate native Entra member account `Oszkar@OscarKisshotmail465.onmicrosoft.com`. A third apparent "tenant" found in the cache (`f8cdef31-a31e-4b4a-93e4-5f571e91255a`) was investigated and is **not** a user tenant — it is Microsoft's own internal multi-tenant app-owner organization, already documented in this repo's history. The OS itself was freshly imaged on **2026-08-27**, meaning no `Windows.old` or pre-imaging artifacts survive locally; all older timestamps come from synced/imported files, not organic local account history.

## Confirmed Microsoft Identities
| Identity (Object ID / login) | UPN | Type | Tenant | Evidence |
|---|---|---|---|---|
| `b7c7f198a4ce6340` | `Oscar.Kiss@hotmail.com` | MSA (personal) | `9188040d-...` (consumer realm) | VERIFIED — OneAuth account cache |
| `ef8c8bef-7f4f-4e3b-ad91-2ba9948d1bc3` | `Oszkar@OscarKisshotmail465.onmicrosoft.com` | AAD native member (`idtyp=user`) | `c194dd61-...` "Default Directory" | VERIFIED — OneAuth account cache, distinct object ID |
| `2a8e7ac3-7187-407f-95d4-7d15ad87c1a1` | `Oscar.Kiss@hotmail.com` (guest rep.) | AAD guest | `c8553249-...` (Osie Black anchor) | CORROBORATED — `home_account_id` ties back to the MSA identity |
| `dc95a94aad6842c9` | `michellekiss2026@outlook.com` | MSA (personal) | `9188040d-...` | VERIFIED — separate family member account, unrelated to Osie Black |

## Confirmed Historical Names
- **"Oscar Kiss"** — primary display name across MSA and Exchange mailbox artifacts (VERIFIED)
- **"Oszkar Kiss" / "Oszkar"** — historical display-name variant, used at least since 2021 (Adecco correspondence bounce) and matches a distinct native Entra account UPN (`Oszkar@OscarKisshotmail465...`) (CORROBORATED)
- **"Michelle kiss"** — separate family-member MSA, not the same person (VERIFIED)

## Confirmed Email Addresses / Aliases
See existing "Confirmed Email Identities" section above (carried forward, not contradicted by this pass): `Oscar.Kiss@hotmail.com`, `oscar.kiss@outlook.com`, `pianist_oscer@outlook.com`, `michellekiss2026@outlook.com`, `Oszkar@OscarKisshotmail465.onmicrosoft.com`.

## Possible Aliases
- `andrea.lakatos@windowslive.com` — appears only in IdentityCRL registry; relationship to primary identity NOT re-verified this pass (INFERRED, carried from prior finding)
- `private-love@private-love.com` — same status (INFERRED, carried from prior finding)

## Windows Profiles and SIDs
| SID (suffix) | Account | Enabled | Created | Notes |
|---|---|---|---|---|
| ...1001 | LENOVO | Yes | 2026-08-27 | Primary profile this session |
| ...1002 | oscar | Yes | 2026-08-27 | Secondary self-inspection profile |
| ...1003 | WsiAccount | No | 2026-08-27 | PasswordLastSet (2026-07-07) predates profile folder creation — timestamp inconsistency, unexplained (UNRESOLVED) |
| ...1008/1009 | CodexSandboxOffline/Online | Yes | 2026-08-10/13 | Copilot CLI sandbox accounts — **not part of the user's identity**, confirmed by naming/purpose |

**Critical caveat (VERIFIED)**: OS install date is 2026-08-27. No `Windows.old` exists. This is a freshly imaged system — any file/timestamp predating this date arrived via OneDrive sync, manual import, or attachment, not organic local history on this specific install.

## Outlook Profiles
Classic Outlook MAPI profile registry (`HKCU:\Software\Microsoft\Office\Outlook\Profiles`) is **empty** under the LENOVO hive (VERIFIED negative result — consistent with using New Outlook / no legacy profile configured). The `oscar` profile's registry hive is not currently mounted/loaded and was not inspected this pass (SEARCH LIMITATION — would require `reg load`, a higher-risk read action not performed without separate authorization).

## Exchange Mailboxes
One real Exchange Online mailbox identified for display name "Oscar Kiss" via `InboxRules.txt`:
- **LegacyExchangeDN**: `/o=First Organization/ou=Exchange Administrative Group(FYDIBOHF23SPDLT)/cn=Recipients/cn=00064000E2621A80`
- **Mailbox GUID**: `00064000-e262-1a80-0000-000000000000`
- **Mailbox Database GUID**: `2f226473-60d9-4e8e-9448-587806558fcb`
- **Server**: `DS4PR17MB7806.namprd17.prod.outlook.com` (real Exchange Online / outlook.com backend)
- **Database**: `NAMPR17DG448-db183`

All VERIFIED — directly present in the mailbox rule export XML, not inferred.

## Exchange GUID / LegacyExchangeDN Evidence
See table above. This is the strongest Exchange-specific artifact found this pass.

## Microsoft 365 Relationships
No M365/SharePoint/Teams organizational identifiers beyond what's already logged (App Center service principal, Foundry resource) were newly found this pass.

## Confirmed Entra Tenants
| Tenant ID | Domain | Relationship | Confidence |
|---|---|---|---|
| `c8553249-62c8-409b-9e73-b496ed042686` | `OscarKisshotmail201.onmicrosoft.com` | Owner (per MS Support case thread) | VERIFIED |
| `c194dd61-7e9f-432c-b107-a45c8f0a7af0` | `OscarKisshotmail465.onmicrosoft.com` ("Default Directory") | Native member (`Oszkar@...`) | VERIFIED |
| `14711b58-546b-466f-97d6-38528f6a109c` | `MyWorkSpace67.onmicrosoft.com` | Workplace-joined device; notification recipient (Entra digest) | CORROBORATED (membership level not independently re-verified) |

## Possible Historical Tenants
- `23ed74b0-4708-4f7b-814d-89aa25583f9` (`OscarKisshotmail482.onmicrosoft.com`) — logged in a prior session checkpoint showing `Oscar.Kiss` as **Member** (not guest/#EXT#) — **not re-verified this pass**. This is a genuinely different relationship pattern than the guest pattern seen elsewhere and is flagged as a high-value unresolved lead below.

## MyWorkSpace67 Investigation
Digest email confirms `oscar.kiss@hotmail.com` receives Microsoft Entra ID Protection admin notifications ("risky users"/"risky sign-ins detected") for `MyWorkSpace67.onmicrosoft.com`, tenant `14711b58-...`. This typically requires a security-related admin role, but the email artifact alone proves **notification receipt**, not conclusively **membership type** — classified CORROBORATED, not fully VERIFIED, pending a live portal check.

## Authentication Evidence
- Windows Device Registration/Admin log shows repeated Hello for Business provisioning skips (benign, expected — not Entra-joined on this device path)
- One AADSTS50173 error found: "provided grant has expired... user might have changed or reset their password" — grant issued 2026-07-11, invalidated by a token-validity reset dated 2026-07-21. Consistent with a legitimate password change on that account around that time, not evidence of compromise.

## Historical Timeline
| Date | Event | Evidence Type |
|---|---|---|
| 2014-08-15 | "Automatically update your contacts" Outlook onboarding email — proves mailbox existed by this date | VERIFIED (message Date header — see caveat below) |
| 2021-06-11 | "Oszkar Kiss" display name used in Adecco job-assessment correspondence | VERIFIED |
| 2026-07-07 | Michelle kiss / michellekiss2026@outlook.com and Entra digest for MyWorkSpace67 both dated | VERIFIED |
| 2026-08-27 | This Windows installation imaged (OS InstallDate) | VERIFIED |
| 2026-09-28 | LENOVO local account password reset (this session) | VERIFIED |

## Application Relationships
No new application-account correlations found beyond what's previously logged (App Center, Azure DevOps link, GitHub Copilot credential entry).

## Evidence Predating 2026
- 2014-08-15 Outlook onboarding email (message timestamp)
- 2021-06-11 Adecco correspondence ("Oszkar Kiss" display name)
- ~2009–2011-era Acer desktop hardware (OZ device) — hardware manufacture date, not an account-creation date

## Evidence Predating 2021
- Only the 2014-08-15 Outlook onboarding email message timestamp, and the Acer hardware's manufacture era. No other pre-2021 evidence found this pass.

## Earliest Verified Evidence
**EARLIEST VERIFIED ACCOUNT-RELATED EVIDENCE**
- **DATE**: 2014-08-15
- **IDENTITY**: `Oscar.Kiss@hotmail.com`
- **ARTIFACT**: "Automatically update your contacts" Outlook onboarding email (.msg)
- **PATH**: `C:\Users\oscar\iCloudDrive\Downloads\Automatically update your contacts.msg`
- **TYPE OF DATE**: Email `Date:` header (message-sent timestamp) — **NOT** an account-creation timestamp, and **NOT** a file-system timestamp
- **WHY IT MATTERS**: Proves the mailbox was active and receiving Outlook.com onboarding mail by this date. It does **not** prove the account was *created* in 2014 — only that it existed and was already onboarded onto Outlook by then. The earlier "traced back to 2014" claim is hereby **downgraded from an implied creation-date claim to an INFERRED lower-bound of existence** — the true creation date remains unknown and could be earlier.

## Contradictions
1. **The 2014 claim** — previously stated loosely as "traced back to 2014." Corrected above: it is message-timestamp evidence of existence, not proof of account creation date. (RESOLVED — reclassified as INFERRED lower bound)
2. **`f8cdef31-...` tenant** — initially looked like an unknown 4th tenant in this pass's fresh cache read. Resolved using this repository's OWN prior documented finding (session checkpoint + earlier IDENTITY-FINDINGS.md entry): it is Microsoft's internal app-owner org, not a user tenant. (RESOLVED — DISPROVEN as user-tenant hypothesis)
3. **WsiAccount timestamp inconsistency** — PasswordLastSet (2026-07-07) predates its profile folder's CreationTime (2026-08-27). Not explained by current evidence. (UNRESOLVED)
4. **Tenant `...482` Member-type relationship** — a prior session checkpoint recorded `Oscar.Kiss` as a **Member** (not guest) of `OscarKisshotmail482.onmicrosoft.com`, which would be a different relationship pattern than every other tenant found (all guest/#EXT# except the native `Oszkar@...465` identity). This was **not re-verified with fresh artifacts this pass** and remains the single most important open contradiction. (UNRESOLVED — HIGH PRIORITY)

## Unsupported Previous Claims
- The unqualified statement "account traced back to 2014" (implying creation date) is **not supported** by any artifact found. Corrected to an inferred existence lower-bound only (see above).

## High-Value Unresolved Leads
1. **Tenant `23ed74b0-...` / `OscarKisshotmail482.onmicrosoft.com`** — re-verify current Member/guest status live; determine why this differs from every other tenant relationship found. Highest-value lead this pass.
2. **`Domain:target=app` credential** (username `92531aa2-ce8e-47c7-bbbd-70db41520b0e`, a raw GUID) — not yet identified; likely an OAuth client/app registration ID, worth resolving.
3. **MyWorkSpace67 actual risky-user/risky-sign-in details** — the digest email only proves an alert was sent, not its contents; live portal check needed.
4. **`oscar` profile's registry hive (NTUSER.DAT)** — not mounted/inspected this pass; may contain a second Outlook profile or additional identity cache entries not visible from file-system-only inspection.

## Next Five Investigative Actions
1. Log into `entra.microsoft.com/OscarKisshotmail482.onmicrosoft.com` (or via tenant switcher) and check current role/membership for `Oscar.Kiss@hotmail.com` — resolves the highest-priority contradiction above.
2. Log into `entra.microsoft.com` for `MyWorkSpace67.onmicrosoft.com` → Identity Protection → Risky sign-ins/Risky users to see the actual digest contents.
3. Resolve the `92531aa2-...` GUID credential — check `Get-MsalTokenCache`/installed app registrations if accessible, or cross-reference against Azure App Registrations under owned tenants.
4. If further Outlook/Exchange registry evidence is wanted from the `oscar` profile, explicitly authorize a `reg load` of its NTUSER.DAT as a separate, deliberate step (not performed automatically per the read-only-first rule).
5. Investigate the WsiAccount timestamp inconsistency (password set before profile folder existed) to rule out a migrated/restored account artifact.

---

---

# TARGETED CONTRADICTION-RESOLUTION PASS (2026-09-29, continuing from `7bc0eb6`)

## Objective A/B/C — OscarKisshotmail482.onmicrosoft.com: UNRESOLVED (no local corroboration found)
Searched every OneAuth cache, IdentityCRL registry key, AAD Broker package, and TokenBroker cache on **both** the `LENOVO` and `oscar` Windows profiles, plus all prior evidence CSVs and session records, for tenant `23ed74b0-4708-4f7b-814d-89aa25583f9` / `OscarKisshotmail482.onmicrosoft.com`. **Zero local artifacts reference this tenant anywhere on this machine.** The only source that has ever recorded it is a prior session checkpoint transcribing user-provided screenshots — no object ID was ever captured, only the tenant ID and the on-screen UPN string.

**Important contradiction within the original source itself**: the UPN shown was `Oscar.Kiss_hotmail.com#EXT#@OscarKisshotmail482.onmicrosoft.com` — this is the standard Entra **guest** naming pattern (`#EXT#`) — yet the checkpoint's "User type" column reportedly showed **Member**. Two explanations are possible, both unproven:
1. A genuine **converted guest-to-member** account (a real, documented Entra behavior: converting a guest to a member does not regenerate the `#EXT#` UPN), or
2. A misread/mistranscribed screenshot detail from the prior session.

**This cannot be upgraded past UNRESOLVED without a fresh, live check** (Entra portal → that tenant → Users → this account's exact "User type" field) or the original screenshot files, which were not retained in the session workspace.

## Objective D — `oscar` Profile Registry: Directly Inspected (Live Hive Access)
The `oscar` session was found to be **disconnected but not logged off** (`query user` showed session state `Disc`), meaning its `NTUSER.DAT` hive remains loaded live under `HKEY_USERS`. This allowed genuine read-only registry inspection without mounting/loading any offline hive.

**Key findings:**
- **Real classic Outlook MAPI profiles exist** on `oscar` (`"Outlook"`, `"NewOutlook-ProfileForPstFiles-Iter1"`) — the `LENOVO` profile has **zero** Outlook profiles by contrast.
- Decoded MAPI service entries show these profiles configure only: (1) an **iCloud mail connector** (Apple's `APLZOD64.dll`) and (2) a generic **"Outlook Data File" PST** pointing to `Outlook1.pst`. **No live Exchange/Hotmail account is actually configured as an active mail-fetching account** in classic Outlook on this machine.
- **`IdentityCRL\UserTileData`** contains the value name `00064000E2621A80` — this **exactly matches** the `LegacyExchangeDN cn=` value found in `InboxRules.txt`. This is a genuine cross-artifact corroboration linking that Exchange mailbox identity to the `oscar` Windows profile's own account tile cache.
- **Three cached OneAuth account objects found on `oscar`** (vs. one on `LENOVO`):
  - `andrea.lakatos@windowslive.com` — a **fully realized MSA account object**, display name "Andrea Lakatos" — this is a genuinely **separate person's** Microsoft account cached on this shared PC, not an alias of Oscar Kiss.
  - `Admin@OscarKisshotmail465.onmicrosoft.com` — object ID `d12d2bab-5f9c-4ff3-aaf3-081c28997865`, a **third** distinct account object in tenant `c194dd61`, alongside the previously found `Oszkar@...` — relationship between these two same-tenant identities not established.
  - Identity-provider hint files show `pianist_oscer@hotmail.com` classified `MSAccount` (a real Microsoft account type), while `pianist_oscer@outlook.com` and `pianist_oscer@gmail.com` are classified `Neither` — meaning those were **typed into a sign-in box but did not resolve to a valid Microsoft account** at the time. One unusual entry, `60.inner.cordial@icloud.com`, is classified `OrgId` (typed into a work/school sign-in box) — flagged as low-confidence, not confirmed as belonging to the user.

## Objective E — Alias Classification (Corrected)
| Address | Type | Evidence | Classification |
|---|---|---|---|
| `Oscar.Kiss@hotmail.com` | Primary MSA + Exchange-backed consumer mailbox | OneAuth MSA object + Exchange export + UserTileData match | **VERIFIED** |
| `oscar.kiss@outlook.com` | Possible alias | Carried forward only, not re-verified this pass | **INFERRED** |
| `pianist_oscer@outlook.com` | Sign-in attempt only, NOT proven owned | identity-provider hint = `Neither` | **DOWNGRADED — UNRESOLVED** |
| `pianist_oscer@hotmail.com` | MSA sign-in attempt (valid account type) | identity-provider hint = `MSAccount` | **CORROBORATED** (stronger than the outlook.com variant, but still just a hint cache) |
| `Oszkar@OscarKisshotmail465.onmicrosoft.com` | Distinct native Entra member | OneAuth object, `idtyp=user` | **VERIFIED** |
| `Admin@OscarKisshotmail465.onmicrosoft.com` | Distinct Entra account, same tenant | OneAuth object on `oscar` profile | **CORROBORATED** (role/type not captured) |
| `andrea.lakatos@windowslive.com` | Separate person's MSA — **NOT an alias of Oscar Kiss** | Full OneAuth account object | **VERIFIED** |

## Objective F — Exchange Mailbox Correlation: Resolved
The `LegacyExchangeDN` pattern `/o=First Organization/ou=Exchange Administrative Group(FYDIBOHF23SPDLT)/...` is the **standard default-organization identifier used across all Microsoft-hosted Exchange backends**, including the native **consumer Outlook.com/Hotmail mailbox infrastructure** (consumer Hotmail/Outlook.com mailboxes have run on real Exchange Online backend servers since Microsoft's ~2013 consumer-mail migration). Combined with the `UserTileData` registry corroboration on the `oscar` profile, the best-supported conclusion is:

**Mailbox GUID `00064000-e262-1a80-0000-000000000000` is the native consumer Outlook.com/Hotmail mailbox belonging to `Oscar.Kiss@hotmail.com` itself — NOT a Microsoft 365 Business/Exchange-Online-for-business mailbox belonging to any of the three Entra tenants** (`c8553249` / `c194dd61` / `14711b58`). **CORROBORATED.**

## Objective G — Account Creation vs. Historical Use (reaffirmed)
No stronger artifact than the previously found 2014-08-15 message timestamp was located this pass. The correction from the prior pass stands: this is a **message-sent date**, not an account-creation date, and remains the earliest verified **lower bound** of mailbox existence.

## Objective H — Decision Matrix
| Identity | Address/UPN | Type | Tenant | Object ID | Mailbox | Windows SID Link | Evidence Strength | Open Questions |
|---|---|---|---|---|---|---|---|---|
| 1 | `Oscar.Kiss@hotmail.com` | MSA + consumer Exchange mailbox | Personal (`9188040d`) | `b7c7f198a4ce6340` | `00064000-e262-1a80-...` | LENOVO + oscar (both profiles cache this account) | VERIFIED | None major |
| 2 | `Oscar.Kiss@hotmail.com` (guest rep.) | AAD Guest | `c8553249` | `2a8e7ac3-...` | — | LENOVO | VERIFIED (same person, different object) | — |
| 3 | `Oszkar@OscarKisshotmail465.onmicrosoft.com` | AAD native Member | `c194dd61` | `ef8c8bef-...` | — | LENOVO | VERIFIED | Relationship to Admin@ below |
| 4 | `Admin@OscarKisshotmail465.onmicrosoft.com` | AAD (type uncaptured) | `c194dd61` | `d12d2bab-...` | — | oscar | CORROBORATED | Same person as #3, or separate admin identity? |
| 5 | `andrea.lakatos@windowslive.com` | MSA — separate person | Personal | `2fbe37e39361df6e` | — | oscar | VERIFIED | Not part of this investigation's subject |
| 6 | `OscarKisshotmail482` object | Unknown | `23ed74b0-...` | **not captured** | — | — | **UNRESOLVED** | Entirely screenshot-sourced; no local corroboration exists |

## Final Answers
1. **Is `OscarKisshotmail482.onmicrosoft.com` independently verified?** No — zero local artifacts corroborate it; the only source is a prior screenshot-derived checkpoint.
2. **Exact Tenant ID?** `23ed74b0-4708-4f7b-814d-89aa25583f9` (from the screenshot record only).
3. **What exact object represented me there?** Unknown — only the UPN string was captured, no object ID.
4. **Was it really "Member," and what proves it?** Unproven. The UPN itself uses the `#EXT#` guest-naming pattern, contradicting the reported "Member" type label. Most likely explanations: a converted guest-to-member account, or a transcription artifact — cannot be resolved without a fresh live check.
5. **Is it distinct from `Oszkar@OscarKisshotmail465.onmicrosoft.com`?** Yes — different domain (`482` vs `465`), different tenant ID, no shared object ID found anywhere.
6. **Which aliases are true aliases vs. separate accounts?** True same-person aliases: `Oscar.Kiss@hotmail.com` (all its representations). Genuinely **separate accounts**, not aliases: `Oszkar@...465`, `Admin@...465`, and definitively `andrea.lakatos@windowslive.com` (a different person entirely).
7. **Which identity owns Mailbox GUID `00064000-e262-1a80-...`?** `Oscar.Kiss@hotmail.com`'s own native consumer Outlook.com/Hotmail mailbox — not any business tenant.
8. **Did the `oscar` profile reveal an older Microsoft identity?** No identity older than what was already known, but it revealed **additional identities not previously visible from the `LENOVO` profile alone** (`Admin@...465`, `andrea.lakatos@...`, plus sign-in-attempt hints for `pianist_oscer@hotmail.com`/`gmail.com`/`outlook.com`).
9. **Oldest verified identity evidence?** Unchanged: 2014-08-15 message timestamp (lower bound only).
10. **Single most likely artifact to resolve the remaining chain?** A **fresh live Entra portal check** of `OscarKisshotmail482.onmicrosoft.com`'s Users blade for the exact current "User type" and Object ID of the Hotmail-derived account — this is the one piece of evidence that would convert the #1 open contradiction from UNRESOLVED to VERIFIED or DISPROVEN.

---

---

# OSIE BLACK HISTORICAL RECONSTRUCTION (2026-09-29)

**Scope note applied throughout:** per the user's explicit correction, `OscarKisshotmail465.onmicrosoft.com` (tenant `c194dd61`) is treated strictly as RECENT and is NOT used to establish any historical claim in this section. As shown below, this caution turns out to be moot for the Osie Black chain specifically — Osie Black was never linked to that tenant in any captured evidence.

## Earliest Verified Osie Black Evidence
**Date: 2026-07-06T03:09:00Z.** Artifact: `C:\Users\oscar\Downloads\History.json` (browser history export), containing two entries: `"TextPlus Microsoft app"` and `"TextPlus bundle"`. This is the earliest **locally-dated** reference found anywhere to any Osie-Black-organization asset (the TextPlus app). No artifact predating 2026 was found. Classification: **CORROBORATED** (browser history timestamp, not an account-creation date).

## All Osie Black Accounts / Organizations
Kept strictly distinct — only **one** entity was found:
- **Microsoft App Center organization** `Osie Black` (`appcenter.ms/orgs/Osie-Black`) — sole Admin/Collaborator `Oscar.Kiss@hotmail.com`, containing 2 apps (`Mac`, `TextPlus`), linked to 2 Azure subscriptions (`f2aa2ed7-9c32-4b6d-9fa5-cd3284de9ceb`, `57c25f8f-b37a-4455-bae8-6991b87c7213`). **VERIFIED** (screenshot + Azure CLI object-ID cross-match, prior session, commits `a1d6b14`/`3c7c8a3`).
- A separate, **unconfirmed** name-similar lead: `rosie.black@live.ca`, mentioned only in a prior self-inspection log tied to Xbox/App Center metadata — **not** established as the same identity. **UNRESOLVED.**

No evidence was found of Osie Black existing as a WordPress profile, Gravatar identity, GitHub organization, or website owner — see below.

## WordPress Association
**No connection found.** Exhaustive search of both Windows profiles (files, registry, browser history/bookmarks/autofill, email, cached HTML) found **zero** occurrences of "wordpress" tied to the user or Osie Black — the only "wordpress" string hits anywhere on the machine were unrelated developer-tool documentation (Cloudflare/Vercel skill files) and npm package metadata, confirmed irrelevant. Classification: **DISPROVEN locally** (i.e., no supporting evidence exists on this machine; a live WordPress.com/Gravatar account check is the only way to fully rule it in or out).

## `phenomenal` Username
**UNRESOLVED — no supporting artifact found.** The string "phenomenal" appears nowhere on this machine except in the user's own investigative directive text. There is no basis to associate it with Osie Black, WordPress, or any Microsoft identity from local evidence.

## WordPress Sites
None found. `29-WordPress-Sites.csv` is empty of results — no cached site list, no `my.wordpress.com/sites` export, no site ID/slug of any kind was located locally.

## Gravatar Association
None found. No Gravatar hash, avatar URL, or profile reference tied to Osie Black, phenomenal, Oscar Kiss, or Oszkar Kiss exists in any locally accessible artifact.

## App Center Association
**VERIFIED** (carried forward from the prior session's screenshot- and Azure-CLI-confirmed findings, independently corroborated this pass by two new artifacts): the Azure Portal's own local settings cache (`OneDrive\Documents\settings.json` and a prior-session attachment `...-oa settings.json`) contains **user-created saved search filters** literally named "Osie Black" (one keyed by subscription *name*, one by subscription *ID* — `57c25f8f-b37a-4455-bae8-6991b87c7213`, exactly matching one of the two subscriptions already known to be linked under the App Center org's "Manage > Azure" page). The same cache file's `searchHistory` array shows the user typing "Osie black" into the Azure Portal's own search box on two separate occasions. This is strong, independent, non-screenshot corroboration of the org's real, self-managed existence.

## TextPlus Association
**VERIFIED.** TextPlus is one of exactly two applications inside the Osie Black App Center organization (screenshot-confirmed, prior session). Earliest local reference: browser history entries dated 2026-07-06 (see above).

## GitHub Association
**None found.** No local Git repository, GitHub CLI cache, or VS Code GitHub extension state references Osie Black, phenomenal, or TextPlus — other than this investigation's own reporting repository (`oscarkiss-dot/backup-notes`), which is self-referential (created *for* this investigation) and does not count as independent evidence.

## Email Associations
**None found.** No `.eml`/`.msg`/PST-derived artifact anywhere shows "Osie Black" or "phenomenal" used as a From/To/Reply-To display name, signature, or service-notification identity.

## Domains
Only `appcenter.ms` (Microsoft's own SaaS domain, not a personally-registered domain) was found associated with Osie Black. No other domain, WordPress subdomain, or third-party site was found. This reconfirms the earlier-closed finding that "osieblack" was never a registered domain/tenant name (bulk tenant lookup previously returned "Invalid tenant ID or domain").

## Historical Timeline
| Date | Event | Source |
|---|---|---|
| 2026-07-06 | Earliest local TextPlus browser-history reference | `History.json` |
| 2026-09-16 | Azure Activity Log: App Center service principal role-assignment attempts | Prior session, Azure Activity Log |
| 2026-09-18 | Osie Black org, TextPlus/Mac apps, sole-admin status, 2 linked subscriptions all screenshot-confirmed | Commits `a1d6b14`, `3c7c8a3` |
| 2026-09-18 | User directly confirms self-creation ("experimenting with App Center") | Chat record, commit `381dac9` |
| 2026-09-22 | Access-recovery screenshots; tenant `482` first recorded (unrelated finding) | Checkpoint 002 |
| 2026-09-29 | This reconstruction pass — no new dates found, negative WordPress/Gravatar/phenomenal result confirmed | This session |

## Evidence Predating Recent Tenant 465
**None applicable.** Tenant `465` (`c194dd61`) was never linked to Osie Black in any captured evidence — Osie Black's two confirmed subscriptions belong to `c8553249` and a second tenant. The user's recency-caution about tenant `465` therefore does not affect any Osie Black finding.

## Contradictions
See `32-OsieBlack-Contradictions.md` for the full point-by-point analysis. Summary: the App Center/TextPlus chain is solid and closed; the WordPress/phenomenal/Gravatar chain has zero supporting evidence; a name-similar but unverified `rosie.black@live.ca` lead remains open.

## Strongest Identity Chain
```
Oscar.Kiss@hotmail.com
  → [screenshot + Azure CLI object-ID match, 2026-09-18]
  → Sole Admin/Collaborator of App Center org "Osie Black"
  → [screenshot-confirmed app list, 2026-09-18]
  → Owns application "TextPlus"
  → [browser history, 2026-07-06 — earliest known date]
```
No further edges (→ phenomenal → WordPress → site/domain) can be added — each would require evidence that does not exist locally.

---

## REQUIRED FINAL ANSWERS

1. **Oldest VERIFIED occurrence of "Osie Black"?** 2026-07-06 (TextPlus browser-history entries; the org name itself is first screenshot-confirmed 2026-09-18).
2. **Where exactly did it appear?** `C:\Users\oscar\Downloads\History.json` (browser history export) for the earliest date; `appcenter.ms/orgs/Osie-Black` for the organization itself.
3. **Is `phenomenal` VERIFIED as an Osie Black WordPress username?** No — **UNRESOLVED, no supporting evidence found anywhere.**
4. **What artifact proves or suggests that association?** None. Zero co-occurrence of the two terms in any artifact except the user's own directive text.
5. **What WordPress sites are associated with it?** None found.
6. **Is there a Gravatar identity associated with it?** None found.
7. **What email addresses are independently linked to Osie Black?** Only `Oscar.Kiss@hotmail.com` (sole confirmed Admin). A name-similar `rosie.black@live.ca` is an unverified, separate lead.
8. **Is the App Center "Osie Black" organization historically older than tenant `465`?** Cannot be determined precisely (no creation-date artifact for either exists), but it is **moot**: Osie Black was never linked to tenant `465` at all.
9. **What GitHub identities or repositories connect to it?** None, other than this investigation's own self-referential reporting repository.
10. **What domains connect to it?** Only `appcenter.ms` (Microsoft's own domain).
11. **Which findings predate 2026?** None in this Osie Black reconstruction — every dated artifact falls in 2026 (2026-07 through 2026-09).
12. **Which findings predate 2021?** None.
13. **Single strongest artifact connecting two otherwise separate Osie Black identity systems?** The Azure Portal's own local settings cache tying the saved filter name "Osie Black" directly to subscription ID `57c25f8f-...` — the exact same subscription already independently confirmed linked under the App Center org's Azure management page. This connects the "Azure side" and "App Center side" of the same organization via two independent local artifacts.
14. **What is still unproven?** Any WordPress/Gravatar/phenomenal connection (no evidence at all); the org's true creation date; whether `rosie.black@live.ca` is the same identity.
15. **What next READ-ONLY source would most likely produce the breakthrough?** A live, authenticated check of `https://wordpress.com/me` / `https://public-api.wordpress.com/rest/v1/me/` and `https://en.gravatar.com/phenomenal` (if such a WordPress.com account is ever actually signed into on this or another device) — this cannot be performed from local disk artifacts alone, since none exist.

---
