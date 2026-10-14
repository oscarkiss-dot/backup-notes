# Exchange tracing and recovery

This is the operational replacement for the proposed October 13 subscription-trace
runbook. It separates local evidence, current domain discovery and account recovery.
The script collects leads; it does not recover a mailbox or grant access.

## Start with existing evidence

Use an original invoice, subscription welcome email, old Outlook account configuration,
or support response that actually names the account. A bank charge alone rarely identifies
a tenant. A note about an old email is a secondary source; retain the original email.
The repository's earlier notes are useful leads, but their labels such as "confirmed"
are not independent verification in a new investigation.

Do not substitute a recently created tenant for a historical one. A current tenant-domain
mapping does not show that a mailbox existed there in 2019, 2020 or 2021. Keep the date
of the source artifact separate from the date on which it was inspected. Even an EML
Date header is a claim until corroborated by trusted Received headers or provider records.

Run from the downloaded repository on a computer with Python 3.9 or newer. Windows:

```powershell
py -3 scripts/trace_exchange.py --evidence "C:\Evidence\old-invoice.eml" --output "$env:USERPROFILE\Desktop\exchange-trace-01"
```

macOS/Linux: replace `py -3` with `python3` and use the appropriate paths. Repeat
`--evidence` for additional files. Inputs are read only. Each output folder must be new.

The local `trace.json` records source path, SHA-256, inspection time, identifier occurrences
and billing-keyword locations. `summary.md` explains collection status. Emails and GUIDs
are unclassified leads, not automatically owned accounts or tenants. MIME text is decoded;
attachments are not opened. Line numbers refer to the named decoded section, not necessarily
the raw EML. Full bodies and card numbers are not copied into the report. Reports still
contain personal identifiers and must be shared privately.

Supported: UTF-8/UTF-16 text, Markdown, JSON, CSV and EML, up to 10 MiB per file. This is
not a full filesystem scan, OCR, PDF reader, PST/OST reader, encrypted-mail reader or a
complete parser for every exported data format. Unsupported/missing inputs are reported.

## Optional current public discovery

Use only an exact domain or canonical tenant UUID grounded in evidence for your account.
The tool never queries identifiers extracted from files automatically.
Truncated or malformed UUIDs must be checked against the original source, never guessed.

```powershell
py -3 scripts/trace_exchange.py --domain "example.onmicrosoft.com" --online --dns --output "$env:USERPROFILE\Desktop\exchange-trace-02"
```

Replace the example before running. Repeat `--domain` for additional known targets.
`--online` permits public OIDC GET requests to Microsoft. `--dns` additionally sends
MX/TXT queries through your configured DNS resolver using `nslookup`, if installed.
Without those options, file inspection makes no network requests. No sign-in occurs.
Discovery redirects are refused; request errors remain unknown rather than "deleted".
Exit code 2 means an incomplete check; read the report before drawing conclusions.
DNS stdout is retained locally without automatic interpretation, including when the
utility exits successfully but reports no records.

| Observation | Supported interpretation | What it does not establish |
|---|---|---|
| Valid tenant UUID in Microsoft OIDC issuer | Current public authority metadata for that target | Mailbox, subscription, owner, role or historical use |
| Shared Microsoft consumer authority | Consumer authentication service | A business tenant owned by the user |
| MX ending in `mail.protection.outlook.com` | Microsoft mail-routing/protection configuration | An Exchange Online mailbox; hybrid/protection-only setups exist |
| `MS=ms...` TXT record | A Microsoft verification token is published | Verification completed, current ownership or admin access |
| No TXT token | No token in that response | No Microsoft tenant; verification tokens can be removed |
| Error/timeout/no result | That check did not establish the fact | Tenant or mailbox deletion |
| `#EXT#` UPN | An external identity representation to investigate | A separate mailbox or a password to reset directly |
| An account named `Admin` | A name recorded in an artifact | A Global Administrator role |

This implementation intentionally omits `getuserrealm.srf`: it is not needed for the
documented OIDC discovery flow and must not be treated as mailbox-existence verification.
Shared provider domains such as hotmail.com cannot identify a customer's business tenant.
For custom domains the shared-provider blocklist is only a convenience, not exhaustive.

## Choose the recovery route after identifying the account

1. **Personal Outlook.com/Hotmail:** use Microsoft's personal-account sign-in helper.
   Seeing Exchange server names in personal mailbox artifacts does not itself establish
   a separate business subscription. Business admin resets do not reset the consumer account.
2. **Known work/school account:** follow Microsoft's work/school reset instructions.
   Self-service reset depends on the organization's configuration and registered security
   information. "Contact your administrator" does not identify the admin, prove the user
   is not an admin, or prove there is only one user. Do not guess `Admin@...` identities.
3. **Existing authorized administrator:** confirm the exact tenant and role first.
   Reset authority is role-dependent; not every admin can reset every other admin.
   An Azure subscription Owner role is not the same as an Entra Global Administrator.
   A Member user type is not an admin-role assignment. Tenant visibility is not mailbox access.
4. **No working administrator sign-in:** use Microsoft 365 business support's current
   contact route and describe the access problem accurately. Supply the original tenant/domain,
   verified account, product and invoice/order references if available. Ask what ownership
   verification and recovery process applies. A payment method alone does not guarantee
   recovery; "billing only, never technical support" is not a universal rule.
5. **Reseller purchase:** use the provider identified on the actual receipt for product
   and account support. Domain registration with a reseller alone does not prove the
   mailbox was purchased there or that the reseller is the only administrator.

The documented DNS admin-takeover procedure is for an **unmanaged directory**. It is
not a general workaround for a locked managed tenant. Do not change DNS, create tenants,
change federation, reset MFA or move a domain merely to trace historical evidence.

## Evidence to collect privately for the next decision

| Field | Record |
|---|---|
| Source | Original filename, SHA-256, relevant page/section and who supplied it |
| Dates | Source event date, inspection time, timezone, and confidence |
| Account | Exact personal sign-in or work/school UPN, as actually shown |
| Tenant | Full domain and valid UUID, plus source; leave unknown fields blank |
| Product | Exact billed product, reseller, order/subscription reference, billing period |
| Role | Role assignment in the target tenant, not display name or Member/Guest type |
| Sign-in evidence | Timestamp/timezone, account, tenant, app/resource, auth method, device/browser, IP/location, result/error, correlation ID and request ID; only values actually available |
| Historical link | Evidence tying the desired older mailbox to this tenant, with source date |
| Outcome | Verified observation, secondary report, inference or unresolved lead |

Keep passwords, MFA codes, recovery codes, cookies, tokens and full payment details out
of reports. The public repository is for source code and fabricated examples. `.gitignore`
only protects matching untracked files; it does not remove already committed information.

## Coordination with the existing mail-indexing pull request

The separate `recover_mail.py` proposal processes `.eml` files that already exist in a
directory or ZIP. It is downstream of obtaining a real export/recovered file set; it
does not unlock Exchange or undelete server-side messages. This PR neither changes nor
merges that proposal. Review and validate it separately with synthetic data before use.

## Official references checked October 13, 2026

- [Microsoft identity platform OIDC discovery](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)
- [Admin takeover of an unmanaged directory](https://learn.microsoft.com/en-us/entra/identity/users/domains-admin-takeover)
- [Microsoft 365 business support](https://learn.microsoft.com/en-us/microsoft-365/admin/get-help-support?view=o365-worldwide)
- [Work/school password reset](https://support.microsoft.com/en-us/accounts-billing/work-school/reset-your-microsoft-work-or-school-account-password-using-security-info)
- [Personal Microsoft account sign-in helper](https://support.microsoft.com/en-us/accounts-billing/manage/microsoft-account-sign-in-helper)
- [Microsoft DNS setup and verification](https://learn.microsoft.com/en-us/microsoft-365/admin/get-help-with-domains/create-dns-records-at-any-dns-hosting-provider?view=o365-worldwide)
- [Exchange Online and Exchange Server licensing FAQ](https://www.microsoft.com/en-us/microsoft-365/exchange/microsoft-exchange-licensing-faq-email-for-business)
- [Microsoft Entra built-in role permissions](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [Azure roles versus Microsoft Entra roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/rbac-and-directory-admin-roles)
