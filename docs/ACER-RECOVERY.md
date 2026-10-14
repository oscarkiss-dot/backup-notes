# Find existing Windows recovery candidates

Run `scripts/Find-AcerRecovery.ps1` on the Windows computer being examined.
Windows PowerShell 5.1 is the intended Windows runtime; no modules need installing.
This is a discovery tool: it finds surviving stores, messages, documents and settings.
It does not undelete disk sectors, reset accounts, repair databases or restore mail.

## Run

Download the script using GitHub's **Download raw file** button into Downloads.
Open Windows PowerShell as the normal user first, then:

```powershell
& "$env:USERPROFILE\Downloads\Find-AcerRecovery.ps1"
```

The new Desktop folder `AcerRecovery-<time>-<suffix>` contains `START-HERE.txt`
and `acer-recovery.json`. Share the JSON privately to select the next original files
for inspection. Never commit reports or originals to this public repository.
If PowerShell blocks the script, retain the exact error; this tool does not alter
execution policy, remove access restrictions, or ask for administrator rights.

Optional: write reports to an existing external folder:

```powershell
& "$env:USERPROFILE\Downloads\Find-AcerRecovery.ps1" -OutputRoot 'E:\RecoveryReports'
```

Use the actual drive and folder, not the example. For a console-only inventory,
add `-ConsoleOnly` (no report files; shows the first 25 candidates and coverage issues).
For a selected nonstandard backup or additional local location, use
`-AdditionalRoots 'D:\OldBackup'`. The default scan budget is approximately five
minutes, 300,000 entries and 25,000 candidates. A single directory or registry
operation can exceed the time budget; it is not a hard process timeout.

## Search order and interpretation

| Source | Why check it | Limits |
|---|---|---|
| Documents\Outlook Files; AppData\Local\Microsoft\Outlook; configured Outlook file paths | PST/OST stores and companions | File extension/size alone cannot establish messages are present |
| AppData\Local\Comms, including UnistoreDB/Unistore; Windows Mail and Windows Live Mail folders | Alternative old Mail storage, even if package LocalState is empty | Presence/content varies by app version; databases and companions need consistent copies |
| Accessible Windows profiles, ProfileList and Windows.old\Users | An older Windows profile may hold a different data set | Unavailable profiles are reported; no taking ownership or loading registry hives |
| Word/Excel/PowerPoint recovery folders, UnsavedFiles, OfficeFileCache, Outlook attachment cache | Surviving document copies and recovery files | A cache record may not be a complete document |
| Recycle Bin, FileHistory and WindowsImageBackup on available fixed/removable drives | Potential retained files or backups | Does not interpret Recycle Bin original names or mount backup images |
| Windows VPN PBK, OpenVPN and WireGuard configuration locations | Existing connection settings | Does not read secret contents, decrypt settings or recover deleted VPN profiles |
| OneDrive configured roots and settings; current user's Office registry settings | Redirected document paths and stored account/path leads | Stored account values are not sign-in events, current access, or ownership proof |
| Recent items, legacy Edge backups, selected Chromium History/Bookmarks/Preferences, Thunderbird | Leads to filenames, original storage or other mail clients | Inventory only; does not collect cookies, passwords or browser authentication databases |

Hidden files are included. Directory junctions, symlinks and other reparse directories
are skipped and reported; this can also exclude OneDrive cloud directories. Offline
files are listed by metadata without opening their content. Cloud-only results must be
handled through the provider. The scanner makes no explicit network requests and
refuses UNC scan roots; Windows itself may perform background activity.

HKCU registry inspection is limited to Office/profile/OneDrive/shell-folder branches.
Only selected account fields and local candidate paths enter the report. No complete
registry export, Credential Manager extraction, password dumping, cookie/token reading,
process termination, repair, app launch, sync reset, service changes or source copies
occur. Source metadata reads do not constitute forensic write-blocking: Windows and
other applications can still write to the live disk.

`Scanned` means enumeration completed within configured scope, not that all data was
recoverable. Missing, access denied, enumeration failures, depth limits and budget
limits are reported separately. Empty roots and roots with no matching candidates
can both have zero new candidates. File modification/creation times are filesystem
metadata, never verified historical sign-in or subscription dates. Numeric priority
is a heuristic; actual contents must be examined before deciding what to restore.

## Recovery decision after the scan

1. Inspect a copy of the best PST/OST/mail store first; determine actual item counts,
   account references, dates and attachments. Preserve originals. An OST is not
   automatically importable as a PST, and reconnecting it may change cached data.
2. For locked/live databases, arrange a consistent copy with all required companion
   files before parsing. Do not run database repair on the only copy.
3. For document recovery files, preserve a copy before opening or converting it.
4. If only traces remain, use existing backups/cloud recycle bins and version history.
5. If actual deleted-sector recovery is needed, minimize use of the source drive and
   recover to another device. Installing tools or writing recovered data on the
   affected drive can overwrite recoverable data. This finder is not that recovery step.

## Validation

```powershell
pwsh -NoProfile -File tests/test_acer_recovery.ps1
```

Sixteen synthetic assertions passed with PowerShell 7.6.7 on Linux. They cover source
content/modification-time preservation, classification, missing paths, de-duplication,
scan limits, reparse-directory handling, network-root refusal and parsing.
Windows PowerShell 5.1 compatibility was considered while writing the script; actual
Windows registry/CIM/cloud behavior has not been executed in this environment.
The symlink assertion skips on Windows if fixture creation lacks permission.

## Primary references

- [Microsoft: Outlook PST/OST locations](https://support.microsoft.com/en-us/outlook/create-an-outlook-data-file-pst-to-save-your-information)
- [Microsoft: document recovery paths](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/recover-lost-unsaved-corrupted-document)
- [Microsoft: Get-ChildItem, hidden files and attributes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem?view=powershell-5.1)

Other paths are explicit discovery candidates, not a claim that those products or
accounts were used on a particular device. No private evidence is included here.
