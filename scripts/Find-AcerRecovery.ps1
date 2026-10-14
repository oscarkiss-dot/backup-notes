#requires -Version 5.1
<#
Find existing recovery candidates without modifying source files.
No file bodies, passwords, cookies, credentials, or token caches are collected.
Writes only a new report directory. -ConsoleOnly avoids report files.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = [Environment]::GetFolderPath('Desktop'),
    [string[]]$AdditionalRoots = @(),
    [switch]$ConsoleOnly,
    [ValidateRange(30,3600)][int]$MaxSeconds = 300,
    [ValidateRange(1000,2000000)][int]$MaxEntries = 300000,
    [ValidateRange(100,100000)][int]$MaxResults = 25000,
    [switch]$FunctionsOnly
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-RecoveryClass {
    param([string]$Path, [string]$Context = '')
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $name = [IO.Path]::GetFileName($Path)
    if ($ext -in @('.pst','.ost','.eml','.msg','.mbox','.mbx','.dbx')) { return '1 Mail store or message' }
    if ($name -in @('store.vol','WindowsMail.MSMessageStore')) { return '1 Mail database' }
    if ($Context -eq 'Mail') { return '1 Mail storage companion' }
    if ($ext -in @('.asd','.wbk','.xlk') -or $Context -eq 'AutoRecover') { return '2 Document recovery candidate' }
    if ($ext -in @('.pbk','.ovpn') -or $Context -eq 'VPN') { return '3 VPN configuration' }
    if ($Context -eq 'Recycle') { return '2 Recycle Bin candidate' }
    if ($ext -in @('.doc','.docx','.docm','.xls','.xlsx','.xlsm','.ppt','.pptx','.pdf','.odt','.ods','.rtf','.one')) { return '2 Document' }
    if ($Context -eq 'Backup' -or $ext -in @('.vhd','.vhdx','.bkf')) { return '2 Backup candidate' }
    if ($Context -in @('Attachment','DocumentCache')) { return '2 Cached document candidate' }
    if ($Context -eq 'Settings') { return '3 Account or application settings' }
    if ($Context -eq 'Thunderbird' -and -not $ext -and $name -notin @('lock','parent.lock')) { return '1 Possible Thunderbird mail store' }
    if ($Context -eq 'Thunderbird' -and $name -eq 'prefs.js') { return '3 Account or application settings' }
    if ($Context -eq 'History') { return '4 File or browser history lead' }
    if ($ext -eq '.zip') { return '4 Archive candidate' }
    return $null
}
function Add-ScanStatus {
    param([string]$Path,[string]$Status,[string]$Detail = '')
    if ($script:Statuses.Count -lt 15000) {
        $script:Statuses.Add([pscustomobject]@{Path=$Path;Status=$Status;Detail=$Detail})
    } else { $script:StatusOverflow = $true }
}
function Test-ScanBudget {
    if ($script:Watch.Elapsed.TotalSeconds -gt $MaxSeconds -or $script:Entries -ge $MaxEntries -or $script:Findings.Count -ge $MaxResults) {
        $script:Truncated = $true
        return $false
    }
    return $true
}
function Add-Target {
    param([string]$Path,[string]$Context,[int]$Depth=12)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $Path = [Environment]::ExpandEnvironmentVariables($Path)
    if ($Path.StartsWith('\\')) { Add-ScanStatus $Path 'Skipped network path'; return }
    try { $Path = [IO.Path]::GetFullPath($Path) } catch { Add-ScanStatus $Path 'Invalid path' $_.Exception.Message; return }
    $key = $Path.TrimEnd('\','/')
    if (-not $script:TargetKeys.Add($key)) { return }
    $script:Targets.Add([pscustomobject]@{Path=$Path;Context=$Context;Depth=$Depth})
}
function Add-Finding {
    param($Item,[string]$Context)
    $class = Get-RecoveryClass $Item.FullName $Context
    if (-not $class) { return }
    $key = $Item.FullName
    if ($script:FindingKeys.ContainsKey($key)) {
        $old=$script:FindingKeys[$key]
        if ([string]::CompareOrdinal($class,$old.Category) -lt 0) { $old.Category=$class }
        return
    }
    $flags=[int64]$Item.Attributes
    $row=[pscustomobject]@{
        Category=$class;Path=$key;Bytes=$Item.Length
        ModifiedUtc=$Item.LastWriteTimeUtc.ToString('o');CreatedUtc=$Item.CreationTimeUtc.ToString('o')
        Attributes=$Item.Attributes.ToString()
        CloudOrOffline=(($flags -band 0x1000) -ne 0 -or ($flags -band 0x40000) -ne 0 -or ($flags -band 0x400000) -ne 0)
        ContentsRead=$false
    }
    $script:Findings.Add($row);$script:FindingKeys[$key]=$row
}
function Scan-Target {
    param($Target)
    if (-not (Test-ScanBudget)) { Add-ScanStatus $Target.Path 'Not scanned: limit reached'; return }
    try { $root=Get-Item -LiteralPath $Target.Path -Force -ErrorAction Stop }
    catch {
        $kind='Unavailable'
        if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { $kind='Missing' }
        elseif ($_.CategoryInfo.Category -eq 'PermissionDenied') { $kind='Access denied' }
        Add-ScanStatus $Target.Path $kind $_.Exception.Message; return
    }
    if (-not $root.PSIsContainer) { Add-Finding $root $Target.Context; Add-ScanStatus $Target.Path 'File inventoried'; return }
    $stack=New-Object 'System.Collections.Generic.Stack[object]'
    $stack.Push([pscustomobject]@{Item=$root;Depth=0})
    $countBefore=$script:Findings.Count
    $incomplete=$false
    while ($stack.Count -gt 0) {
        if (-not (Test-ScanBudget)) { $incomplete=$true;break }
        $node=$stack.Pop();$d=$node.Item
        if (($d.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Add-ScanStatus $d.FullName 'Skipped reparse directory' 'May be a junction, link or cloud folder; contents not searched.';$incomplete=$true;continue
        }
        if ($d.FullName -match '(?i)(^|[\\/])(AcerRecovery-\d|\.git)([^\\/]*)([\\/]|$)') { continue }
        try {
            $children=@(Get-ChildItem -LiteralPath $d.FullName -Force -ErrorAction Stop)
            foreach ($child in $children) {
                if (-not (Test-ScanBudget)) { $incomplete=$true;break }
                $script:Entries++
                if ($child.PSIsContainer) {
                    if ($node.Depth -lt $Target.Depth) { $stack.Push([pscustomobject]@{Item=$child;Depth=($node.Depth+1)}) }
                    else { Add-ScanStatus $child.FullName 'Depth limit';$incomplete=$true }
                } else { Add-Finding $child $Target.Context }
            }
        } catch { Add-ScanStatus $d.FullName 'Enumeration failed' $_.Exception.Message;$incomplete=$true }
    }
    $status='Scanned'
    if ($incomplete) { $status='Partial' }
    Add-ScanStatus $Target.Path $status ("New candidates: " + ($script:Findings.Count-$countBefore))
}
function Add-ProfileTargets {
    param([string]$Profile)
    # Specific stores first, then wider user folders. No WebServiceCache scan.
    foreach ($rel in @('AppData\Local\Microsoft\Outlook','Documents\Outlook Files','AppData\Local\Comms','AppData\Local\Microsoft\Windows Mail','AppData\Local\Microsoft\Windows Live Mail')) { Add-Target (Join-Path $Profile $rel) 'Mail' 16 }
    foreach ($rel in @('AppData\Local\Microsoft\Office\UnsavedFiles','AppData\Roaming\Microsoft\Word','AppData\Roaming\Microsoft\Excel','AppData\Roaming\Microsoft\PowerPoint')) { Add-Target (Join-Path $Profile $rel) 'AutoRecover' 10 }
    foreach ($rel in @('AppData\Local\Microsoft\Windows\INetCache\Content.Outlook','AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook')) { Add-Target (Join-Path $Profile $rel) 'Attachment' 10 }
    foreach ($v in @('14.0','15.0','16.0')) { Add-Target (Join-Path $Profile "AppData\Local\Microsoft\Office\$v\OfficeFileCache") 'DocumentCache' 8 }
    Add-Target (Join-Path $Profile 'AppData\Roaming\Microsoft\Network\Connections\Pbk') 'VPN' 8
    Add-Target (Join-Path $Profile 'OpenVPN\config') 'VPN' 8
    Add-Target (Join-Path $Profile 'AppData\Local\Microsoft\FileHistory\Configuration') 'Backup' 6
    Add-Target (Join-Path $Profile 'AppData\Roaming\Microsoft\Outlook') 'Settings' 6
    Add-Target (Join-Path $Profile 'AppData\Local\Microsoft\OneDrive\settings') 'Settings' 6
    Add-Target (Join-Path $Profile 'AppData\Roaming\Microsoft\Windows\Recent') 'History' 5
    Add-Target (Join-Path $Profile 'MicrosoftEdgeBackups') 'History' 12
    foreach ($rel in @('Documents','Desktop','Downloads','AppData\Local\Temp')) { Add-Target (Join-Path $Profile $rel) '' 16 }
    Add-Target (Join-Path $Profile 'AppData\Roaming\Thunderbird\Profiles') 'Thunderbird' 16
    foreach ($rel in @('AppData\Local\Microsoft\Edge\User Data','AppData\Local\Google\Chrome\User Data')) {
        $browserRoot=Join-Path $Profile $rel
        try {
            foreach ($b in Get-ChildItem -LiteralPath $browserRoot -Directory -Force -ErrorAction Stop) {
                if ($b.Name -eq 'Default' -or $b.Name -like 'Profile *') {
                    foreach ($name in @('History','Bookmarks','Preferences')) { Add-Target (Join-Path $b.FullName $name) 'History' 0 }
                }
            }
        } catch { Add-ScanStatus $browserRoot 'Browser discovery unavailable' $_.Exception.Message }
    }
    try {
        $local=Join-Path $Profile 'AppData\Local\Packages'
        foreach ($p in Get-ChildItem -LiteralPath $local -Directory -Force -ErrorAction Stop) {
            if ($p.Name -like 'microsoft.windowscommunicationsapps_*' -or $p.Name -like 'Microsoft.OutlookForWindows_*') {
                foreach ($rel in @('LocalState','LocalCache','Settings')) { Add-Target (Join-Path $p.FullName $rel) 'Settings' 12 }
            }
        }
    } catch { Add-ScanStatus $local 'Package discovery unavailable' $_.Exception.Message }
    try {
        foreach ($d in Get-ChildItem -LiteralPath $Profile -Directory -Force -ErrorAction Stop) {
            if ($d.Name -match '^(OneDrive|Dropbox|iCloudDrive)') { Add-Target $d.FullName '' 16 }
        }
    } catch { Add-ScanStatus $Profile 'Profile discovery incomplete' $_.Exception.Message }
}
function Read-RegistryLeads {
    # HKCU only. No offline hive loading, credential values or wholesale registry exports.
    $roots=@('HKCU:\Software\Microsoft\Office','HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles','HKCU:\Software\Microsoft\OneDrive\Accounts','HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
    foreach ($r in $roots) {
        try {
            if (-not (Test-Path -LiteralPath $r)) { Add-ScanStatus $r 'Missing';continue }
            $keys=@(Get-Item -LiteralPath $r)
            if ($r -notlike '*User Shell Folders') { $keys+=@(Get-ChildItem -LiteralPath $r -Recurse -ErrorAction Stop | Select-Object -First 5000) }
            foreach ($k in $keys) {
                if (-not (Test-ScanBudget)) { break }
                if ($k.Name -notmatch '(?i)(Outlook|Profiles|Identities|OneDrive\\Accounts|User Shell Folders|Word\\Options|Excel\\Options|PowerPoint\\Options|File MRU|Place MRU)') { continue }
                foreach ($name in $k.GetValueNames()) {
                    if ($name -match '(?i)(password|secret|token|credential)') { continue }
                    $raw=$k.GetValue($name)
                    $text=$null
                    if ($raw -is [string]) { $text=$raw }
                    elseif ($raw -is [byte[]] -and $raw.Length -lt 16384) { $text=[Text.Encoding]::Unicode.GetString($raw).Trim([char]0) }
                    if (-not $text) { continue }
                    if ($name -match '^(Email|EmailAddress|UserEmail|UserName|ADUserName|TenantId|DisplayName|SMTP Address|SMTP Email Address)$' -and $raw -is [string]) {
                        $script:RegistryLeads.Add([pscustomobject]@{Key=$k.Name;Name=$name;Value=$text;Meaning='Stored setting, not proof of current login or ownership'})
                    }
                    # Exact local paths or MRU paths. Never follow UNC paths or URLs.
                    $expanded=[Environment]::ExpandEnvironmentVariables($text)
                    $m=[regex]::Match($expanded,'(?i)[A-Z]:\\[^\x00\r\n]*?\.(pst|ost|asd|wbk)(?=$|[\x00\r\n])')
                    if ($m.Success) { Add-Target $m.Value ''; $script:RegistryLeads.Add([pscustomobject]@{Key=$k.Name;Name=$name;Value=$m.Value;Meaning='Configured file path; existence checked separately'}) }
                    if ($name -match '^(Personal|Desktop|UserFolder|AutoRecoverPath|AUTOSAVE-PATH)$' -and $expanded -match '^[A-Za-z]:\\') {
                        Add-Target $expanded '' 16
                        $script:RegistryLeads.Add([pscustomobject]@{Key=$k.Name;Name=$name;Value=$expanded;Meaning='Configured folder'})
                    }
                }
            }
        } catch { Add-ScanStatus $r 'Registry read incomplete' $_.Exception.Message }
    }
}
function Initialize-RecoveryState {
    $script:Targets=New-Object 'System.Collections.Generic.List[object]'
    $script:TargetKeys=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $script:Findings=New-Object 'System.Collections.Generic.List[object]'
    $script:FindingKeys=@{}
    $script:Statuses=New-Object 'System.Collections.Generic.List[object]'
    $script:RegistryLeads=New-Object 'System.Collections.Generic.List[object]'
    $script:Entries=0;$script:Truncated=$false;$script:StatusOverflow=$false
    $script:Watch=[Diagnostics.Stopwatch]::StartNew()
}
if ($FunctionsOnly) { return }
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Run this tool on the Windows computer being examined.' }
Initialize-RecoveryState
$scanStarted=[DateTime]::UtcNow.ToString('o')
Write-Host 'Finding existing recovery candidates. No source file contents will be opened.'
$profiles=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
[void]$profiles.Add($env:USERPROFILE)
foreach ($base in @((Join-Path $env:SystemDrive 'Users'),(Join-Path $env:SystemDrive 'Windows.old\Users'))) {
    try {
        foreach ($p in Get-ChildItem -LiteralPath $base -Directory -Force -ErrorAction Stop) {
            if (($p.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $p.Name -notin @('Default','Default User','All Users')) { [void]$profiles.Add($p.FullName) }
        }
    } catch { Add-ScanStatus $base 'Profile discovery unavailable' $_.Exception.Message }
}
try {
    foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') {
        $p=Get-ItemProperty -LiteralPath $k.PSPath -Name ProfileImagePath
        $expanded=[Environment]::ExpandEnvironmentVariables($p.ProfileImagePath)
        if ($expanded -notmatch '(?i)\\(system32|ServiceProfiles)\\') { [void]$profiles.Add($expanded) }
    }
} catch { Add-ScanStatus 'ProfileList' 'Profile registry unavailable' $_.Exception.Message }
foreach ($p in $profiles) { Add-ProfileTargets $p }
Read-RegistryLeads
Add-Target (Join-Path $env:ProgramData 'Microsoft\Network\Connections\Pbk') 'VPN' 8
foreach ($base in @($env:ProgramFiles,${env:ProgramFiles(x86)})) {
    if ($base) { Add-Target (Join-Path $base 'OpenVPN\config') 'VPN' 8;Add-Target (Join-Path $base 'WireGuard\Data\Configurations') 'VPN' 6 }
}
$drives=@()
try {
    $drives=@(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in @(2,3) -and $_.Size -gt 0 } | Select-Object DeviceID,DriveType,Size,FreeSpace)
    foreach ($d in $drives) {
        Add-Target ($d.DeviceID+'\$Recycle.Bin') 'Recycle' 8
        Add-Target ($d.DeviceID+'\FileHistory') 'Backup' 20
        Add-Target ($d.DeviceID+'\WindowsImageBackup') 'Backup' 12
    }
} catch { Add-ScanStatus 'Local drives' 'Drive discovery unavailable' $_.Exception.Message }
foreach ($p in $AdditionalRoots) { Add-Target $p '' 20 }
foreach ($t in $script:Targets) {
    Write-Progress -Activity 'Finding recovery candidates' -Status $t.Path
    Scan-Target $t
}
Write-Progress -Activity 'Finding recovery candidates' -Completed
$shadows=@()
try { $shadows=@(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Select-Object ID,InstallDate,VolumeName,DeviceObject) }
catch { Add-ScanStatus 'Shadow copies' 'Snapshot query unavailable' $_.Exception.Message }
$ordered=@($script:Findings | Sort-Object Category,@{Expression='Bytes';Descending=$true})
$report=[ordered]@{
    Version='1.0';StartedUtc=$scanStarted;FinishedUtc=[DateTime]::UtcNow.ToString('o')
    Scope='Existing local files: metadata only; no deleted-sector scan or automatic restoration'
    Profiles=@($profiles);Drives=$drives;ShadowCopies=$shadows
    Limits=@{Seconds=$MaxSeconds;Entries=$MaxEntries;Results=$MaxResults;Reached=$script:Truncated;StatusOverflow=$script:StatusOverflow}
    EntriesExamined=$script:Entries;Candidates=$ordered;RegistryLeads=@($script:RegistryLeads.ToArray());Coverage=@($script:Statuses.ToArray())
    Notes=@('No source contents read. Cloud placeholders not downloaded. Reparse directories skipped.', 'Missing, access-denied and partial paths are distinct. No hit does not prove deletion.', 'File timestamps are metadata, not verified account activity. Priority is heuristic.', 'Locked stores need a consistent copy before parsing; keep database companion files together.', 'No passwords, cookies, tokens or Credential Manager secrets collected. Reports contain private paths and account names.')
}
Write-Host ("Candidates: {0}; Entries examined: {1}; Limit reached: {2}" -f $ordered.Count,$script:Entries,$script:Truncated)
$ordered | Select-Object -First 25 Category,Bytes,Path | Format-Table -AutoSize -Wrap | Out-Host
if ($ConsoleOnly) {
    Write-Host 'ConsoleOnly: no report files written. Coverage issues:'
    $script:Statuses | Where-Object {$_.Status -notin @('Scanned','Missing','File inventoried')} | Format-Table -Wrap | Out-Host
} else {
    if (-not (Test-Path -LiteralPath $OutputRoot -PathType Container)) { throw 'OutputRoot must be an existing folder.' }
    $out=Join-Path $OutputRoot ('AcerRecovery-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6))
    [void](New-Item -ItemType Directory -Path $out)
    $report | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath (Join-Path $out 'acer-recovery.json') -Encoding UTF8
    $lines=@('ACER RECOVERY CANDIDATES - CONTENTS NOT YET VERIFIED',"Started UTC: $scanStarted",'Report only. Originals have not been copied or restored.','')
    foreach ($row in ($ordered | Select-Object -First 60)) { $lines+=('{0} | {1:N0} bytes | {2}' -f $row.Category,$row.Bytes,$row.Path) }
    $lines+=@('','Read acer-recovery.json for full results and incomplete/missing paths.','Keep reports private; do not commit them to GitHub.')
    $lines | Set-Content -LiteralPath (Join-Path $out 'START-HERE.txt') -Encoding UTF8
    Write-Host "Report saved: $out"
    Write-Host 'Upload acer-recovery.json privately for selection of files to recover.'
}
