# Synthetic fixtures only. Runs on PowerShell 7 or Windows PowerShell 5.1.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../scripts/Find-AcerRecovery.ps1') -FunctionsOnly
function Assert-That($Condition,[string]$Message) { if (-not $Condition) { throw $Message }; Write-Host "PASS: $Message" }
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('acer-test-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $fixture)
try {
    $mail=Join-Path $fixture 'old.pst';[IO.File]::WriteAllText($mail,'synthetic PST-shaped name only')
    $doc=Join-Path $fixture 'letter.asd';[IO.File]::WriteAllText($doc,'synthetic recovery file')
    $irrelevant=Join-Path $fixture 'application.js';[IO.File]::WriteAllText($irrelevant,'do not execute')
    $hidden=Join-Path $fixture '.hidden.eml';[IO.File]::WriteAllText($hidden,'synthetic hidden message')
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { [IO.File]::SetAttributes($hidden,[IO.FileAttributes]::Hidden) }
    $hash=(Get-FileHash $mail).Hash
    $before=[IO.File]::GetLastWriteTimeUtc($mail)
    Initialize-RecoveryState
    Add-Target $fixture '' 5
    Scan-Target $script:Targets[0]
    Assert-That ($script:Findings.Count -eq 3) 'Finds mail and document candidates without counting generic application code'
    Assert-That (((Get-FileHash $mail).Hash -eq $hash) -and ([IO.File]::GetLastWriteTimeUtc($mail) -eq $before)) 'Source content and modification time preserved'
    Assert-That (@($script:Findings | Where-Object {$_.ContentsRead}).Count -eq 0) 'Inventory does not read file bodies'
    Assert-That (@($script:Findings | Where-Object {$_.Path -eq $hidden}).Count -eq 1) 'Hidden message is included'
    Add-Target $fixture '' 5
    Assert-That ($script:Targets.Count -eq 1) 'Duplicate targets suppressed'
    Scan-Target $script:Targets[0]
    Assert-That ($script:Findings.Count -eq 3) 'Duplicate candidate paths suppressed'
    Scan-Target ([pscustomobject]@{Path=(Join-Path $fixture 'missing');Context='';Depth=5})
    Assert-That (@($script:Statuses | Where-Object {$_.Status -eq 'Missing'}).Count -eq 1) 'Missing path recorded explicitly'
    Assert-That ((Get-RecoveryClass 'Inbox' 'Thunderbird') -like '1 *') 'Extensionless Thunderbird stores are candidates'
    Assert-That ((Get-RecoveryClass 'store.vol' '') -eq '1 Mail database') 'Windows Mail store.vol recognized'
    Assert-That ((Get-RecoveryClass 'rasphone.pbk' '') -eq '3 VPN configuration') 'Windows VPN configuration recognized'
    $sub=Join-Path $fixture 'deep';[void](New-Item -ItemType Directory -Path $sub)
    [IO.File]::WriteAllText((Join-Path $sub 'inside.eml'),'synthetic')
    Initialize-RecoveryState
    Scan-Target ([pscustomobject]@{Path=$fixture;Context='';Depth=0})
    Assert-That (@($script:Statuses | Where-Object {$_.Status -eq 'Depth limit'}).Count -eq 1) 'Depth limit produces incomplete-coverage evidence'
    $link=Join-Path $fixture 'linked'
    try { [void](New-Item -ItemType SymbolicLink -Path $link -Target $sub -ErrorAction Stop) }
    catch { Write-Host 'SKIP: symlink fixture creation needs developer mode or permission on this machine' }
    if (Test-Path -LiteralPath $link) {
        Initialize-RecoveryState
        Scan-Target ([pscustomobject]@{Path=$link;Context='';Depth=5})
        Assert-That ($script:Findings.Count -eq 0 -and @($script:Statuses | Where-Object {$_.Status -eq 'Skipped reparse directory'}).Count -eq 1) 'Reparse directory is not traversed'
    }
    Initialize-RecoveryState
    $script:Entries=$MaxEntries
    Scan-Target ([pscustomobject]@{Path=$fixture;Context='';Depth=5})
    Assert-That ($script:Truncated -and $script:Findings.Count -eq 0) 'Entry budget stops traversal and records truncation'
    Initialize-RecoveryState
    Add-Target '\\server\share' ''
    Assert-That ($script:Targets.Count -eq 0) 'Network targets refused'
    Initialize-RecoveryState
    Scan-Target ([pscustomobject]@{Path=$mail;Context='';Depth=0})
    Assert-That ($script:Findings.Count -eq 1) 'Explicit configured file path is inventoried'
    $errors=$null;$tokens=$null
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../scripts/Find-AcerRecovery.ps1'),[ref]$tokens,[ref]$errors)
    Assert-That ($errors.Count -eq 0) 'Script parses without errors'
} finally { Remove-Item -LiteralPath $fixture -Recurse -Force }
