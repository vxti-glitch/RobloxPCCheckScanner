

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$Host.UI.RawUI.WindowTitle = 'PC Check Scanner  |  vxti'
try { $Host.UI.RawUI.BufferSize = [Management.Automation.Host.Size]::new(200, 9999) } catch {}
try { $Host.UI.RawUI.WindowSize = [Management.Automation.Host.Size]::new(160, 45)  } catch {}


Add-Type -MemberDefinition @'
[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@ -Name 'K32' -Namespace 'Win32' -EA SilentlyContinue

$script:DeviceMap = @{}
try {
    foreach ($letter in [Environment]::GetLogicalDrives()) {
        $l  = $letter.TrimEnd('\')
        $sb = New-Object System.Text.StringBuilder 300
        [void][Win32.K32]::QueryDosDevice($l, $sb, 300)
        if ($sb.Length -gt 0) { $script:DeviceMap[$sb.ToString()] = $l }
    }
} catch {}

function Resolve-Path2([string]$p) {
    if (-not $p) { return $p }
   
    if ($p -match '^[A-Za-z]:\\') { return $p }
   
    if ($p -match '^\\Device\\') {
        foreach ($dev in $script:DeviceMap.Keys) {
            if ($p.StartsWith($dev, [StringComparison]::OrdinalIgnoreCase)) {
                return $script:DeviceMap[$dev] + $p.Substring($dev.Length)
            }
        }
    }
    return $p
}


$script:CritList = [Collections.Generic.List[pscustomobject]]::new()
function Add-Crit([string]$ph, [string]$lbl, [string]$val) {
    $script:CritList.Add([pscustomobject]@{ Phase = $ph; Label = $lbl; Value = $val })
}


$BL  = @('Wave','Velocity','Potassium','Volcano','Xeno','Seliware','Volt','SirHurt',
         'Solara','Bunni','Synapse','isabelle','DX9WARE','Photon','MatrixHub','Ronin',
         'Matcha','Serotonin','Severe','RbxCli','loader','Executor','Injector','Sploit','autoexc','workspace')
$BLP = ($BL | ForEach-Object { [regex]::Escape($_) }) -join '|'
function Test-BL([string]$s) { return ($s -match $BLP) }


function Get-Sig([string]$rawPath) {
    $p = Resolve-Path2 $rawPath
    if (-not $p)                                                      { return 'NoPath'    }
    if (-not (Test-Path -LiteralPath $p -PathType Leaf -EA SilentlyContinue)) { return 'NotOnDisk' }
    try   { return (Get-AuthenticodeSignature -LiteralPath $p -EA Stop).Status }
    catch { return 'Error' }
}


$C = @{
    Border='DarkCyan'; Accent='Cyan'; Header='White'
    OK='Green'; Warn='Yellow'; Crit='Red'; Muted='DarkGray'; Dim='Gray'
}


$BW = 155  

function _b { Write-Host "  +$('=' * $BW)+" -ForegroundColor $C.Border }
function _e { Write-Host "  +$('=' * $BW)+" -ForegroundColor $C.Border }
function _m { Write-Host "  |$('=' * $BW)|" -ForegroundColor $C.Border }
function _t { Write-Host "  +$('-' * $BW)+" -ForegroundColor $C.Border }
function _s { Write-Host "  |$(' ' * $BW)|" -ForegroundColor $C.Border }

function Write-Section([string]$num, [string]$title) {
    Write-Host ''
    _b
    $credit = ' vxti '
    $inner  = " $num  --  $title"
    $pad    = [Math]::Max(1, $BW - $inner.Length - $credit.Length)
    Write-Host "  |" -NoNewline -ForegroundColor $C.Border
    Write-Host $inner -NoNewline -ForegroundColor $C.Accent
    Write-Host (' ' * $pad) -NoNewline
    Write-Host $credit -NoNewline -ForegroundColor $C.Muted
    Write-Host "|" -ForegroundColor $C.Border
    _m
    _s
}

function Write-SectionEnd { _s; _e; Write-Host '' }

function Write-Sub([string]$t) {
    _t
    $inner = "  >>  $t"
    $pad   = [Math]::Max(1, $BW - $inner.Length)
    Write-Host "  |" -NoNewline -ForegroundColor $C.Border
    Write-Host $inner -NoNewline -ForegroundColor $C.Header
    Write-Host (' ' * $pad) -NoNewline
    Write-Host "|" -ForegroundColor $C.Border
    _t
}


function Write-Row([string]$badge, [string]$label, [string]$val, [string]$col = 'Gray', [string]$ph = '') {
    $bt = switch ($badge) {
        'OK'   {'[  OK  ]'}; 'CRIT' {'[ CRIT ]'}; 'WARN' {'[ WARN ]'}
        'INFO' {'[ INFO ]'}; 'SKIP' {'[ SKIP ]'}; default{'[  --  ]'}
    }
    $bc = switch ($badge) {
        'OK'   {$C.OK}; 'CRIT' {$C.Crit}; 'WARN' {$C.Warn}
        'INFO' {$C.Accent}; 'SKIP' {$C.Muted}; default{$C.Muted}
    }
    $lp = $label.PadRight(34)
    Write-Host "  |  " -NoNewline -ForegroundColor $C.Border
    Write-Host "$bt " -NoNewline -ForegroundColor $bc
    Write-Host "$lp  " -NoNewline -ForegroundColor $C.Muted
    Write-Host $val -ForegroundColor $col
    if ($badge -eq 'CRIT' -and $ph) { Add-Crit $ph $label $val }
}

function Write-Crit([string]$label, [string]$val, [string]$ph = '') {
    $lp = $label.PadRight(34)
    Write-Host "  |  " -NoNewline -ForegroundColor $C.Border
    Write-Host "[ CRIT ] " -NoNewline -ForegroundColor $C.Crit
    Write-Host "$lp  " -NoNewline -ForegroundColor $C.Crit
    Write-Host "!!  $val" -ForegroundColor $C.Crit
    if ($ph) { Add-Crit $ph $label $val }
}


function Clean-RegPath([string]$raw) {
    if (-not $raw) { return $raw }
    $p = $raw.Trim().Trim('"').Trim("'")
   
    if ($p -match '^(.+?\.(?:exe|dll|sys|com|bat|cmd|msi|msp|scr))') {
        $p = $Matches[1]
    }
  
    $p = [Environment]::ExpandEnvironmentVariables($p)
    return $p.Trim()
}

function Write-RegPath([string]$ctx, [string]$rawPath, [string]$ts, [string]$ph = '') {
    if (-not $rawPath) { return }

    # clean and resolve before any file check
    $cleaned = Clean-RegPath $rawPath
    $path    = Resolve-Path2 $cleaned
    $bl      = Test-BL $path


    $exists = $false
    if ($path) {
        $exists = [System.IO.File]::Exists($path)
       
        if (-not $exists) {
            $exists = (Test-Path -LiteralPath $path -PathType Leaf -EA SilentlyContinue) -eq $true
        }
    }

  
    if (-not ($path -match '\.[a-zA-Z]{2,4}$')) { return }

    if (-not $exists) {
       
        if ($bl) {
            $line = $path
            if ($ts) { $line += "  [KeyMod: $ts]" }
            $line += "  [DELETED]"
            Write-Crit $ctx $line $ph
        }
        return
    }

    $sig = Get-Sig $path
    $bad = $bl -or ($sig -notin @('Valid','Error','NotOnDisk','NoPath',''))
    $line = $path
    if ($ts) { $line += "  [KeyMod: $ts]" }
    if ($bad) {
        if ($bl)              { $line += "  [BLACKLISTED]" }
        if ($sig -notin @('Valid','Error','')) { $line += "  [UNSIGNED: $sig]" }
        Write-Crit $ctx $line $ph
    }
   
}


function ConvertFrom-RegFT([byte[]]$b) {
    if ($b -and $b.Count -ge 8) {
        try { return [DateTime]::FromFileTime([BitConverter]::ToInt64($b, 0)) }
        catch {}
    }
    return $null
}

function Get-KeyMod([string]$path) {
    try { return (Get-Item $path -EA Stop).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }
    catch { return $null }
}



function Show-Banner {
    Clear-Host
    Write-Host ''
    Write-Host '  +-------------------------------------------------+' -ForegroundColor DarkCyan
    Write-Host '  |   PC CHECK SCANNER  --  made by vxti            |' -ForegroundColor Cyan
    Write-Host '  +-------------------------------------------------+' -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host "  Date  : $(Get-Date -Format 'dddd dd MMM yyyy  --  HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host "  Host  : $($env:COMPUTERNAME)  |  User: $($env:USERNAME)" -ForegroundColor DarkGray
    Write-Host ''
}

Show-Banner



Write-Section '01' 'Environment and Bootstrap'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    _s
    Write-Crit 'ACCESS DENIED' 'Must be run as Administrator -- right-click PowerShell and select Run as administrator'
    _s
    Write-SectionEnd
    exit 1
}

Write-Row 'OK'   'Admin Rights'    'Elevated session confirmed'                                          $C.OK   '01'
Write-Row 'INFO' 'Hostname'        $env:COMPUTERNAME                                                     $C.Dim
Write-Row 'INFO' 'User'            $env:USERNAME                                                         $C.Dim
Write-Row 'INFO' 'OS'              (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).Caption  $C.Dim

$dn9 = & dotnet --list-runtimes 2>$null | Where-Object { $_ -match 'NETCore\.App\s+9\.' }
if ($dn9) {
    Write-Row 'OK'   '.NET 9 Runtime' ($dn9 | Select-Object -First 1) $C.OK
} else {
    Write-Row 'WARN' '.NET 9 Runtime' 'Not found -- EZTools may fail  https://dotnet.microsoft.com/download/dotnet/9.0' $C.Warn '01'
}

Write-Sub 'EZTools Download -- AmcacheParser / AppCompatCacheParser / TimelineExplorer / PECmd'


$ezDir = "$env:USERPROFILE\Downloads\EZTools"
if (-not (Test-Path $ezDir)) { New-Item -ItemType Directory -Path $ezDir -Force | Out-Null }

$tools = [ordered]@{
    AmcacheParser        = 'https://download.ericzimmermanstools.com/net9/AmcacheParser.zip'
    AppCompatCacheParser = 'https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip'
    TimelineExplorer     = 'https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip'
    PECmd                = 'https://download.ericzimmermanstools.com/net9/PECmd.zip'
}

foreach ($t in $tools.GetEnumerator()) {
    $exePath  = Join-Path $ezDir "$($t.Key).exe"
    $jsonPath = Join-Path $ezDir "$($t.Key).runtimeconfig.json"

    if ((Test-Path $exePath -EA SilentlyContinue) -and (Test-Path $jsonPath -EA SilentlyContinue)) {
        Write-Row 'OK' $t.Key "Present in $ezDir" $C.OK
        continue
    }

    Write-Row 'INFO' $t.Key 'Downloading...' $C.Warn
    try {
        $zip    = Join-Path $ezDir "$($t.Key).zip"
        $tmpDir = Join-Path $ezDir "_tmp_$($t.Key)"

        Invoke-WebRequest -Uri $t.Value -OutFile $zip -UseBasicParsing -EA Stop

      
        if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
        Expand-Archive -LiteralPath $zip -DestinationPath $tmpDir -Force
        Remove-Item $zip -Force -EA SilentlyContinue

      
        $keep = @('.exe','.dll','.json')
        Get-ChildItem $tmpDir -Recurse -File -EA SilentlyContinue |
            Where-Object { $keep -contains $_.Extension.ToLower() } |
            ForEach-Object {
                $dest = Join-Path $ezDir $_.Name
                Move-Item -LiteralPath $_.FullName -Destination $dest -Force -EA SilentlyContinue
            }
        Remove-Item $tmpDir -Recurse -Force -EA SilentlyContinue

        Write-Row 'OK' $t.Key "Extracted to $ezDir" $C.OK
    } catch {
        Write-Row 'CRIT' $t.Key "Download failed: $_" $C.Crit '01'
    }
}


Get-ChildItem $ezDir -File -EA SilentlyContinue |
    Where-Object { $_.Extension.ToLower() -notin @('.exe','.dll','.json') } |
    ForEach-Object { Remove-Item $_.FullName -Force -EA SilentlyContinue }


$usnJournalExe = Join-Path $ezDir 'USN.Journal.exe'
if (-not (Test-Path $usnJournalExe -EA SilentlyContinue)) {
    Write-Row 'INFO' 'USN.Journal' 'Downloading...' $C.Warn
    try {
        Invoke-WebRequest -Uri 'https://github.com/detect-ac/USNJournal/releases/download/forensics/USN.Journal.exe' `
            -OutFile $usnJournalExe -UseBasicParsing -EA Stop
        Write-Row 'OK' 'USN.Journal' "Saved to $usnJournalExe" $C.OK
    } catch {
        Write-Row 'WARN' 'USN.Journal' "Download failed: $_" $C.Warn
    }
} else {
    Write-Row 'OK' 'USN.Journal' "Present: $usnJournalExe" $C.OK
}


$amExe  = Get-ChildItem $ezDir -Filter 'AmcacheParser.exe'        -EA SilentlyContinue | Select-Object -First 1
$accExe = Get-ChildItem $ezDir -Filter 'AppCompatCacheParser.exe'  -EA SilentlyContinue | Select-Object -First 1
$tlExe  = Get-ChildItem $ezDir -Filter 'TimelineExplorer.exe'      -EA SilentlyContinue | Select-Object -First 1
$peExe  = Get-ChildItem $ezDir -Filter 'PECmd.exe'                 -EA SilentlyContinue | Select-Object -First 1

Write-SectionEnd



Write-Section '02' 'Windows Defender -- Threats, Exclusions and AV Status'

Write-Sub 'Defender Real-Time Protection Status'


$defLoaded = $false
try {
    $mpComp    = Get-MpComputerStatus -EA Stop
    $defLoaded = $true
} catch {}

if ($defLoaded) {
    if ($mpComp.RealTimeProtectionEnabled) {
        Write-Row 'OK' 'Real-Time Protection' 'Enabled' $C.OK
    } else {
        Write-Crit 'Real-Time Protection' 'DISABLED -- antivirus protection is off' '02'
    }
    if ($mpComp.AntivirusEnabled) {
        Write-Row 'OK' 'Antivirus Engine' 'Enabled' $C.OK
    } else {
        Write-Crit 'Antivirus Engine' 'DISABLED' '02'
    }
    Write-Row 'INFO' 'Defender Version'    $mpComp.AMProductVersion         $C.Dim
    Write-Row 'INFO' 'Signature Version'   $mpComp.AntivirusSignatureVersion $C.Dim
    Write-Row 'INFO' 'Sig Last Updated'    "$($mpComp.AntivirusSignatureLastUpdated)" $C.Dim
} else {

    $defSvc = Get-Service WinDefend -EA SilentlyContinue
    $defReg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender' -EA SilentlyContinue
    $rtpReg = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' -EA SilentlyContinue).DisableRealtimeMonitoring

    if ($defSvc -and $defSvc.Status -ne 'Running') {
        Write-Crit 'Defender Service (WinDefend)' "Status: $($defSvc.Status) -- service not running" '02'
    }
    if ($rtpReg -eq 1) {
        Write-Crit 'Real-Time Protection' 'Disabled via registry (DisableRealtimeMonitoring = 1)' '02'
    }
    Write-Row 'WARN' 'Defender Status' 'Could not query live status (WinDefend service may be stopped)' $C.Warn '02'
}

Write-Sub 'Defender Disable Events -- IDs 5001 / 5010 / 5012'

$defDisableHits = 0
foreach ($eid in @(5001, 5010, 5012)) {
    $evts = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = $eid
    } -MaxEvents 20 -EA SilentlyContinue
    foreach ($ev in $evts) {
        $defDisableHits++
        $ts  = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        $msg = ($ev.Message -split "`n" | Select-Object -First 1).Trim()
        Write-Crit "Defender Disabled (ID $eid)" "@ $ts  --  $msg" '02'
    }
}
if ($defDisableHits -eq 0) { Write-Row 'OK' 'Defender Disable Events' 'None found' $C.OK }

Write-Sub 'Security Center -- Registered AV Products'
try {
    $avProds = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -EA Stop
    foreach ($av in $avProds) {
        $hex     = [Convert]::ToString([int]$av.productState, 16).PadLeft(6, '0')
        $enabled = $hex.Substring(1, 2) -eq '10'
        if ($enabled) {
            Write-Row 'OK'   "AV: $($av.displayName)" "State: 0x$hex  (Active)" $C.OK
        } else {
            Write-Crit "AV: $($av.displayName)" "State: 0x$hex  -- NOT ACTIVE" '02'
        }
    }
} catch {
    Write-Row 'SKIP' 'SecurityCenter2' 'Could not query registered AV products' $C.Muted
}

Write-Sub 'Defender Exclusions -- Paths, Extensions, Processes'
$mpPref = $null
try { $mpPref = Get-MpPreference -EA Stop } catch {}

if ($mpPref) {
    $exPaths = $mpPref.ExclusionPath
    $exExts  = $mpPref.ExclusionExtension
    $exProcs = $mpPref.ExclusionProcess

    if ($exPaths -and $exPaths.Count -gt 0) {
        foreach ($ep in $exPaths) {
            if (Test-BL $ep) { Write-Crit 'Exclusion Path -- BLACKLIST' $ep '02' }
            else             { Write-Row 'WARN' 'Exclusion Path' $ep $C.Warn '02' }
        }
    } else { Write-Row 'OK' 'Exclusion Paths' 'None configured' $C.OK }

    if ($exExts -and $exExts.Count -gt 0) {
        foreach ($ee in $exExts) { Write-Row 'WARN' 'Exclusion Extension' $ee $C.Warn '02' }
    } else { Write-Row 'OK' 'Exclusion Extensions' 'None configured' $C.OK }

    if ($exProcs -and $exProcs.Count -gt 0) {
        foreach ($epr in $exProcs) {
            if (Test-BL $epr) { Write-Crit 'Exclusion Process -- BLACKLIST' $epr '02' }
            else              { Write-Row 'WARN' 'Exclusion Process' $epr $C.Warn '02' }
        }
    } else { Write-Row 'OK' 'Exclusion Processes' 'None configured' $C.OK }
} else {
    # fallback -- read exclusions directly from registry
    $exRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
    foreach ($sub in @('Paths','Extensions','Processes')) {
        $exReg = Get-ItemProperty "$exRegPath\$sub" -EA SilentlyContinue
        if ($exReg) {
            $exReg.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                if (Test-BL $_.Name) { Write-Crit "Exclusion $sub -- BLACKLIST" $_.Name '02' }
                else                 { Write-Row 'WARN' "Exclusion $sub" $_.Name $C.Warn '02' }
            }
        } else {
            Write-Row 'OK' "Exclusion $sub" 'None configured' $C.OK
        }
    }
}

Write-Sub 'Defender Threat History -- Detected, Quarantined, Allowed'
$threatMap = @{
    1116 = 'Threat Detected'
    1117 = 'Threat Action Taken'
    1118 = 'Threat Action Failed'
    1008 = 'Threat ALLOWED by User'
}
$threatHits = 0
foreach ($eid in $threatMap.Keys) {
    $evts = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = $eid
    } -MaxEvents 30 -EA SilentlyContinue
    foreach ($ev in $evts) {
        $threatHits++
        $ts  = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        $msg = ($ev.Message -split "`n" | Where-Object { $_ -match 'Name:|Path:|Action:' } |
                Select-Object -First 2) -join '  |  '
        if (-not $msg) { $msg = ($ev.Message -split "`n" | Select-Object -First 1).Trim() }
        if ($eid -eq 1008) {
            Write-Crit "Defender: $($threatMap[$eid])" "@ $ts  --  $msg" '02'
        } else {
            Write-Row 'WARN' "Defender: $($threatMap[$eid])" "@ $ts  --  $msg" $C.Warn
        }
    }
}
if ($threatHits -eq 0) { Write-Row 'OK' 'Defender Threat History' 'No threat events found in log' $C.OK }

Write-SectionEnd



Write-Section '03' 'Service Status and Tamper Detection'

Write-Sub 'Critical Service Health'
$svcs = [ordered]@{
    EventLog  = 'Event Logging (disabled = audit evasion)'
    Sysmain   = 'Superfetch / SysMain'
    Diagtrack = 'Connected User Experiences / Telemetry'
    DPS       = 'Diagnostic Policy Service'
    PcaSvc    = 'Program Compatibility Assistant'
}
foreach ($name in $svcs.Keys) {
    $svc = Get-Service $name -EA SilentlyContinue
    $wmi = Get-CimInstance Win32_Service -Filter "Name='$name'" -EA SilentlyContinue
    if ($svc) {
        $mode = $wmi.StartMode
        if ($svc.Status -eq 'Running') {
            Write-Row 'OK' $name "Status: $($svc.Status)  |  StartType: $mode  |  $($svcs[$name])" $C.OK
        } else {
            Write-Crit $name "Status: $($svc.Status)  |  StartType: $mode  |  $($svcs[$name])" '03'
        }
    } else {
        Write-Row 'SKIP' $name 'Not found on this system' $C.Muted
    }
}

Write-SectionEnd



Write-Section '04' 'File and Disk Forensics'

Write-Sub 'USN Journal -- Integrity Check'
$usnQuery = & fsutil usn queryjournal C: 2>&1
if ("$usnQuery" -match 'Invalid|No journal|error') {
    Write-Crit 'USN Journal' 'CLEARED or disabled -- strong indicator of anti-forensic activity' '04'
} else {
    Write-Row 'OK' 'USN Journal' 'Present and active on C:' $C.OK
}

Write-SectionEnd



Write-Section '05' 'Hyper-V and VM Environment Check'

$vmScore = 0
$vmHints = New-Object System.Collections.Generic.List[string]
$csys    = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue

Write-Sub 'Manufacturer and Model Strings'
$vmMfr = 'VMware|VirtualBox|VBOX|Microsoft Corporation|Hyper-V|QEMU|KVM|Xen|Parallels|innotek'
if ($csys.Manufacturer -match $vmMfr -or $csys.Model -match $vmMfr -or $bios.Version -match $vmMfr) {
    $vmScore++
    $vmHints.Add("Manufacturer: $($csys.Manufacturer) / Model: $($csys.Model)")
    Write-Crit 'VM String Detected' "Mfr: $($csys.Manufacturer)  |  Model: $($csys.Model)  |  BIOS: $($bios.Version)" '05'
} else {
    Write-Row 'OK' 'Manufacturer / Model' "$($csys.Manufacturer)  |  $($csys.Model)" $C.OK
}

Write-Sub 'VM Registry Keys'
$vmKeys = @(
    'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools',
    'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions',
    'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters',
    'HKLM:\SYSTEM\CurrentControlSet\Services\VBoxGuest',
    'HKLM:\SYSTEM\CurrentControlSet\Services\vmhgfs',
    'HKLM:\SYSTEM\CurrentControlSet\Services\vmmouse',
    'HKLM:\SYSTEM\CurrentControlSet\Services\vmrawdsk'
)
$vmKeyHit = $false
foreach ($k in $vmKeys) {
    if (Test-Path $k -EA SilentlyContinue) {
        $vmScore++; $vmKeyHit = $true
        $vmHints.Add("RegKey: $k")
        Write-Crit 'VM Registry Key' $k '05'
    }
}
if (-not $vmKeyHit) { Write-Row 'OK' 'VM Registry Keys' 'No known VM keys present' $C.OK }

Write-Sub 'VM Drivers and Services'
$vmDrvList = @('vmbus','vmhgfs','vmmouse','vmrawdsk','vmusbmouse','vboxguest','vboxsf','vboxvideo','vioscsi','balloon','netkvm')
$vmDrvHit  = $false
foreach ($d in $vmDrvList) {
    $s = Get-Service $d -EA SilentlyContinue
    if ($s) {
        $vmScore++; $vmDrvHit = $true
        $vmHints.Add("Driver: $d")
        Write-Crit 'VM Driver Found' "$d  |  Status: $($s.Status)" '05'
    }
}
if (-not $vmDrvHit) { Write-Row 'OK' 'VM Drivers' 'No known VM driver services found' $C.OK }

Write-Sub 'VM Processes'
$vmProcList = @('vmtoolsd','vmwaretray','vmwareuser','vboxservice','vboxtray','xenservice','qemu-ga','prl_tools')
$vmProcHit  = $false
foreach ($pn in $vmProcList) {
    $pr = Get-Process $pn -EA SilentlyContinue
    if ($pr) {
        $vmScore++; $vmProcHit = $true
        $vmHints.Add("Process: $pn")
        Write-Crit 'VM Process Running' "$pn  |  PID: $($pr.Id)  |  Path: $($pr.Path)" '05'
    }
}
if (-not $vmProcHit) { Write-Row 'OK' 'VM Processes' 'No known VM processes running' $C.OK }

Write-Sub 'Hyper-V Windows Feature'
$hvFeature = Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V-All' -EA SilentlyContinue
if ($hvFeature -and $hvFeature.State -eq 'Enabled') {
    $vmScore++; $vmHints.Add('Hyper-V feature enabled')
    Write-Row 'WARN' 'Hyper-V Feature' 'Enabled -- machine may be acting as a hypervisor host' $C.Warn '05'
} else {
    Write-Row 'OK' 'Hyper-V Feature' 'Disabled / not installed' $C.OK
}

Write-Sub 'Verdict'
if ($vmScore -gt 0) {
    Write-Crit 'VM ENVIRONMENT DETECTED' "$vmScore indicator(s): $($vmHints -join ' / ')" '05'
} else {
    Write-Row 'OK' 'VM Verdict' 'No virtualisation indicators -- appears to be bare metal' $C.OK
}

Write-SectionEnd



Write-Section '06' 'EZTools -- AmcacheParser and AppCompatCacheParser'

$amHve = 'C:\Windows\appcompat\Programs\Amcache.hve'

Write-Sub 'AmcacheParser'
if ($amExe) {
    Write-Row 'INFO' 'AmcacheParser' "Running -- please wait..." $C.Accent

    
    $amOut = "$env:TEMP\_am_out.tmp"
    $amErr = "$env:TEMP\_am_err.tmp"
    $amProc = Start-Process -FilePath $amExe.FullName `
        -ArgumentList "-f `"$amHve`" --csv `"$ezDir`"" `
        -WorkingDirectory $ezDir `
        -RedirectStandardOutput $amOut `
        -RedirectStandardError  $amErr `
        -NoNewWindow -PassThru
    $amProc.WaitForExit()
    Remove-Item $amOut,$amErr -Force -EA SilentlyContinue

    $amAllCsvs = Get-ChildItem $ezDir -Filter '*Amcache*.csv' -EA SilentlyContinue
    $amCsv     = $amAllCsvs | Where-Object { $_.Name -match 'UnassociatedFile' } | Select-Object -First 1

    if ($amAllCsvs.Count -gt 0) {
        Write-Row 'OK' 'AmcacheParser' "$($amAllCsvs.Count) CSV(s) saved to $ezDir  (open UnassociatedFileEntries in TimelineExplorer)" $C.OK
        if ($amCsv) {
            $rows   = Import-Csv $amCsv.FullName -EA SilentlyContinue
            $amHits = 0
            foreach ($row in $rows) {
                $resolvedPath = Resolve-Path2 $row.FullPath
                $combo = "$resolvedPath $($row.Name) $($row.FileDescription) $($row.Publisher)"
                if (-not (Test-BL $combo)) { continue }
                $amHits++
                if (Test-Path -LiteralPath $resolvedPath -EA SilentlyContinue) {
                    Write-Crit 'AMCACHE BLACKLIST' "$($row.Name)  |  $resolvedPath  |  Sig: $(Get-Sig $resolvedPath)" '06'
                } else {
                    Write-Crit 'AMCACHE BLACKLIST' "$($row.Name)  |  $resolvedPath  |  DELETED" '06'
                }
            }
            if ($amHits -eq 0) { Write-Row 'OK' 'Amcache Scan' 'No blacklisted entries found' $C.OK }
        }
    } else {
        Write-Row 'WARN' 'AmcacheParser' "No CSV output in $ezDir -- make sure .NET 9 is installed" $C.Warn '06'
    }
} else {
    Write-Row 'SKIP' 'AmcacheParser.exe' "Not found in $ezDir" $C.Muted
}

Write-Sub 'AppCompatCacheParser (ShimCache)'
if ($accExe) {
    Write-Row 'INFO' 'AppCompatCacheParser' "Running -- please wait..." $C.Accent


    $accOut = "$env:TEMP\_acc_out.tmp"
    $accErr = "$env:TEMP\_acc_err.tmp"
    $accProc = Start-Process -FilePath $accExe.FullName `
        -ArgumentList "--csv `"$ezDir`"" `
        -WorkingDirectory $ezDir `
        -RedirectStandardOutput $accOut `
        -RedirectStandardError  $accErr `
        -NoNewWindow -PassThru
    $accProc.WaitForExit()
    Remove-Item $accOut,$accErr -Force -EA SilentlyContinue

    $accCsv = Get-ChildItem $ezDir -Filter '*AppCompatCache*.csv' -EA SilentlyContinue |
              Select-Object -First 1

    if ($accCsv) {
        Write-Row 'OK' 'AppCompatCacheParser' "CSV saved: $($accCsv.Name)" $C.OK
        $rows    = Import-Csv $accCsv.FullName -EA SilentlyContinue
        $accHits = 0
        foreach ($row in $rows) {
            $resolvedPath = Resolve-Path2 $row.Path
            if (Test-BL "$resolvedPath $($row.Executable)") {
                $accHits++
                if (Test-Path -LiteralPath $resolvedPath -EA SilentlyContinue) {
                    Write-Crit 'SHIMCACHE BLACKLIST' "$($row.Executable)  |  $resolvedPath  |  Sig: $(Get-Sig $resolvedPath)" '06'
                } else {
                    Write-Crit 'SHIMCACHE BLACKLIST' "$($row.Executable)  |  $resolvedPath  |  DELETED" '06'
                }
            }
        }
        if ($accHits -eq 0) { Write-Row 'OK' 'ShimCache Scan' 'No blacklisted entries found' $C.OK }
    } else {
        Write-Row 'WARN' 'AppCompatCacheParser' "No CSV output in $ezDir -- make sure .NET 9 is installed" $C.Warn '06'
    }
} else {
    Write-Row 'SKIP' 'AppCompatCacheParser.exe' "Not found in $ezDir" $C.Muted
}

if ($tlExe) { Write-Row 'INFO' 'TimelineExplorer' "Open CSVs from $ezDir in $($tlExe.FullName)" $C.Accent }

Write-SectionEnd



Write-Section '07' 'Registry Execution Logs'

Write-Sub 'AppCompatFlags -- Store'
$acsKey = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store'
$acsMod = Get-KeyMod $acsKey
if ($acsMod) { Write-Row 'INFO' 'Key LastWriteTime' $acsMod $C.Dim }
$acs = Get-ItemProperty $acsKey -EA SilentlyContinue
if ($acs) {
    $acs.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        Write-RegPath 'ACF-Store' $_.Name $acsMod '07'
    }
} else { Write-Row 'SKIP' 'ACF Store' 'No entries' $C.Muted }

Write-Sub 'AppCompatFlags -- Layers'
$aclKey = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
$aclMod = Get-KeyMod $aclKey
if ($aclMod) { Write-Row 'INFO' 'Key LastWriteTime' $aclMod $C.Dim }
$acl = Get-ItemProperty $aclKey -EA SilentlyContinue
if ($acl) {
    $acl.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        Write-RegPath 'ACF-Layers' $_.Name $aclMod '07'
    }
} else { Write-Row 'SKIP' 'ACF Layers' 'No entries' $C.Muted }

Write-Sub 'MuiCache -- Friendly App Name Cache'
$muiKey = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
$muiMod = Get-KeyMod $muiKey
if ($muiMod) { Write-Row 'INFO' 'Key LastWriteTime' $muiMod $C.Dim }
$mui = Get-ItemProperty $muiKey -EA SilentlyContinue
if ($mui) {
    $mui.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Name -match '\\' } | ForEach-Object {
        Write-RegPath 'MuiCache' ($_.Name -split '\.FriendlyAppName')[0] $muiMod '07'
    }
} else { Write-Row 'SKIP' 'MuiCache' 'No entries' $C.Muted }

Write-Sub 'BAM -- Background Activity Moderator (SID *-1001)'
$bamBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
if (Test-Path $bamBase -EA SilentlyContinue) {
    Get-ChildItem $bamBase -EA SilentlyContinue | Where-Object { $_.PSChildName -match '1001' } | ForEach-Object {
        $bamMod = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        Write-Row 'INFO' 'BAM SID' "$($_.PSChildName)  |  LastWriteTime: $bamMod" $C.Dim
        $p = Get-ItemProperty $_.PSPath -EA SilentlyContinue
        $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Name -match '\\' } | ForEach-Object {
            Write-RegPath 'BAM' $_.Name $bamMod '07'
        }
    }
} else { Write-Row 'SKIP' 'BAM' 'Key not present (Win10 1803+ required)' $C.Muted }

Write-Sub 'ShellBags -- Folder Access History (includes deleted folders)'
$sbRoots = @(
    'HKCU:\Software\Microsoft\Windows\Shell\BagMRU',
    'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU'
)
$sbCount = 0; $sbHits = 0
foreach ($root in $sbRoots) {
    if (-not (Test-Path $root -EA SilentlyContinue)) { continue }
    Get-ChildItem $root -Recurse -EA SilentlyContinue | Select-Object -First 60 | ForEach-Object {
        $pp = Get-ItemProperty $_.PSPath -EA SilentlyContinue
        if ($pp.MRUListEx -or $pp.NodeSlot) {
            $sbCount++
            if (Test-BL $_.PSPath) { $sbHits++; Write-Crit 'ShellBag BL Match' $_.PSPath '07' }
        }
    }
}
Write-Row 'INFO' 'ShellBag Entries' "$sbCount scanned  |  $sbHits blacklist hits" $C.Dim

Write-Sub 'RunMRU -- Win+R History'
$rmruKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
$rmruMod = Get-KeyMod $rmruKey
if ($rmruMod) { Write-Row 'INFO' 'Key LastWriteTime' $rmruMod $C.Dim }
$rmru = Get-ItemProperty $rmruKey -EA SilentlyContinue
if ($rmru) {
    $any = $false
    $rmru.PSObject.Properties | Where-Object { $_.Name -match '^[a-z]$' } | ForEach-Object {
        $any = $true
        $cmd = $_.Value -replace '\\1$',''
        if (Test-BL $cmd) { Write-Crit 'RunMRU BL Hit' $cmd '07' }
        else              { Write-Row 'INFO' 'RunMRU Entry' $cmd $C.Dim }
    }
    if (-not $any) { Write-Row 'OK' 'RunMRU' 'No entries' $C.OK }
} else { Write-Row 'SKIP' 'RunMRU' 'Key not found' $C.Muted }

Write-SectionEnd



Write-Section '08' 'Prefetch Analysis -- Unsigned and Blacklist'

$pfDir = 'C:\Windows\Prefetch'

if (Test-Path $pfDir -EA SilentlyContinue) {
    $pfFiles = Get-ChildItem $pfDir -Filter '*.pf' -EA SilentlyContinue
    Write-Row 'INFO' 'Prefetch Files Found' "$($pfFiles.Count) .pf files in $pfDir" $C.Dim


    Write-Row 'INFO' 'Prefetch Lookup' 'Building exe index -- this takes a few seconds...' $C.Muted

    $exeIndex  = @{}
    $indexDirs = @(
        $env:SystemRoot, "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64",
        $env:ProgramFiles, ${env:ProgramFiles(x86)},
        $env:LOCALAPPDATA, $env:APPDATA,
        "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", 'C:\Users\Public'
    )
    foreach ($iDir in $indexDirs) {
        if (-not $iDir -or -not (Test-Path $iDir -EA SilentlyContinue)) { continue }
        Get-ChildItem $iDir -Filter '*.exe' -Recurse -Depth 3 -EA SilentlyContinue -Force |
            ForEach-Object {
                $key = $_.Name.ToLower()
                if (-not $exeIndex.ContainsKey($key)) { $exeIndex[$key] = $_.FullName }
            }
    }

    $pfFlagged = 0
    foreach ($pf in $pfFiles) {
        $exeName = ($pf.BaseName -replace '-[0-9A-F]{8}$','') + '.exe'
        $bl      = Test-BL $pf.Name
        $lastRun = $pf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')

      
        $exePath = $exeIndex[$exeName.ToLower()]

        if (-not $exePath) {
           
            if ($bl) {
                $pfFlagged++
                Write-Crit "Prefetch: $($pf.Name)" "Last Run: $lastRun  |  EXE: DELETED  |  BLACKLISTED" '08'
            }
            continue
        }

      
        $sig      = Get-Sig $exePath
        $unsigned = $sig -notin @('Valid','Error','')

        if ($bl -or $unsigned) {
            $pfFlagged++
            $tags = New-Object System.Collections.Generic.List[string]
            if ($bl)       { $tags.Add('BLACKLISTED') }
            if ($unsigned) { $tags.Add("UNSIGNED (Sig: $sig)") }
            Write-Crit "Prefetch: $($pf.Name)" "Last Run: $lastRun  |  EXE: $exePath  |  $($tags -join ' + ')" '08'
        }
    }
    if ($pfFlagged -eq 0) { Write-Row 'OK' 'Prefetch' 'No blacklisted or unsigned entries found' $C.OK }
    else                  { Write-Row 'WARN' 'Prefetch Total Flagged' "$pfFlagged entries -- see above" $C.Warn }
} else {
    Write-Row 'SKIP' 'Prefetch' 'Directory not accessible (Prefetch may be disabled)' $C.Muted
}

Write-Sub 'PECmd -- Full Prefetch Parse (Embedded File Paths)'

if ($peExe) {
    $pfCsvDir = "$ezDir\PECmd_output"
    if (-not (Test-Path $pfCsvDir)) { New-Item -ItemType Directory -Path $pfCsvDir -Force | Out-Null }

    Write-Row 'INFO' 'PECmd' "Running on $pfDir -- please wait..." $C.Accent
    $peOut = "$env:TEMP\pecmd_out.tmp"
    $peErr = "$env:TEMP\pecmd_err.tmp"
    $peProc = Start-Process -FilePath $peExe.FullName `
        -ArgumentList "-d `"$pfDir`" --csv `"$pfCsvDir`" --csvf PECmd_results.csv" `
        -WorkingDirectory $ezDir `
        -RedirectStandardOutput $peOut `
        -RedirectStandardError  $peErr `
        -NoNewWindow -PassThru
    $peProc.WaitForExit()
    Remove-Item $peOut,$peErr -Force -EA SilentlyContinue

    $peCsv = "$pfCsvDir\PECmd_results.csv"
    if (Test-Path $peCsv -EA SilentlyContinue) {
        Write-Row 'OK' 'PECmd' "CSV saved to $peCsv  (open in TimelineExplorer for full analysis)" $C.OK
        $peRows = Import-Csv $peCsv -EA SilentlyContinue
        $peHits = 0
        foreach ($row in $peRows) {
            $exeName = $row.ExecutableName
            $lastRun = $row.LastRun
            $loaded  = $row.FilesLoaded
            if ((Test-BL $exeName) -or (Test-BL $loaded)) {
                $peHits++
                Write-Crit 'PECMD BLACKLIST' "EXE: $exeName  |  LastRun: $lastRun  |  BLACKLISTED in loaded files" '08'
            }
        }
        Write-Row 'INFO' 'PECmd Entries' "$($peRows.Count) prefetch records parsed  |  $peHits blacklist hit(s)" $C.Dim
    } else {
        Write-Row 'WARN' 'PECmd' "No CSV output -- ExitCode: $($peProc.ExitCode)" $C.Warn
    }
} else {
    Write-Row 'SKIP' 'PECmd' "Not found -- will download on next run" $C.Muted
}

Write-SectionEnd



Write-Section '09' 'Process Scan, USB History and PowerShell History'

Write-Sub 'Running Processes -- Blacklist Check'
$procs        = Get-Process -EA SilentlyContinue | Where-Object { $_.Id -ne $PID }
$procHitCount = 0

foreach ($proc in $procs) {
    if ((Test-BL $proc.Name) -or ($proc.Path -and (Test-BL $proc.Path))) {
        $procHitCount++
        $sig = if ($proc.Path) { Get-Sig $proc.Path } else { 'NoPath' }
        Write-Crit 'PROCESS BLACKLISTED' "PID: $($proc.Id)  |  $($proc.Name)  |  $($proc.Path)  |  Sig: $sig" '09'
    }
}
if ($procHitCount -eq 0) { Write-Row 'OK' 'Running Processes' 'No blacklisted processes found' $C.OK }

Write-Sub 'Loaded Modules -- Injected / Blacklisted DLLs'
$modHitCount = 0
foreach ($proc in ($procs | Select-Object -First 80)) {
    $mods = $null
    try { $mods = $proc.Modules } catch {}
    if (-not $mods) { continue }
    $mods | Where-Object {
       
      
        $fn = [IO.Path]::GetFileNameWithoutExtension($_.FileName)
        (Test-BL $fn) -and ($_.FileName -notmatch '^C:\\Windows\\')
    } | ForEach-Object {
        $modHitCount++
        $sig = Get-Sig $_.FileName
        Write-Crit 'MODULE BLACKLISTED' "PID: $($proc.Id) ($($proc.Name))  |  $($_.FileName)  |  Sig: $sig" '09'
    }
}
if ($modHitCount -eq 0) { Write-Row 'OK' 'Loaded Modules' 'No blacklisted DLLs found' $C.OK }

Write-Sub 'USB History -- All Connected Devices'


$usbCount = 0
$usbBases = @(
    'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR',
    'HKLM:\SYSTEM\ControlSet001\Enum\USBSTOR',
    'HKLM:\SYSTEM\ControlSet002\Enum\USBSTOR'
)
$usbSeen = @{}
foreach ($usbBase in $usbBases) {
    if (-not (Test-Path $usbBase -EA SilentlyContinue)) { continue }
    Get-ChildItem $usbBase -EA SilentlyContinue | ForEach-Object {
        $devType = $_
        Get-ChildItem $devType.PSPath -EA SilentlyContinue | ForEach-Object {
            $inst      = $_
            $serial    = $inst.PSChildName -replace '&\d+$',''   # strip port suffix
            if ($usbSeen[$serial]) { return }
            $usbSeen[$serial] = $true

            $props     = Get-ItemProperty $inst.PSPath -EA SilentlyContinue
            $friendly  = $props.FriendlyName
            if (-not $friendly) {
                
                $friendly = ($devType.PSChildName -replace '^Disk&','') -replace '&Rev_[^&]+$',''
                $friendly = $friendly -replace 'Ven_','' -replace 'Prod_',' '
            }

        
            $lastWrite = $inst.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')

           
            $mfr = $props.Mfg
            if (-not $mfr) { $mfr = '' }

            $usbCount++
            $line = "Last Registry Write: $lastWrite  |  Serial: $serial"
            if ($mfr) { $line += "  |  Mfg: $mfr" }
            Write-Row 'INFO' "USB: $friendly" $line $C.Dim
        }
    }
}
if ($usbCount -eq 0) {
    Write-Row 'INFO' 'USB History' 'No USBSTOR devices found in any ControlSet' $C.Muted
} else {
    Write-Row 'INFO' 'USB Devices Total' "$usbCount unique device(s) found across all ControlSets" $C.Dim
}

Write-Sub 'PowerShell History -- All User Profiles'
$suspPt      = 'iex\b|iwr\b|DownloadString|Invoke-Expression|Invoke-WebRequest|WebClient|bypass|hidden|encodedcommand|-enc '
$allProfiles = Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue
foreach ($up in $allProfiles) {
    $histFile = "$($up.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (-not (Test-Path $histFile -EA SilentlyContinue)) { continue }
    $lines = Get-Content $histFile -EA SilentlyContinue
    $susp  = $lines | Where-Object { $_ -match $suspPt -or (Test-BL $_) }
    if ($susp) {
        foreach ($l in $susp) {
            Write-Row 'WARN' "PS History ($($up.Name))" $l $C.Warn
        }
    } else {
        Write-Row 'OK' "PS History ($($up.Name))" "$($lines.Count) commands -- nothing suspicious" $C.OK
    }
}

Write-Sub 'Script Block Logging -- Event ID 4104'
$sbPol = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA SilentlyContinue).EnableScriptBlockLogging
if ($sbPol -eq 1) {
    Write-Row 'OK' 'Script Block Logging' 'Enabled -- checking Event ID 4104...' $C.OK
    $sb4104 = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104
    } -MaxEvents 100 -EA SilentlyContinue
    if ($sb4104) {
        $hits = $sb4104 | Where-Object { $_.Message -match $suspPt -or (Test-BL $_.Message) }
        if ($hits) {
            foreach ($h in $hits) {
                Write-Crit "4104 @ $($h.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" ($h.Message -split "`n")[0].Trim() '09'
            }
        } else {
            Write-Row 'OK' '4104 Results' "$($sb4104.Count) events checked -- nothing suspicious" $C.OK
        }
    } else { Write-Row 'INFO' '4104' 'Policy enabled but log is empty' $C.Dim }
} else {
    Write-Row 'INFO' 'Script Block Logging' 'Not enabled (normal for home PCs) -- history file checked instead' $C.Dim
}

Write-SectionEnd





Write-Section '10' 'UserAssist -- GUI Execution History'

function Invoke-ROT13([string]$str) {
    $out = [System.Text.StringBuilder]::new()
    foreach ($ch in $str.ToCharArray()) {
        if     ($ch -ge 'A' -and $ch -le 'Z') { [void]$out.Append([char](65 + (([int]$ch - 65 + 13) % 26))) }
        elseif ($ch -ge 'a' -and $ch -le 'z') { [void]$out.Append([char](97 + (([int]$ch - 97 + 13) % 26))) }
        else   { [void]$out.Append($ch) }
    }
    return $out.ToString()
}

$uaBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
$uaHits = 0

if (Test-Path $uaBase -EA SilentlyContinue) {
    Get-ChildItem $uaBase -EA SilentlyContinue | ForEach-Object {
        $countKey = Join-Path $_.PSPath 'Count'
        if (-not (Test-Path $countKey -EA SilentlyContinue)) { return }
        $vals = Get-ItemProperty $countKey -EA SilentlyContinue
        $vals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            $decoded = Invoke-ROT13 $_.Name
            if ($decoded -notmatch '\.exe' -and $decoded -notmatch '\.lnk') { return }

            $raw      = $_.Value
            $runCount = 0
            $lastRun  = $null
            if ($raw -is [byte[]] -and $raw.Count -ge 72) {
                $runCount = [BitConverter]::ToInt32($raw, 4)
                $ft       = [BitConverter]::ToInt64($raw, 60)
                if ($ft -gt 0) {
                    try { $lastRun = [DateTime]::FromFileTime($ft).ToString('yyyy-MM-dd HH:mm:ss') } catch {}
                }
            }
            if ($runCount -le 0) { return }

            $resolved = Resolve-Path2 $decoded
            $bl       = Test-BL $resolved

            if ($bl) {
                $uaHits++
                Write-Crit 'UserAssist BLACKLIST' "$resolved  |  RunCount: $runCount  |  LastRun: $lastRun" '10'
                return
            }

            # also flag unsigned exes executed from user-writable directories
            $isUserPath = $resolved -match [regex]::Escape($env:USERPROFILE)
            if ($isUserPath) {
                $sig = Get-Sig $resolved
                if ($sig -notin @('Valid','NotOnDisk','Error','NoPath')) {
                    $uaHits++
                    Write-Crit 'UserAssist UNSIGNED' "$resolved  |  RunCount: $runCount  |  LastRun: $lastRun  |  Sig: $sig" '10'
                }
            }
        }
    }
    if ($uaHits -eq 0) { Write-Row 'OK' 'UserAssist' 'No blacklisted or unsigned entries found' $C.OK }
} else {
    Write-Row 'SKIP' 'UserAssist' 'Registry key not found' $C.Muted
}

Write-SectionEnd



Write-Section '11' 'Installed Programs -- Blacklist Check'

$instHits = 0
$instSeen = @{}

$uninstPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

foreach ($uPath in $uninstPaths) {
    if (-not (Test-Path $uPath -EA SilentlyContinue)) { continue }
    Get-ChildItem $uPath -EA SilentlyContinue | ForEach-Object {
        $p    = Get-ItemProperty $_.PSPath -EA SilentlyContinue
        $name = $p.DisplayName
        if (-not $name -or $instSeen[$name]) { return }
        $instSeen[$name] = $true

        $combo = "$name $($p.Publisher) $($p.InstallLocation)"
        if (Test-BL $combo) {
            $instHits++
            $line = $name
            if ($p.DisplayVersion) { $line += "  |  v$($p.DisplayVersion)" }
            if ($p.InstallDate)    { $line += "  |  Installed: $($p.InstallDate)" }
            if ($p.Publisher)      { $line += "  |  Pub: $($p.Publisher)" }
            if ($p.InstallLocation){ $line += "  |  Location: $($p.InstallLocation)" }
            Write-Crit 'INSTALLED PROGRAM BL' $line '11'
        }
    }
}

if ($instHits -eq 0) { Write-Row 'OK' 'Installed Programs' 'No blacklisted programs found' $C.OK }
Write-Row 'INFO' 'Programs Scanned' "$($instSeen.Count) unique entries checked across all uninstall keys" $C.Dim

Write-SectionEnd


Write-Section '12' 'Kernel Driver Audit -- Unsigned and Blacklisted Drivers'

Write-Sub 'Filter Manager Minifilters  (fltMC)'
$fltHits = 0
$fltRaw  = & fltMC 2>&1
if ($fltRaw) {
    $fltRaw | Where-Object { $_ -match '\S' -and $_ -notmatch '^Filter Name|^---|\bInstances\b' } | ForEach-Object {
        $drvName = ($_.Trim() -split '\s+')[0]
        if (-not $drvName -or $drvName.Length -lt 3) { return }

        $drvPath = $null
        $svcReg  = "HKLM:\SYSTEM\CurrentControlSet\Services\$drvName"
        if (Test-Path $svcReg -EA SilentlyContinue) {
            $imgRaw = (Get-ItemProperty $svcReg -EA SilentlyContinue).ImagePath
            if ($imgRaw) {
                $drvPath = Resolve-Path2 ($imgRaw -replace '^\\\?\?\\','' -replace '\\SystemRoot\\',"$env:SystemRoot\")
            }
        }

        $bl  = Test-BL $drvName
        $sig = if ($drvPath -and (Test-Path -LiteralPath $drvPath -EA SilentlyContinue)) { Get-Sig $drvPath } else { 'Unknown' }

        if ($bl) {
            $fltHits++
            Write-Crit 'FILTER DRIVER BL' "$drvName  |  Path: $drvPath  |  Sig: $sig" '12'
        } elseif ($sig -notin @('Valid','Unknown','Error','') -and $drvPath -and $drvPath -notmatch [regex]::Escape("$env:SystemRoot")) {
            $fltHits++
            Write-Crit 'FILTER DRIVER UNSIGNED' "$drvName  |  Path: $drvPath  |  Sig: $sig" '12'
        }
    }
    if ($fltHits -eq 0) { Write-Row 'OK' 'Filter Drivers' 'No blacklisted or unsigned filter drivers found' $C.OK }
} else {
    Write-Row 'SKIP' 'fltMC' 'No output returned' $C.Muted
}

Write-Sub 'Loaded Kernel Drivers  (driverquery)'
$dqHits = 0
$dqNull = "$env:TEMP\_dq_err.tmp"
$dqRaw  = & driverquery /fo csv 2>$dqNull | ConvertFrom-Csv -EA SilentlyContinue
Remove-Item $dqNull -Force -EA SilentlyContinue

if ($dqRaw) {
    foreach ($drv in $dqRaw) {
        $dName = $drv.'Module Name'
        if (-not $dName) { $dName = $drv.DisplayName }
        if (-not $dName) { continue }

        $svcReg2 = "HKLM:\SYSTEM\CurrentControlSet\Services\$dName"
        $drvPath2 = $null
        if (Test-Path $svcReg2 -EA SilentlyContinue) {
            $imgRaw2 = (Get-ItemProperty $svcReg2 -EA SilentlyContinue).ImagePath
            if ($imgRaw2) {
                $drvPath2 = Resolve-Path2 ($imgRaw2 -replace '^\\\?\?\\','' -replace '\\SystemRoot\\',"$env:SystemRoot\")
            }
        }

        $bl2  = Test-BL $dName
        $sig2 = if ($drvPath2 -and (Test-Path -LiteralPath $drvPath2 -EA SilentlyContinue)) { Get-Sig $drvPath2 } else { $null }

        if ($bl2) {
            $dqHits++
            Write-Crit 'KERNEL DRIVER BL' "$dName  |  Path: $drvPath2" '12'
        } elseif ($sig2 -and $sig2 -notin @('Valid','Error','') -and $drvPath2 -and $drvPath2 -notmatch [regex]::Escape("$env:SystemRoot")) {
            $dqHits++
            Write-Crit 'KERNEL DRIVER UNSIGNED' "$dName  |  Path: $drvPath2  |  Sig: $sig2" '12'
        }
    }
    if ($dqHits -eq 0) { Write-Row 'OK' 'Kernel Drivers' 'No blacklisted or non-Windows unsigned drivers found' $C.OK }
    Write-Row 'INFO' 'Drivers Checked' "$($dqRaw.Count) drivers scanned via driverquery" $C.Dim
} else {
    Write-Row 'SKIP' 'driverquery' 'Could not retrieve driver list' $C.Muted
}

Write-SectionEnd


Write-Host ''
Write-Host "  +$('=' * $BW)+" -ForegroundColor $C.Crit
$hdrTxt = "  13  --  CRITICAL FINDINGS SUMMARY  |  made by vxti"
Write-Host "  |" -NoNewline -ForegroundColor $C.Crit
Write-Host $hdrTxt.PadRight($BW) -NoNewline -ForegroundColor $C.Crit
Write-Host "|" -ForegroundColor $C.Crit
Write-Host "  |$('=' * $BW)|" -ForegroundColor $C.Crit

if ($script:CritList.Count -eq 0) {
    Write-Host "  |  " -NoNewline -ForegroundColor $C.Crit
    Write-Host "  No critical findings detected. Machine appears clean.".PadRight($BW - 2) -NoNewline -ForegroundColor $C.OK
    Write-Host "|" -ForegroundColor $C.Crit
} else {
    $grouped = $script:CritList | Group-Object Phase | Sort-Object Name
    foreach ($grp in $grouped) {
        Write-Host "  +$('-' * $BW)+" -ForegroundColor $C.Crit
        $pHdr = "  [ Phase $($grp.Name) ]  $($grp.Count) finding(s)"
        Write-Host "  |" -NoNewline -ForegroundColor $C.Crit
        Write-Host $pHdr.PadRight($BW) -NoNewline -ForegroundColor $C.Warn
        Write-Host "|" -ForegroundColor $C.Crit
        Write-Host "  +$('-' * $BW)+" -ForegroundColor $C.Crit
        foreach ($item in $grp.Group) {
            $lbl = "  !!  $($item.Label)".PadRight(44)
            Write-Host "  |  " -NoNewline -ForegroundColor $C.Crit
            Write-Host $lbl -NoNewline -ForegroundColor $C.Crit
            Write-Host "  $($item.Value)" -ForegroundColor $C.Crit
        }
    }
}

Write-Host "  +$('-' * $BW)+" -ForegroundColor $C.Crit
$foot = "  Total: $($script:CritList.Count) critical finding(s)   |   Finished: $(Get-Date -Format 'HH:mm:ss')   |   made by vxti"
Write-Host "  |" -NoNewline -ForegroundColor $C.Crit
Write-Host $foot.PadRight($BW) -NoNewline -ForegroundColor $C.Muted
Write-Host "|" -ForegroundColor $C.Crit
Write-Host "  +$('=' * $BW)+" -ForegroundColor $C.Crit
Write-Host ''



Set-Location $env:TEMP
Remove-Item "$ezDir\csv_out" -Recurse -Force -EA SilentlyContinue



