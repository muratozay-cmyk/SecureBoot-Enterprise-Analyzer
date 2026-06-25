#requires -version 5.1
<#
.SYNOPSIS
    Microsoft Secure Boot 2023 Enterprise Readiness Analyzer v5.0

.AUTHOR
    Murat Ozay

.MODE
    READ ONLY

.DESCRIPTION
    Enterprise-style Secure Boot 2023 readiness assessment tool.

    Features:
    - Local assessment
    - Remote assessment via PowerShell Remoting / WinRM
    - Target input: hostname, IP, comma/newline separated list
    - IP range support: 10.0.0.1-10.0.0.20
    - TXT import
    - CSV import
    - CSV / JSON / TXT / HTML report output
    - Modernized WinForms GUI
    - Dashboard cards
    - Platform detection: Proxmox/QEMU/KVM, VMware, Hyper-V, Dell, HPE, Supermicro, Physical/Other
    - Recommendation engine
    - Credential safety notice

.SECURITY
    Credentials are collected using Windows PowerShell Get-Credential.
    Passwords are not stored in the script.
    Passwords are not written into CSV, JSON, TXT or HTML reports.
    Credentials exist only in the current PowerShell session memory.

.NOTES
    Remote assessment requires WinRM / PowerShell Remoting on target servers.
    This tool does not modify any setting on local or remote systems.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$Script:ToolName    = "Microsoft Secure Boot 2023 Enterprise Readiness Analyzer"
$Script:ToolVersion = "5.0"
$Script:Author      = "Murat Ozay"
$Script:Credential  = $null
$Script:ReportRoot  = Join-Path $PSScriptRoot "Reports"

if (!(Test-Path $Script:ReportRoot)) {
    New-Item -ItemType Directory -Path $Script:ReportRoot -Force | Out-Null
}

# -----------------------------
# Utility
# -----------------------------

function Expand-Targets {
    param([string]$InputText)

    $items = @()
    $raw = $InputText -split "[,`r`n; ]+" | Where-Object { $_ -and $_.Trim() }

    foreach ($item in $raw) {
        $v = $item.Trim()

        if ($v -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$') {
            $prefix = $matches[1]
            $start  = [int]$matches[2]
            $end    = [int]$matches[3]

            if ($end -ge $start) {
                for ($i=$start; $i -le $end; $i++) {
                    $items += "$prefix$i"
                }
            }
        }
        else {
            $items += $v
        }
    }

    $items | Sort-Object -Unique
}

function Import-TargetsFromFile {
    param([string]$Path)

    if (!(Test-Path $Path)) { return @() }

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()

    if ($ext -eq ".csv") {
        try {
            $csv = Import-Csv $Path
            if ($csv[0].PSObject.Properties.Name -contains "ComputerName") {
                return $csv.ComputerName | Where-Object { $_ }
            }
            elseif ($csv[0].PSObject.Properties.Name -contains "Target") {
                return $csv.Target | Where-Object { $_ }
            }
            elseif ($csv[0].PSObject.Properties.Count -gt 0) {
                $firstCol = $csv[0].PSObject.Properties.Name[0]
                return $csv.$firstCol | Where-Object { $_ }
            }
        } catch {
            return @()
        }
    }
    else {
        return Get-Content $Path | Where-Object { $_ -and $_.Trim() }
    }
}

# -----------------------------
# Assessment Engine
# -----------------------------

$AssessmentScriptBlock = {
    function New-Check {
        param(
            [string]$Name,
            [string]$State,
            [string]$Message,
            [int]$Weight = 10,
            [string]$Category = "General"
        )

        $earned = 0
        switch ($State) {
            "PASS"    { $earned = $Weight }
            "WAITING" { $earned = [math]::Round($Weight * 0.7) }
            "WARN"    { $earned = [math]::Round($Weight * 0.4) }
            "FAIL"    { $earned = 0 }
            "NA"      { $earned = $Weight }
            default   { $earned = 0 }
        }

        [pscustomobject]@{
            Category = $Category
            Name     = $Name
            State    = $State
            Message  = $Message
            Weight   = $Weight
            Earned   = $earned
        }
    }

    $Checks = @()

    $FirmwareType = "Unknown"
    $SecureBootStatus = $null

    $Db2023 = $false
    $Db2011 = $false
    $Kek2023 = $false
    $Kek2011 = $false

    $Has1808 = $false
    $Has1801 = $false
    $Has1803 = $false
    $Has1796 = $false
    $Has1795 = $false

    $UEFICA2023Status = $null
    $WindowsUEFICA2023Capable = $null
    $UEFICA2023Error = $null
    $SecureBootFolder = $false

    $Platform = "Unknown"
    $RiskLevel = "Unknown"
    $PlatformAdvice = ""
    $PrimaryRecommendation = ""

    try {
        $OS = Get-ComputerInfo
        $OSName       = $OS.OsName
        $OSVersion    = $OS.OsVersion
        $OSBuild      = $OS.OsBuildNumber
        $Manufacturer = $OS.CsManufacturer
        $Model        = $OS.CsModel
        $FirmwareType = $OS.BiosFirmwareType
    }
    catch {
        $wmiOs = Get-CimInstance Win32_OperatingSystem
        $OSName    = $wmiOs.Caption
        $OSVersion = $wmiOs.Version
        $OSBuild   = $wmiOs.BuildNumber

        $cs = Get-CimInstance Win32_ComputerSystem
        $Manufacturer = $cs.Manufacturer
        $Model        = $cs.Model

        if ($env:firmware_type) { $FirmwareType = $env:firmware_type }
    }

    $manModel = "$Manufacturer $Model"

    if ($manModel -match "QEMU|KVM|Bochs|Standard PC \(Q35|Proxmox") {
        $Platform = "QEMU / KVM / Proxmox"
    }
    elseif ($manModel -match "VMware") {
        $Platform = "VMware"
    }
    elseif ($manModel -match "Virtual Machine|Hyper-V|Microsoft Corporation") {
        $Platform = "Microsoft Hyper-V"
    }
    elseif ($manModel -match "Dell|PowerEdge") {
        $Platform = "Dell Physical Server"
    }
    elseif ($manModel -match "HPE|HP|ProLiant") {
        $Platform = "HPE Physical Server"
    }
    elseif ($manModel -match "Supermicro") {
        $Platform = "Supermicro Physical Server"
    }
    elseif ($manModel -match "Amazon|EC2") {
        $Platform = "AWS EC2"
    }
    elseif ($manModel -match "Google") {
        $Platform = "Google Cloud VM"
    }
    elseif ($manModel -match "Azure") {
        $Platform = "Azure VM"
    }
    else {
        $Platform = "Physical / Other"
    }

    # OS lifecycle advisory
    if ($OSName -match "2012") {
        $Checks += New-Check "OS Lifecycle" "WARN" "Windows Server 2012/2012 R2 detected; upgrade or migration is strongly recommended" 10 "System"
    }
    elseif ($OSName -match "2016") {
        $Checks += New-Check "OS Lifecycle" "WAITING" "Windows Server 2016 detected; verify latest cumulative updates and firmware" 10 "System"
    }
    elseif ($OSName -match "2019|2022|2025|Windows 10|Windows 11") {
        $Checks += New-Check "OS Lifecycle" "PASS" "Supported OS family detected for Secure Boot readiness validation" 10 "System"
    }
    else {
        $Checks += New-Check "OS Lifecycle" "WARN" "OS family could not be mapped; manual lifecycle review recommended" 10 "System"
    }

    # Firmware
    if ($FirmwareType -match "Uefi") {
        $Checks += New-Check "Firmware" "PASS" "UEFI mode detected" 10 "Firmware"
    }
    else {
        $Checks += New-Check "Firmware" "NA" "Legacy BIOS detected; Secure Boot 2023 does not directly apply" 10 "Firmware"
    }

    # Secure Boot
    try {
        $SecureBootStatus = Confirm-SecureBootUEFI
        if ($SecureBootStatus -eq $true) {
            $Checks += New-Check "Secure Boot" "PASS" "Secure Boot is enabled" 10 "Firmware"
        }
        else {
            $Checks += New-Check "Secure Boot" "NA" "Secure Boot is disabled; direct impact is not expected" 10 "Firmware"
        }
    }
    catch {
        $SecureBootStatus = "Unsupported"
        $Checks += New-Check "Secure Boot" "NA" "Unsupported or Legacy BIOS" 10 "Firmware"
    }

    # DB / KEK
    if ($SecureBootStatus -eq $true) {
        try {
            $db = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name db).Bytes)
            $Db2023 = $db -match "Windows UEFI CA 2023"
            $Db2011 = $db -match "Windows Production PCA 2011"

            if ($Db2023) { $Checks += New-Check "DB 2023" "PASS" "Windows UEFI CA 2023 found" 20 "Certificate" }
            else { $Checks += New-Check "DB 2023" "WARN" "Windows UEFI CA 2023 not found" 20 "Certificate" }

            if ($Db2011) { $Checks += New-Check "DB 2011" "PASS" "Windows Production PCA 2011 found" 5 "Certificate" }
            else { $Checks += New-Check "DB 2011" "WARN" "Windows Production PCA 2011 not found" 5 "Certificate" }
        }
        catch {
            $Checks += New-Check "DB" "FAIL" "UEFI DB could not be read" 20 "Certificate"
        }

        try {
            $kek = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name KEK).Bytes)
            $Kek2023 = $kek -match "KEK 2K CA 2023"
            $Kek2011 = $kek -match "KEK CA 2011"

            if ($Kek2023) { $Checks += New-Check "KEK 2023" "PASS" "KEK 2K CA 2023 found" 20 "Certificate" }
            else { $Checks += New-Check "KEK 2023" "WARN" "KEK 2K CA 2023 not found" 20 "Certificate" }

            if ($Kek2011) { $Checks += New-Check "KEK 2011" "PASS" "KEK CA 2011 found" 5 "Certificate" }
            else { $Checks += New-Check "KEK 2011" "WARN" "KEK CA 2011 not found" 5 "Certificate" }
        }
        catch {
            $Checks += New-Check "KEK" "FAIL" "UEFI KEK could not be read" 20 "Certificate"
        }
    }
    else {
        $Checks += New-Check "DB / KEK" "NA" "Secure Boot is not active; certificate validation not required" 20 "Certificate"
    }

    # Servicing Registry
    $svc = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"

    if (Test-Path $svc) {
        $reg = Get-ItemProperty $svc

        $UEFICA2023Status = $reg.UEFICA2023Status
        $WindowsUEFICA2023Capable = $reg.WindowsUEFICA2023Capable
        $UEFICA2023Error = $reg.UEFICA2023Error

        $Checks += New-Check "Servicing Registry" "PASS" "Secure Boot Servicing registry exists" 10 "Windows"

        if ($UEFICA2023Status -match "Updated|Completed|Complete|Done|Success") {
            $Checks += New-Check "UEFICA2023Status" "PASS" "Secure Boot 2023 transition completed" 15 "Windows"
        }
        elseif ($UEFICA2023Status -match "NotStarted|Pending|InProgress|Updating") {
            $Checks += New-Check "UEFICA2023Status" "WAITING" "Transition state: $UEFICA2023Status" 15 "Windows"
        }
        else {
            $Checks += New-Check "UEFICA2023Status" "WAITING" "No clear completed status" 15 "Windows"
        }

        if ($UEFICA2023Error) {
            $Checks += New-Check "UEFICA2023Error" "FAIL" "Error detected: $UEFICA2023Error" 20 "Windows"
        }
        else {
            $Checks += New-Check "UEFICA2023Error" "PASS" "No error detected" 20 "Windows"
        }
    }
    else {
        if ($SecureBootStatus -eq $true -and $Db2023 -and $Kek2023) {
            $Checks += New-Check "Servicing Registry" "WAITING" "Registry not found; firmware already has 2023 certificates" 10 "Windows"
        }
        elseif ($SecureBootStatus -eq $true) {
            $Checks += New-Check "Servicing Registry" "WAITING" "Windows servicing has not started yet" 10 "Windows"
        }
        else {
            $Checks += New-Check "Servicing Registry" "NA" "Secure Boot is not active" 10 "Windows"
        }
    }

    # SecureBoot Folder
    $SecureBootFolder = Test-Path "C:\Windows\SecureBoot"
    if ($SecureBootFolder) {
        $Checks += New-Check "C:\Windows\SecureBoot" "PASS" "SecureBoot folder exists" 5 "Windows"
    }
    else {
        if ($SecureBootStatus -eq $true) {
            $Checks += New-Check "C:\Windows\SecureBoot" "WAITING" "Folder not found; servicing may not have used it yet" 5 "Windows"
        }
        else {
            $Checks += New-Check "C:\Windows\SecureBoot" "NA" "Secure Boot is not active" 5 "Windows"
        }
    }

    # Hotfix
    try {
        $Hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, InstalledOn
        if ($Hotfixes) {
            $Checks += New-Check "Windows HotFix" "PASS" "HotFix information was read successfully" 5 "Windows"
        }
        else {
            $Checks += New-Check "Windows HotFix" "WARN" "HotFix list is empty" 5 "Windows"
        }
    }
    catch {
        $Hotfixes = @()
        $Checks += New-Check "Windows HotFix" "WARN" "HotFix information could not be read" 5 "Windows"
    }

    # Events
    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName='System'
            Id=1795,1796,1799,1801,1803,1808
        } -MaxEvents 20 -ErrorAction SilentlyContinue

        if ($Events) {
            $Has1808 = [bool]($Events | Where-Object { $_.Id -eq 1808 })
            $Has1801 = [bool]($Events | Where-Object { $_.Id -eq 1801 })
            $Has1803 = [bool]($Events | Where-Object { $_.Id -eq 1803 })
            $Has1796 = [bool]($Events | Where-Object { $_.Id -eq 1796 })
            $Has1795 = [bool]($Events | Where-Object { $_.Id -eq 1795 })
        }

        if ($Has1808) {
            $Checks += New-Check "Event 1808" "PASS" "Successful Secure Boot 2023 event found" 15 "Event"
        }
        else {
            if ($SecureBootStatus -eq $true -and $Db2023 -and $Kek2023) {
                $Checks += New-Check "Event 1808" "WAITING" "1808 not found; firmware certificates already look ready" 15 "Event"
            }
            elseif ($SecureBootStatus -eq $true) {
                $Checks += New-Check "Event 1808" "WAITING" "1808 success event not found yet" 15 "Event"
            }
            else {
                $Checks += New-Check "Event 1808" "NA" "Secure Boot is not active" 15 "Event"
            }
        }

        if ($Has1795 -or $Has1796 -or $Has1803) {
            $Checks += New-Check "Critical Events" "FAIL" "1795 / 1796 / 1803 detected" 25 "Event"
        }
        else {
            $Checks += New-Check "Critical Events" "PASS" "No 1795 / 1796 / 1803 critical event found" 25 "Event"
        }
    }
    catch {
        $Events = @()
        $Checks += New-Check "Event Log" "WARN" "Event Log could not be read" 10 "Event"
    }

    $Score = ($Checks | Measure-Object -Property Earned -Sum).Sum
    $MaxScore = ($Checks | Measure-Object -Property Weight -Sum).Sum
    $Percent = 0
    if ($MaxScore -gt 0) {
        $Percent = [math]::Round(($Score / $MaxScore) * 100, 0)
    }

    $CriticalIssue = [bool]($Checks | Where-Object { $_.State -eq "FAIL" })
    $WaitingState = [bool]($Checks | Where-Object { $_.State -eq "WAITING" })

    # Platform advice
    if ($Platform -eq "QEMU / KVM / Proxmox") {
        if ($SecureBootStatus -eq $true -and $Db2023 -and $Kek2023) {
            $PlatformAdvice = "Proxmox/QEMU VM appears compatible. If efidisk uses ms-cert=2023k and Proxmox pve-edk2-firmware is current, the 2023 Secure Boot chain is expected to be ready."
        }
        else {
            $PlatformAdvice = "Proxmox/QEMU VM detected. Verify OVMF, efidisk0, pre-enrolled-keys and ms-cert=2023k where applicable."
        }
    }
    elseif ($Platform -eq "VMware") {
        $PlatformAdvice = "VMware VM detected. Verify ESXi/vCenter build level, VM hardware version, Secure Boot, vTPM/BitLocker usage, and Broadcom Secure Boot certificate guidance."
    }
    elseif ($Platform -eq "Microsoft Hyper-V") {
        $PlatformAdvice = "Hyper-V VM detected. Generation 2 + Secure Boot systems should be verified with latest host and guest updates."
    }
    elseif ($Platform -match "Physical Server") {
        $PlatformAdvice = "Physical server detected. Verify BIOS/UEFI firmware, vendor advisory and Secure Boot certificate update support."
    }
    elseif ($Platform -match "AWS|Azure|Google") {
        $PlatformAdvice = "Cloud VM detected. Verify cloud provider Secure Boot and firmware support guidance."
    }
    else {
        $PlatformAdvice = "Platform not clearly identified. Review firmware and virtualization layer manually."
    }

    # Overall status
    if ($CriticalIssue) {
        $OverallStatus = "CRITICAL"
        $OverallColor = "RED"
        $RiskLevel = "High"
        $Summary = "Secure Boot 2023 transition has a critical problem."
        $PrimaryRecommendation = "Investigate firmware, KEK, DB and Event Log."
    }
    elseif ($SecureBootStatus -eq $true -and $Db2023 -and $Kek2023 -and ($Has1808 -or $UEFICA2023Status -match "Updated|Completed|Complete|Done|Success")) {
        $OverallStatus = "READY / UPDATED"
        $OverallColor = "GREEN"
        $RiskLevel = "Low"
        $Summary = "Secure Boot 2023 transition is completed successfully."
        $PrimaryRecommendation = "No additional action required. Continue standard Windows Update, firmware and hypervisor lifecycle."
    }
    elseif ($SecureBootStatus -eq $true -and $Db2023 -and $Kek2023) {
        $OverallStatus = "READY"
        $OverallColor = "GREEN"
        $RiskLevel = "Low"
        $Summary = "Secure Boot 2023 certificates are present at firmware level."
        $PrimaryRecommendation = "Complete Windows Update process and monitor Event ID 1808."
    }
    elseif ($Has1801 -or $UEFICA2023Status -match "NotStarted|Pending|InProgress|Updating") {
        $OverallStatus = "ATTENTION / WAITING"
        $OverallColor = "YELLOW"
        $RiskLevel = "Medium"
        $Summary = "Secure Boot 2023 transition is waiting or in progress."
        $PrimaryRecommendation = "Monitor Windows Update, firmware state and Event Log."
    }
    elseif ($SecureBootStatus -eq "Unsupported" -or $SecureBootStatus -eq $false) {
        $OverallStatus = "NOT AFFECTED"
        $OverallColor = "GREEN"
        $RiskLevel = "Low"
        $Summary = "Legacy BIOS or Secure Boot disabled."
        $PrimaryRecommendation = "No Secure Boot 2023 action required. Continue standard lifecycle."
    }
    else {
        $OverallStatus = "REVIEW REQUIRED"
        $OverallColor = "YELLOW"
        $RiskLevel = "Medium"
        $Summary = "No clear result."
        $PrimaryRecommendation = "Manual review is recommended."
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        OSName = $OSName
        OSVersion = $OSVersion
        OSBuild = $OSBuild
        Manufacturer = $Manufacturer
        Model = $Model
        Platform = $Platform
        PlatformAdvice = $PlatformAdvice
        Firmware = $FirmwareType
        SecureBoot = $SecureBootStatus
        DB2023 = $Db2023
        DB2011 = $Db2011
        KEK2023 = $Kek2023
        KEK2011 = $Kek2011
        UEFICA2023Status = $UEFICA2023Status
        WindowsUEFICA2023Capable = $WindowsUEFICA2023Capable
        UEFICA2023Error = $UEFICA2023Error
        SecureBootFolder = $SecureBootFolder
        Event1808 = $Has1808
        Event1801 = $Has1801
        Event1803 = $Has1803
        Event1796 = $Has1796
        Event1795 = $Has1795
        Score = $Score
        MaxScore = $MaxScore
        Percent = $Percent
        RiskLevel = $RiskLevel
        OverallStatus = $OverallStatus
        OverallColor = $OverallColor
        Summary = $Summary
        RecommendedAction = $PrimaryRecommendation
        Checks = $Checks
        Hotfixes = $Hotfixes
    }
}

# -----------------------------
# Output
# -----------------------------

function Write-AssessmentToConsole {
    param($Result)

    Clear-Host
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host " $($Script:ToolName)" -ForegroundColor Cyan
    Write-Host " Version : $($Script:ToolVersion)" -ForegroundColor Cyan
    Write-Host " Author  : $($Script:Author)" -ForegroundColor Cyan
    Write-Host " Mode    : READ ONLY" -ForegroundColor Cyan
    Write-Host "====================================================================" -ForegroundColor Cyan
    Write-Host ""

    $statusColor = if ($Result.OverallColor -eq "GREEN") {"Green"} elseif ($Result.OverallColor -eq "RED") {"Red"} else {"Yellow"}
    Write-Host "OVERALL STATUS : $($Result.OverallStatus)" -ForegroundColor $statusColor
    Write-Host "READINESS      : $($Result.Percent)%"
    Write-Host "RISK LEVEL     : $($Result.RiskLevel)"
    Write-Host ""

    Write-Host "Computer Name  : $($Result.ComputerName)"
    Write-Host "OS             : $($Result.OSName)"
    Write-Host "OS Version     : $($Result.OSVersion)"
    Write-Host "OS Build       : $($Result.OSBuild)"
    Write-Host "Manufacturer   : $($Result.Manufacturer)"
    Write-Host "Model          : $($Result.Model)"
    Write-Host "Platform       : $($Result.Platform)"
    Write-Host ""

    $currentCategory = ""
    foreach ($c in $Result.Checks) {
        if ($c.Category -ne $currentCategory) {
            $currentCategory = $c.Category
            Write-Host ""
            Write-Host "[$currentCategory]" -ForegroundColor Cyan
        }

        $color = switch ($c.State) {
            "PASS" {"Green"}
            "WAITING" {"Yellow"}
            "WARN" {"Yellow"}
            "FAIL" {"Red"}
            "NA" {"Gray"}
            default {"White"}
        }

        Write-Host ("[{0,-7}] {1,-28} : {2}" -f $c.State, $c.Name, $c.Message) -ForegroundColor $color
    }

    Write-Host ""
    Write-Host "Score    : $($Result.Score) / $($Result.MaxScore) ($($Result.Percent)%)"

    if ($Result.Percent -ge 95) {
        Write-Host "Progress : [####################] $($Result.Percent)%" -ForegroundColor Green
    }
    elseif ($Result.Percent -ge 75) {
        Write-Host "Progress : [###############-----] $($Result.Percent)%" -ForegroundColor Yellow
    }
    else {
        Write-Host "Progress : [########------------] $($Result.Percent)%" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "SUMMARY       : $($Result.Summary)"
    Write-Host "ACTION        : $($Result.RecommendedAction)"
    Write-Host "PLATFORM NOTE : $($Result.PlatformAdvice)"
    Write-Host ""
}

function Save-AssessmentReport {
    param(
        $Results,
        [string]$ReportRoot
    )

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $csvPath  = Join-Path $ReportRoot "SecureBoot_Assessment_$timestamp.csv"
    $jsonPath = Join-Path $ReportRoot "SecureBoot_Assessment_$timestamp.json"
    $txtPath  = Join-Path $ReportRoot "SecureBoot_Assessment_$timestamp.txt"
    $htmlPath = Join-Path $ReportRoot "SecureBoot_Assessment_$timestamp.html"

    $flat = $Results | Select-Object ComputerName,OSName,OSVersion,OSBuild,Manufacturer,Model,Platform,Firmware,SecureBoot,DB2023,KEK2023,UEFICA2023Status,WindowsUEFICA2023Capable,Event1808,Event1803,Event1796,Event1795,Score,MaxScore,Percent,RiskLevel,OverallStatus,Summary,RecommendedAction,PlatformAdvice

    $flat | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $Results | ConvertTo-Json -Depth 8 | Out-File $jsonPath -Encoding UTF8

    $txt = @()
    $txt += "$($Script:ToolName) v$($Script:ToolVersion)"
    $txt += "Author: $($Script:Author)"
    $txt += "Generated: $(Get-Date)"
    $txt += ""
    foreach ($r in $Results) {
        $txt += "Computer: $($r.ComputerName)"
        $txt += "OS: $($r.OSName)"
        $txt += "Platform: $($r.Platform)"
        $txt += "Status: $($r.OverallStatus)"
        $txt += "Score: $($r.Percent)%"
        $txt += "Summary: $($r.Summary)"
        $txt += "Action: $($r.RecommendedAction)"
        $txt += "Platform Note: $($r.PlatformAdvice)"
        $txt += "-" * 80
    }
    $txt | Out-File $txtPath -Encoding UTF8

    $total       = @($Results).Count
    $ready       = @($Results | Where-Object {$_.OverallStatus -match "READY"}).Count
    $critical    = @($Results | Where-Object {$_.OverallStatus -match "CRITICAL|FAILED"}).Count
    $waiting     = @($Results | Where-Object {$_.OverallStatus -match "WAITING|REVIEW"}).Count
    $notAffected = @($Results | Where-Object {$_.OverallStatus -match "NOT AFFECTED"}).Count

    $avg = 0
    if ($total -gt 0) {
        $avg = [math]::Round((($Results | Measure-Object -Property Percent -Average).Average),0)
    }

    $platformGroups = $Results | Group-Object Platform | Sort-Object Count -Descending
    $platformCards = ""
    foreach ($pg in $platformGroups) {
        $platformCards += "<div class='mini-card'><span>$($pg.Name)</span><b>$($pg.Count)</b></div>`n"
    }

    $rows = ""
    foreach ($r in $flat) {
        $cls = if ($r.OverallStatus -match "CRITICAL|FAILED") {"bad"} elseif ($r.OverallStatus -match "WAITING|REVIEW") {"warn"} else {"ok"}
        $rows += "<tr class='$cls'><td>$($r.ComputerName)</td><td>$($r.OSName)</td><td>$($r.Platform)</td><td>$($r.Firmware)</td><td>$($r.SecureBoot)</td><td>$($r.DB2023)</td><td>$($r.KEK2023)</td><td>$($r.UEFICA2023Status)</td><td>$($r.Event1808)</td><td>$($r.Percent)%</td><td>$($r.RiskLevel)</td><td>$($r.OverallStatus)</td><td>$($r.RecommendedAction)</td><td>$($r.PlatformAdvice)</td></tr>`n"
    }

    $compatibility = @"
<tr><td>Windows Server 2012 / 2012 R2</td><td class="warn-text">Review / Upgrade Recommended</td><td>End of support family. Migration or upgrade should be considered.</td></tr>
<tr><td>Windows Server 2016</td><td class="warn-text">Review</td><td>Latest cumulative updates and firmware should be verified.</td></tr>
<tr><td>Windows Server 2019 / 2022</td><td class="ok-text">Supported</td><td>Validate Secure Boot readiness with latest updates.</td></tr>
<tr><td>Proxmox / QEMU / OVMF</td><td class="ok-text">Ready when current</td><td>Verify OVMF, efidisk0, pre-enrolled-keys and ms-cert=2023k.</td></tr>
<tr><td>VMware</td><td class="warn-text">Vendor Advisory</td><td>Verify ESXi/vCenter build, VM hardware version, Secure Boot, vTPM/BitLocker and Broadcom guidance.</td></tr>
<tr><td>Hyper-V</td><td class="warn-text">Validate Gen2</td><td>Generation 2 + Secure Boot systems should be verified.</td></tr>
<tr><td>Physical Servers</td><td class="warn-text">Firmware Dependent</td><td>Check Dell/HPE/Supermicro/Lenovo BIOS/UEFI firmware advisories.</td></tr>
"@

    $html = @"
<html>
<head>
<meta charset="utf-8">
<title>Secure Boot 2023 Enterprise Readiness Dashboard</title>
<style>
:root {
  --blue:#123a8c;
  --blue2:#1c65d8;
  --cyan:#04b8ff;
  --bg:#f4f7fb;
  --text:#102033;
  --ok:#00a86b;
  --warn:#ffb000;
  --bad:#d12f2f;
}
body { font-family: Segoe UI, Arial, sans-serif; background:var(--bg); color:var(--text); margin:0; }
.header { background:linear-gradient(135deg,var(--blue),var(--blue2)); color:white; padding:28px 34px; }
.header h1 { margin:0; font-size:34px; }
.header .sub { opacity:.9; margin-top:8px; font-size:15px; }
.container { padding:24px 34px; }
.note { background:#eaf4ff; border-left:6px solid var(--blue); padding:13px 16px; margin-bottom:20px; border-radius:8px; }
.cards { display:flex; gap:14px; margin-bottom:22px; flex-wrap:wrap; }
.card { background:white; border-radius:16px; padding:18px 20px; box-shadow:0 6px 18px rgba(16,32,51,.08); min-width:155px; }
.card span { color:#445; font-size:14px; }
.card b { display:block; font-size:32px; color:var(--blue); margin-top:6px; }
.hero { display:grid; grid-template-columns: 1.3fr .7fr; gap:18px; margin-bottom:22px; }
.panel { background:white; border-radius:16px; padding:18px 20px; box-shadow:0 6px 18px rgba(16,32,51,.08); }
.score { font-size:54px; color:var(--blue); font-weight:700; }
.bar { height:18px; background:#dfe7f5; border-radius:30px; overflow:hidden; margin-top:10px; }
.fill { height:100%; background:linear-gradient(90deg,var(--blue2),var(--cyan)); width:${avg}%; }
.mini { display:flex; gap:10px; flex-wrap:wrap; }
.mini-card { background:#f6f9ff; border:1px solid #dde8fb; border-radius:12px; padding:12px 14px; min-width:150px; }
.mini-card span { display:block; font-size:12px; color:#566; }
.mini-card b { font-size:24px; color:var(--blue); }
h2 { color:var(--blue); margin-top:24px; }
table { border-collapse:collapse; width:100%; background:white; box-shadow:0 6px 18px rgba(16,32,51,.08); font-size:13px; border-radius:14px; overflow:hidden; }
th { background:var(--blue); color:white; padding:10px; text-align:left; }
td { padding:9px; border-bottom:1px solid #e5e8ef; vertical-align:top; }
tr.ok td:first-child { border-left:6px solid var(--ok); }
tr.warn td:first-child { border-left:6px solid var(--warn); }
tr.bad td:first-child { border-left:6px solid var(--bad); }
.ok-text { color:var(--ok); font-weight:700; }
.warn-text { color:#a46b00; font-weight:700; }
.bad-text { color:var(--bad); font-weight:700; }
.footer { margin-top:24px; color:#667; font-size:12px; }
</style>
</head>
<body>
<div class="header">
  <h1>Microsoft Secure Boot 2023 Enterprise Readiness Dashboard</h1>
  <div class="sub">Assessment Engine v$($Script:ToolVersion) | Author: $($Script:Author) | Mode: READ ONLY | Generated: $(Get-Date)</div>
</div>
<div class="container">
<div class="note">
<b>Credential safety:</b> This tool does not write credentials into CSV, JSON, TXT or HTML reports. Remote execution uses Windows PowerShell Get-Credential and the credential exists only in the current PowerShell session memory.
</div>

<div class="hero">
  <div class="panel">
    <h2 style="margin-top:0;">Executive Readiness Summary</h2>
    <div class="cards">
      <div class="card"><span>Total</span><b>$total</b></div>
      <div class="card"><span>Ready</span><b>$ready</b></div>
      <div class="card"><span>Waiting / Review</span><b>$waiting</b></div>
      <div class="card"><span>Critical</span><b>$critical</b></div>
      <div class="card"><span>Not Affected</span><b>$notAffected</b></div>
    </div>
  </div>
  <div class="panel">
    <h2 style="margin-top:0;">Average Readiness</h2>
    <div class="score">$avg%</div>
    <div class="bar"><div class="fill"></div></div>
  </div>
</div>

<div class="panel">
<h2 style="margin-top:0;">Platform Distribution</h2>
<div class="mini">
$platformCards
</div>
</div>

<h2>Assessment Results</h2>
<table>
<tr><th>Computer</th><th>OS</th><th>Platform</th><th>Firmware</th><th>Secure Boot</th><th>DB2023</th><th>KEK2023</th><th>UEFICA2023Status</th><th>Event1808</th><th>Score</th><th>Risk</th><th>Status</th><th>Action</th><th>Platform Note</th></tr>
$rows
</table>

<h2>Compatibility Matrix</h2>
<table>
<tr><th>Platform / OS</th><th>Status</th><th>Guidance</th></tr>
$compatibility
</table>

<div class="footer">Reports: CSV, JSON, TXT and HTML generated by $($Script:ToolName) v$($Script:ToolVersion).</div>
</div>
</body>
</html>
"@

    $html | Out-File $htmlPath -Encoding UTF8

    [pscustomobject]@{
        CSV  = $csvPath
        JSON = $jsonPath
        TXT  = $txtPath
        HTML = $htmlPath
    }
}

function Run-LocalAssessment {
    $Script:LastResults = @()
    $txtOutput.AppendText("Running local assessment...`r`n")
    $result = & $AssessmentScriptBlock
    $Script:LastResults = @($result)
    Write-AssessmentToConsole $result
    $saved = Save-AssessmentReport -Results @($result) -ReportRoot $Script:ReportRoot
    $txtOutput.AppendText("OK: Local -> $($result.OverallStatus) / $($result.Percent)%`r`n")
    $txtOutput.AppendText("Reports saved:`r`nCSV: $($saved.CSV)`r`nJSON: $($saved.JSON)`r`nTXT: $($saved.TXT)`r`nHTML: $($saved.HTML)`r`n")
    [System.Windows.Forms.MessageBox]::Show("Local assessment completed.`n`nHTML:`n$($saved.HTML)", "Completed")
}

function Run-RemoteAssessment {
    param([string[]]$Targets)

    $Script:LastResults = @()
    $results = @()
    $progressBar.Value = 0
    $progressBar.Maximum = [Math]::Max($Targets.Count,1)

    foreach ($target in $Targets) {
        $lblStatus.Text = "Checking $target ..."
        $txtOutput.AppendText("Running assessment on $target ...`r`n")
        [System.Windows.Forms.Application]::DoEvents()

        try {
            if ($Script:Credential) {
                $r = Invoke-Command -ComputerName $target -Credential $Script:Credential -ScriptBlock $AssessmentScriptBlock -ErrorAction Stop
            } else {
                $r = Invoke-Command -ComputerName $target -ScriptBlock $AssessmentScriptBlock -ErrorAction Stop
            }

            $results += $r
            $txtOutput.AppendText("OK: $target -> $($r.OverallStatus) / $($r.Percent)%`r`n")
        }
        catch {
            $txtOutput.AppendText("FAILED: $target -> $($_.Exception.Message)`r`n")
            $results += [pscustomobject]@{
                ComputerName = $target
                OSName = ""
                OSVersion = ""
                OSBuild = ""
                Manufacturer = ""
                Model = ""
                Platform = "Unknown"
                PlatformAdvice = "Check WinRM / firewall / credentials."
                Firmware = ""
                SecureBoot = ""
                DB2023 = $false
                DB2011 = $false
                KEK2023 = $false
                KEK2011 = $false
                UEFICA2023Status = ""
                WindowsUEFICA2023Capable = ""
                UEFICA2023Error = $_.Exception.Message
                SecureBootFolder = $false
                Event1808 = $false
                Event1801 = $false
                Event1803 = $false
                Event1796 = $false
                Event1795 = $false
                Score = 0
                MaxScore = 0
                Percent = 0
                RiskLevel = "High"
                OverallStatus = "CONNECTION FAILED"
                OverallColor = "RED"
                Summary = "Could not connect or run assessment."
                RecommendedAction = "Check WinRM / firewall / credentials."
                Checks = @()
                Hotfixes = @()
            }
        }

        if ($progressBar.Value -lt $progressBar.Maximum) { $progressBar.Value++ }
        [System.Windows.Forms.Application]::DoEvents()
    }

    $Script:LastResults = $results
    $saved = Save-AssessmentReport -Results $results -ReportRoot $Script:ReportRoot
    $lblStatus.Text = "Completed"
    $txtOutput.AppendText("`r`nReports saved:`r`nCSV: $($saved.CSV)`r`nJSON: $($saved.JSON)`r`nTXT: $($saved.TXT)`r`nHTML: $($saved.HTML)`r`n")
    [System.Windows.Forms.MessageBox]::Show("Remote assessment completed.`n`nHTML:`n$($saved.HTML)", "Completed")
}

# -----------------------------
# GUI
# -----------------------------

$form = New-Object System.Windows.Forms.Form
$form.Text = "Secure Boot Enterprise Analyzer v5.0"
$form.Size = New-Object System.Drawing.Size(1120, 760)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(244,247,251)

$fontTitle = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$fontNormal = New-Object System.Drawing.Font("Segoe UI", 9)
$fontSmall = New-Object System.Drawing.Font("Segoe UI", 8)
$blue = [System.Drawing.Color]::FromArgb(18,58,140)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "Microsoft Secure Boot 2023 Enterprise Readiness Analyzer v5.0"
$lblTitle.Font = $fontTitle
$lblTitle.ForeColor = $blue
$lblTitle.Location = New-Object System.Drawing.Point(22, 18)
$lblTitle.Size = New-Object System.Drawing.Size(1000, 34)
$form.Controls.Add($lblTitle)

$lblSecurity = New-Object System.Windows.Forms.Label
$lblSecurity.Text = "Credential safety: Password is not stored or written to reports. Get-Credential is used only for current session remote execution."
$lblSecurity.Font = $fontSmall
$lblSecurity.ForeColor = [System.Drawing.Color]::DarkGreen
$lblSecurity.Location = New-Object System.Drawing.Point(24, 58)
$lblSecurity.Size = New-Object System.Drawing.Size(980, 20)
$form.Controls.Add($lblSecurity)

$groupTargets = New-Object System.Windows.Forms.GroupBox
$groupTargets.Text = "Targets"
$groupTargets.Font = $fontNormal
$groupTargets.Location = New-Object System.Drawing.Point(24, 90)
$groupTargets.Size = New-Object System.Drawing.Size(510, 220)
$form.Controls.Add($groupTargets)

$lblTargets = New-Object System.Windows.Forms.Label
$lblTargets.Text = "Hostname / IP / List / Range: 10.0.0.1-10.0.0.20"
$lblTargets.Location = New-Object System.Drawing.Point(14, 25)
$lblTargets.Size = New-Object System.Drawing.Size(450, 20)
$groupTargets.Controls.Add($lblTargets)

$txtTargets = New-Object System.Windows.Forms.TextBox
$txtTargets.Multiline = $true
$txtTargets.ScrollBars = "Vertical"
$txtTargets.Location = New-Object System.Drawing.Point(16, 50)
$txtTargets.Size = New-Object System.Drawing.Size(470, 115)
$txtTargets.Font = New-Object System.Drawing.Font("Consolas", 9)
$groupTargets.Controls.Add($txtTargets)

$btnImportTxt = New-Object System.Windows.Forms.Button
$btnImportTxt.Text = "Import TXT/CSV"
$btnImportTxt.Location = New-Object System.Drawing.Point(16, 175)
$btnImportTxt.Size = New-Object System.Drawing.Size(130, 30)
$btnImportTxt.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = "Text or CSV|*.txt;*.csv|All Files|*.*"
    if ($ofd.ShowDialog() -eq "OK") {
        $targets = Import-TargetsFromFile $ofd.FileName
        $txtTargets.Text = ($targets -join "`r`n")
    }
})
$groupTargets.Controls.Add($btnImportTxt)

$btnClearTargets = New-Object System.Windows.Forms.Button
$btnClearTargets.Text = "Clear Targets"
$btnClearTargets.Location = New-Object System.Drawing.Point(160, 175)
$btnClearTargets.Size = New-Object System.Drawing.Size(120, 30)
$btnClearTargets.Add_Click({ $txtTargets.Clear() })
$groupTargets.Controls.Add($btnClearTargets)

$groupActions = New-Object System.Windows.Forms.GroupBox
$groupActions.Text = "Assessment"
$groupActions.Font = $fontNormal
$groupActions.Location = New-Object System.Drawing.Point(554, 90)
$groupActions.Size = New-Object System.Drawing.Size(520, 220)
$form.Controls.Add($groupActions)

$lblCredential = New-Object System.Windows.Forms.Label
$lblCredential.Text = "Credential: Not Set"
$lblCredential.ForeColor = [System.Drawing.Color]::DarkRed
$lblCredential.Location = New-Object System.Drawing.Point(20, 28)
$lblCredential.Size = New-Object System.Drawing.Size(460, 20)
$groupActions.Controls.Add($lblCredential)

$btnCred = New-Object System.Windows.Forms.Button
$btnCred.Text = "Set Credential"
$btnCred.Location = New-Object System.Drawing.Point(20, 58)
$btnCred.Size = New-Object System.Drawing.Size(150, 34)
$btnCred.Add_Click({
    $Script:Credential = Get-Credential
    if ($Script:Credential) {
        $lblCredential.Text = "Credential: Set ($($Script:Credential.UserName))"
        $lblCredential.ForeColor = [System.Drawing.Color]::DarkGreen
    }
})
$groupActions.Controls.Add($btnCred)

$btnClearCred = New-Object System.Windows.Forms.Button
$btnClearCred.Text = "Clear Credential"
$btnClearCred.Location = New-Object System.Drawing.Point(185, 58)
$btnClearCred.Size = New-Object System.Drawing.Size(150, 34)
$btnClearCred.Add_Click({
    $Script:Credential = $null
    $lblCredential.Text = "Credential: Not Set"
    $lblCredential.ForeColor = [System.Drawing.Color]::DarkRed
})
$groupActions.Controls.Add($btnClearCred)

$btnLocal = New-Object System.Windows.Forms.Button
$btnLocal.Text = "Run Local"
$btnLocal.Location = New-Object System.Drawing.Point(20, 108)
$btnLocal.Size = New-Object System.Drawing.Size(150, 38)
$btnLocal.BackColor = [System.Drawing.Color]::FromArgb(18,58,140)
$btnLocal.ForeColor = [System.Drawing.Color]::White
$btnLocal.FlatStyle = "Flat"
$btnLocal.Add_Click({ Run-LocalAssessment })
$groupActions.Controls.Add($btnLocal)

$btnRemote = New-Object System.Windows.Forms.Button
$btnRemote.Text = "Run Remote"
$btnRemote.Location = New-Object System.Drawing.Point(185, 108)
$btnRemote.Size = New-Object System.Drawing.Size(150, 38)
$btnRemote.BackColor = [System.Drawing.Color]::FromArgb(28,101,216)
$btnRemote.ForeColor = [System.Drawing.Color]::White
$btnRemote.FlatStyle = "Flat"
$btnRemote.Add_Click({
    $targets = @(Expand-Targets $txtTargets.Text)
    if ($targets.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please enter at least one target.", "Warning")
        return
    }
    Run-RemoteAssessment -Targets $targets
})
$groupActions.Controls.Add($btnRemote)

$btnOpenReports = New-Object System.Windows.Forms.Button
$btnOpenReports.Text = "Open Reports"
$btnOpenReports.Location = New-Object System.Drawing.Point(350, 108)
$btnOpenReports.Size = New-Object System.Drawing.Size(140, 38)
$btnOpenReports.Add_Click({
    if (!(Test-Path $Script:ReportRoot)) { New-Item -ItemType Directory -Path $Script:ReportRoot -Force | Out-Null }
    Start-Process explorer.exe $Script:ReportRoot
})
$groupActions.Controls.Add($btnOpenReports)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(20, 166)
$progressBar.Size = New-Object System.Drawing.Size(470, 18)
$groupActions.Controls.Add($progressBar)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "Ready"
$lblStatus.Location = New-Object System.Drawing.Point(20, 188)
$lblStatus.Size = New-Object System.Drawing.Size(470, 20)
$groupActions.Controls.Add($lblStatus)

$groupOutput = New-Object System.Windows.Forms.GroupBox
$groupOutput.Text = "Live Output"
$groupOutput.Font = $fontNormal
$groupOutput.Location = New-Object System.Drawing.Point(24, 328)
$groupOutput.Size = New-Object System.Drawing.Size(1050, 365)
$form.Controls.Add($groupOutput)

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.Location = New-Object System.Drawing.Point(16, 26)
$txtOutput.Size = New-Object System.Drawing.Size(1018, 318)
$txtOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtOutput.BackColor = [System.Drawing.Color]::White
$groupOutput.Controls.Add($txtOutput)

[void]$form.ShowDialog()
