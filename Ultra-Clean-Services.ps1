#requires -Version 5.1

<#
.SYNOPSIS
    Audits and reduces optional Windows background activity with rollback support.

.DESCRIPTION
    This script deliberately does not try to reach a process-count target by
    disabling random services. It applies a small reviewed service preset and
    can disable exact startup entries or scheduled tasks selected from its audit.

    Start with:
        .\Ultra-Clean-Services.ps1 -Mode Audit

    Preview a change:
        .\Ultra-Clean-Services.ps1 -Mode Apply -Preset Lean -NoXbox -WhatIf

    Apply it:
        .\Ultra-Clean-Services.ps1 -Mode Apply -Preset Lean -NoXbox

    Restore the most recent backup:
        .\Ultra-Clean-Services.ps1 -Mode Restore

.NOTES
    Apply and Restore must be run in an elevated PowerShell window.
    Compatible with Windows PowerShell 5.1 and PowerShell 7+ on Windows.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Audit', 'Apply', 'Restore')]
    [string]$Mode = 'Audit',

    [ValidateSet('Safe', 'Lean')]
    [string]$Preset = 'Safe',

    [switch]$NoXbox,
    [switch]$NoPrinting,
    [switch]$NoBluetooth,
    [switch]$NoSearchIndex,
    [switch]$NoLocation,
    [switch]$NoPhoneLink,
    [switch]$NoOfflineMaps,
    [switch]$NoConnectedDevices,
    [switch]$NoNotifications,
    [switch]$NoNetworkSharing,
    [switch]$NoVirtualMachinesOrWSL,

    # Exact audit names only. Wildcards are intentionally not accepted.
    [string[]]$DisableStartupItem = @(),

    # Exact full paths, for example: \Vendor\Update at logon
    [string[]]$DisableScheduledTask = @(),

    # For Apply this is the new backup path; for Restore it is the backup to use.
    [string]$BackupPath,

    [ValidateRange(20, 1000)]
    [int]$TargetProcessCount = 120,

    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'UltraCleanServices')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Section {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host ''
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('-' * $Text.Length) -ForegroundColor DarkGray
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Protect-ReportValue {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    $privatePaths = @(
        [PSCustomObject]@{ Value = $env:LOCALAPPDATA; Token = '%LOCALAPPDATA%' }
        [PSCustomObject]@{ Value = $env:APPDATA; Token = '%APPDATA%' }
        [PSCustomObject]@{ Value = $env:TEMP; Token = '%TEMP%' }
        [PSCustomObject]@{ Value = $env:USERPROFILE; Token = '%USERPROFILE%' }
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) } |
        Sort-Object { $_.Value.Length } -Descending

    foreach ($path in $privatePaths) {
        $text = [regex]::Replace(
            $text,
            [regex]::Escape($path.Value),
            $path.Token,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }
    return $text
}

function Get-ProcessInventory {
    try {
        $items = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
        foreach ($item in $items) {
            [PSCustomObject]@{
                Name           = $item.Name
                ProcessId      = $item.ProcessId
                ParentId       = $item.ParentProcessId
                WorkingSetMB   = if ($null -ne $item.WorkingSetSize) {
                    [math]::Round(([double]$item.WorkingSetSize / 1MB), 1)
                } else { 0 }
                ExecutablePath = $item.ExecutablePath
            }
        }
        return
    } catch {
        # Some locked-down systems deny CIM process queries. The standard
        # process API still provides the count and memory figures we need.
    }

    foreach ($item in @(Get-Process -ErrorAction Stop)) {
        $path = $null
        try { $path = $item.Path } catch { $path = $null }
        [PSCustomObject]@{
            Name           = $item.ProcessName
            ProcessId      = $item.Id
            ParentId       = $null
            WorkingSetMB   = [math]::Round(([double]$item.WorkingSet64 / 1MB), 1)
            ExecutablePath = $path
        }
    }
}

function Get-StartupEntries {
    $entries = [System.Collections.Generic.List[object]]::new()
    $registryLocations = @(
        [PSCustomObject]@{
            Scope = 'Current user'
            Path  = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
        },
        [PSCustomObject]@{
            Scope = 'All users (64-bit)'
            Path  = 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
        },
        [PSCustomObject]@{
            Scope = 'All users (32-bit)'
            Path  = 'Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        }
    )

    foreach ($location in $registryLocations) {
        if (-not (Test-Path -LiteralPath $location.Path)) { continue }
        $key = Get-Item -LiteralPath $location.Path
        foreach ($valueName in $key.GetValueNames()) {
            $value = $key.GetValue(
                $valueName,
                $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            $entries.Add([PSCustomObject]@{
                Name      = $valueName
                Type      = 'RegistryRun'
                Scope     = $location.Scope
                Location  = $location.Path
                Command   = $value
                ValueKind = $key.GetValueKind($valueName).ToString()
            })
        }
    }

    $startupLocations = @(
        [PSCustomObject]@{
            Scope = 'Current user'
            Path  = [Environment]::GetFolderPath('Startup')
        },
        [PSCustomObject]@{
            Scope = 'All users'
            Path  = [Environment]::GetFolderPath('CommonStartup')
        }
    )

    foreach ($location in $startupLocations) {
        if ([string]::IsNullOrWhiteSpace($location.Path)) { continue }
        if (-not (Test-Path -LiteralPath $location.Path)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $location.Path -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.Name -ieq 'desktop.ini') { continue }
            $entries.Add([PSCustomObject]@{
                Name      = $file.BaseName
                Type      = 'StartupFolder'
                Scope     = $location.Scope
                Location  = $file.FullName
                Command   = $file.FullName
                ValueKind = $null
            })
        }
    }

    return @($entries)
}

function Get-EnabledThirdPartyTasks {
    if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        return @()
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        if ($task.TaskPath -like '\Microsoft\Windows\*') { continue }
        if (-not $task.Settings.Enabled) { continue }

        $triggerNames = @(
            foreach ($trigger in @($task.Triggers)) {
                if ($null -ne $trigger -and $null -ne $trigger.CimClass) {
                    $trigger.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Trigger$', ''
                }
            }
        )
        $actionText = @(
            foreach ($action in @($task.Actions)) {
                if ($null -ne $action.Execute) {
                    (($action.Execute, $action.Arguments) -join ' ').Trim()
                }
            }
        )

        $results.Add([PSCustomObject]@{
            FullName = $task.TaskPath + $task.TaskName
            State    = $task.State
            Triggers = $triggerNames -join ', '
            Actions  = $actionText -join ' | '
        })
    }
    return @($results)
}

function Get-AutomaticServices {
    try {
        $items = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Where-Object { $_.StartMode -eq 'Auto' })
        foreach ($service in $items) {
            [PSCustomObject]@{
                Name        = $service.Name
                DisplayName = $service.DisplayName
                State       = $service.State
                ProcessId   = $service.ProcessId
                Account     = $service.StartName
                Path        = $service.PathName
            }
        }
        return
    } catch {
        # Fall back when CIM is blocked by local policy.
    }

    foreach ($service in @(Get-Service -ErrorAction Stop |
        Where-Object { $_.StartType -eq 'Automatic' })) {
        [PSCustomObject]@{
            Name        = $service.Name
            DisplayName = $service.DisplayName
            State       = $service.Status
            ProcessId   = $null
            Account     = $null
            Path        = $null
        }
    }
}

function New-AuditReport {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][int]$Target,
        [switch]$SkipFiles
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $reportDirectory = Join-Path (Join-Path $Root 'Reports') $stamp
    if (-not $SkipFiles) {
        New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
    }

    Write-Host 'Collecting process, startup, service, and task information...'
    $processes = @(Get-ProcessInventory)
    $startup = @(Get-StartupEntries)
    $services = @(Get-AutomaticServices)
    $tasks = @(Get-EnabledThirdPartyTasks)

    $processGroups = @($processes | Group-Object Name | ForEach-Object {
        [PSCustomObject]@{
            Count            = $_.Count
            Name             = $_.Name
            TotalWorkingSetMB = [math]::Round((($_.Group | Measure-Object WorkingSetMB -Sum).Sum), 1)
        }
    } | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, Name)
    if (-not $SkipFiles) {
        $processes |
            Sort-Object Name, ProcessId |
            Select-Object Name, ProcessId, ParentId, WorkingSetMB,
                @{ Name = 'ExecutablePath'; Expression = { Protect-ReportValue $_.ExecutablePath } } |
            Export-Csv -LiteralPath (Join-Path $reportDirectory 'Processes.csv') -NoTypeInformation -Encoding UTF8
        $processGroups |
            Export-Csv -LiteralPath (Join-Path $reportDirectory 'Process-Groups.csv') -NoTypeInformation -Encoding UTF8
        $startup |
            Sort-Object Name, Scope |
            Select-Object Name, Type, Scope,
                @{ Name = 'Location'; Expression = { Protect-ReportValue $_.Location } },
                @{ Name = 'Command'; Expression = { Protect-ReportValue $_.Command } },
                ValueKind |
            Export-Csv -LiteralPath (Join-Path $reportDirectory 'Startup-Items.csv') -NoTypeInformation -Encoding UTF8
        $services |
            Sort-Object Name |
            Select-Object Name, DisplayName, State, ProcessId, Account,
                @{ Name = 'Path'; Expression = { Protect-ReportValue $_.Path } } |
            Export-Csv -LiteralPath (Join-Path $reportDirectory 'Automatic-Services.csv') -NoTypeInformation -Encoding UTF8
        $tasks |
            Sort-Object FullName |
            Select-Object FullName, State, Triggers,
                @{ Name = 'Actions'; Expression = { Protect-ReportValue $_.Actions } } |
            Export-Csv -LiteralPath (Join-Path $reportDirectory 'Third-Party-Tasks.csv') -NoTypeInformation -Encoding UTF8
    }

    $groups = @($processes | Group-Object Name | Sort-Object -Property `
        @{ Expression = 'Count'; Descending = $true },
        @{ Expression = 'Name'; Descending = $false })
    $topGroups = @($groups | Select-Object -First 20 | ForEach-Object {
        '  {0,3}  {1}' -f $_.Count, $_.Name
    })

    $summary = @(
        'Ultra Clean Services audit'
        'Created: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')
        'Windows: {0}' -f ([Environment]::OSVersion.VersionString)
        ''
        'Current process count: {0}' -f $processes.Count
        'Requested target:      {0}' -f $Target
        'Difference:            {0}' -f ($processes.Count - $Target)
        'Startup entries:       {0}' -f $startup.Count
        'Automatic services:    {0}' -f $services.Count
        'Enabled non-Windows scheduled tasks: {0}' -f $tasks.Count
        ''
        'Most duplicated process names:'
        $topGroups
        ''
        'A process target is a measurement, not a safe stopping condition.'
        'Review Startup-Items.csv and Third-Party-Tasks.csv for the biggest wins.'
    )
    if (-not $SkipFiles) {
        $summary | Set-Content -LiteralPath (Join-Path $reportDirectory 'Summary.txt') -Encoding UTF8
    }

    Write-Section 'Audit result'
    Write-Host ('Processes now:       {0}' -f $processes.Count)
    Write-Host ('Requested target:    {0}' -f $Target)
    Write-Host ('Startup entries:     {0}' -f $startup.Count)
    Write-Host ('Third-party tasks:   {0}' -f $tasks.Count)
    if ($SkipFiles) {
        Write-Host 'Report folder:       not written during preview' -ForegroundColor DarkGray
    } else {
        Write-Host ('Report folder:       {0}' -f $reportDirectory) -ForegroundColor Green
    }
    Write-Host ''
    Write-Host 'Most duplicated process names:' -ForegroundColor Yellow
    $topGroups | ForEach-Object { Write-Host $_ }

    return [PSCustomObject]@{
        Directory    = if ($SkipFiles) { $null } else { $reportDirectory }
        ProcessCount = $processes.Count
        Startup      = $startup
        Tasks        = $tasks
    }
}

function Add-ServiceRule {
    param(
        [Parameter(Mandatory)][hashtable]$Rules,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Manual', 'Disabled')][string]$StartupType,
        [Parameter(Mandatory)][string]$Reason
    )
    $Rules[$Name] = [PSCustomObject]@{
        Name        = $Name
        StartupType = $StartupType
        Reason      = $Reason
    }
}

function Get-ServiceRules {
    $rules = @{}

    # Low-risk baseline: obsolete or remote-management features on a home PC.
    Add-ServiceRule $rules 'Fax' 'Disabled' 'Windows faxing'
    Add-ServiceRule $rules 'RetailDemo' 'Disabled' 'Retail demonstration mode'
    Add-ServiceRule $rules 'RemoteRegistry' 'Disabled' 'Remote Registry access'
    Add-ServiceRule $rules 'WMPNetworkSvc' 'Disabled' 'Legacy Windows Media Player sharing'

    if ($Preset -eq 'Lean') {
        Add-ServiceRule $rules 'DiagTrack' 'Disabled' 'Optional diagnostics and telemetry'
        Add-ServiceRule $rules 'dmwappushservice' 'Disabled' 'Optional WAP push diagnostics channel'
        Add-ServiceRule $rules 'WerSvc' 'Manual' 'Start Windows Error Reporting only when requested'
    }

    if ($NoXbox) {
        Add-ServiceRule $rules 'XblAuthManager' 'Disabled' 'Xbox Live authentication'
        Add-ServiceRule $rules 'XblGameSave' 'Disabled' 'Xbox Live cloud saves'
        Add-ServiceRule $rules 'XboxNetApiSvc' 'Disabled' 'Xbox Live networking'
        Add-ServiceRule $rules 'XboxGipSvc' 'Disabled' 'Xbox accessory management'
    }
    if ($NoPrinting) {
        Add-ServiceRule $rules 'Spooler' 'Disabled' 'Printing, including Microsoft Print to PDF'
    }
    if ($NoBluetooth) {
        Add-ServiceRule $rules 'bthserv' 'Disabled' 'Bluetooth device support'
    }
    if ($NoSearchIndex) {
        Add-ServiceRule $rules 'WSearch' 'Disabled' 'Windows content indexing'
    }
    if ($NoLocation) {
        Add-ServiceRule $rules 'lfsvc' 'Disabled' 'Windows location service'
    }
    if ($NoPhoneLink) {
        Add-ServiceRule $rules 'PhoneSvc' 'Disabled' 'Phone Link telephony support'
    }
    if ($NoOfflineMaps) {
        Add-ServiceRule $rules 'MapsBroker' 'Disabled' 'Downloaded and offline maps'
    }
    if ($NoConnectedDevices) {
        Add-ServiceRule $rules 'CDPSvc' 'Disabled' 'Nearby sharing and cross-device experiences'
        Add-ServiceRule $rules 'CDPUserSvc' 'Disabled' 'Per-user cross-device experiences'
    }
    if ($NoNotifications) {
        Add-ServiceRule $rules 'WpnService' 'Disabled' 'Windows push notifications'
        Add-ServiceRule $rules 'WpnUserService' 'Disabled' 'Per-user Windows notifications'
    }
    if ($NoNetworkSharing) {
        Add-ServiceRule $rules 'LanmanServer' 'Disabled' 'Inbound Windows file and printer sharing'
    }
    if ($NoVirtualMachinesOrWSL) {
        Add-ServiceRule $rules 'vmms' 'Disabled' 'Hyper-V virtual machine management'
        Add-ServiceRule $rules 'vmcompute' 'Disabled' 'Hyper-V containers and compute'
        Add-ServiceRule $rules 'WSLService' 'Disabled' 'Windows Subsystem for Linux'
        Add-ServiceRule $rules 'LxssManager' 'Disabled' 'Legacy Windows Subsystem for Linux management'
    }

    return @($rules.Values | Sort-Object Name)
}

function Get-ServiceChange {
    param([Parameter(Mandatory)][object]$Rule)

    $escapedName = $Rule.Name.Replace("'", "''")
    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escapedName'" -ErrorAction Stop
    } catch {
        $service = $null
    }

    if ($null -ne $service) {
        $currentType = switch ($service.StartMode) {
            'Auto' { 'Automatic' }
            'Manual' { 'Manual' }
            'Disabled' { 'Disabled' }
            default { [string]$service.StartMode }
        }
        $displayName = $service.DisplayName
        $isRunning = $service.State -eq 'Running'
    } else {
        $serviceController = Get-Service -Name $Rule.Name -ErrorAction SilentlyContinue
        if ($null -eq $serviceController) { return $null }
        $currentType = [string]$serviceController.StartType
        $displayName = $serviceController.DisplayName
        $isRunning = $serviceController.Status -eq 'Running'
    }
    $needsTypeChange = $currentType -ne $Rule.StartupType
    $needsStop = $Rule.StartupType -eq 'Disabled' -and $isRunning
    if (-not $needsTypeChange -and -not $needsStop) { return $null }

    $delayed = $false
    $registryPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{0}' -f $Rule.Name
    if (Test-Path -LiteralPath $registryPath) {
        $property = Get-ItemProperty -LiteralPath $registryPath -Name DelayedAutoStart -ErrorAction SilentlyContinue
        if ($null -ne $property) { $delayed = [bool]$property.DelayedAutoStart }
    }

    return [PSCustomObject]@{
        Name                 = $Rule.Name
        DisplayName          = $displayName
        Reason               = $Rule.Reason
        DesiredStartupType   = $Rule.StartupType
        OriginalStartupType  = $currentType
        OriginalDelayedStart = $delayed
        WasRunning           = $isRunning
    }
}

function Find-StartupChanges {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$AllEntries,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$RequestedNames,
        [Parameter(Mandatory)][string]$AssetDirectory
    )

    $changes = [System.Collections.Generic.List[object]]::new()
    $protectedNames = @('SecurityHealth')
    foreach ($requestedName in @($RequestedNames | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($requestedName)) { continue }
        if ($protectedNames -icontains $requestedName) {
            Write-Warning "Protected Windows security startup item was not changed: $requestedName"
            continue
        }
        $matches = @($AllEntries | Where-Object { $_.Name -ieq $requestedName })
        if ($matches.Count -eq 0) {
            Write-Warning "Startup item not found by exact name: $requestedName"
            continue
        }

        foreach ($entry in $matches) {
            $storedPath = $null
            if ($entry.Type -eq 'StartupFolder') {
                $safeLeaf = [IO.Path]::GetFileName($entry.Location)
                $storedPath = Join-Path $AssetDirectory ('{0}_{1}' -f ([guid]::NewGuid().ToString('N')), $safeLeaf)
            }
            $changes.Add([PSCustomObject]@{
                Name         = $entry.Name
                Type         = $entry.Type
                Scope        = $entry.Scope
                Location     = $entry.Location
                Value        = $entry.Command
                ValueKind    = $entry.ValueKind
                StoredPath   = $storedPath
            })
        }
    }
    return @($changes)
}

function Find-TaskChanges {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$RequestedNames)
    $changes = [System.Collections.Generic.List[object]]::new()
    if ($RequestedNames.Count -eq 0) { return @() }
    if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Write-Warning 'Scheduled Tasks cmdlets are unavailable on this Windows installation.'
        return @()
    }

    $allTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue)
    foreach ($requestedName in @($RequestedNames | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($requestedName)) { continue }
        if ($requestedName -like '\Microsoft\Windows\*') {
            Write-Warning "Protected Windows scheduled task was not changed: $requestedName"
            continue
        }
        $task = @($allTasks | Where-Object { ($_.TaskPath + $_.TaskName) -ieq $requestedName })
        if ($task.Count -eq 0) {
            Write-Warning "Scheduled task not found by exact full path: $requestedName"
            continue
        }
        foreach ($match in $task) {
            if (-not $match.Settings.Enabled) {
                Write-Host "[ALREADY DISABLED] $requestedName" -ForegroundColor DarkGray
                continue
            }
            $changes.Add([PSCustomObject]@{
                FullName   = $match.TaskPath + $match.TaskName
                TaskName   = $match.TaskName
                TaskPath   = $match.TaskPath
                WasEnabled = $true
            })
        }
    }
    return @($changes)
}

function Set-RegistryRunValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$ValueKind
    )
    $kind = [Microsoft.Win32.RegistryValueKind]::$ValueKind
    $typedValue = switch ($ValueKind) {
        'Binary' { [byte[]]$Value }
        'DWord' { [int]$Value }
        'QWord' { [long]$Value }
        'MultiString' { [string[]]$Value }
        default { [string]$Value }
    }
    $key = Get-Item -LiteralPath $Path
    $key.SetValue($Name, $typedValue, $kind)
}

function Set-ServiceStartupType {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Automatic', 'Manual', 'Disabled')][string]$StartupType,
        [bool]$DelayedAutomatic = $false
    )

    if ($StartupType -eq 'Automatic' -and $DelayedAutomatic) {
        $null = & "$env:SystemRoot\System32\sc.exe" config $Name start= delayed-auto
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe could not restore delayed automatic start for $Name (exit $LASTEXITCODE)."
        }
    } else {
        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
    }
}

function Invoke-Apply {
    param([Parameter(Mandatory)][object]$Audit)

    $rules = @(Get-ServiceRules)
    $serviceChanges = @(
        foreach ($rule in $rules) {
            $change = Get-ServiceChange -Rule $rule
            if ($null -ne $change) { $change }
            else {
                $exists = Get-Service -Name $rule.Name -ErrorAction SilentlyContinue
                if ($null -eq $exists) {
                    Write-Host "[NOT PRESENT] $($rule.Name)" -ForegroundColor DarkGray
                } else {
                    Write-Host "[NO CHANGE] $($rule.Name)" -ForegroundColor DarkGray
                }
            }
        }
    )

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupDirectory = Join-Path $DataRoot 'Backups'
    $backupFile = if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        Join-Path $backupDirectory "Backup-$stamp.json"
    } else {
        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupPath)
    }
    $assetDirectory = "$backupFile.assets"

    $startupChanges = @(Find-StartupChanges -AllEntries $Audit.Startup -RequestedNames $DisableStartupItem -AssetDirectory $assetDirectory)
    $taskChanges = @(Find-TaskChanges -RequestedNames $DisableScheduledTask)
    $totalChanges = $serviceChanges.Count + $startupChanges.Count + $taskChanges.Count

    Write-Section 'Proposed changes'
    foreach ($change in $serviceChanges) {
        Write-Host ('SERVICE  {0}: {1} -> {2} ({3})' -f
            $change.Name, $change.OriginalStartupType, $change.DesiredStartupType, $change.Reason)
    }
    foreach ($change in $startupChanges) {
        Write-Host ('STARTUP  {0} [{1}]' -f $change.Name, $change.Scope)
    }
    foreach ($change in $taskChanges) {
        Write-Host ('TASK     {0}' -f $change.FullName)
    }

    if ($totalChanges -eq 0) {
        Write-Host 'Nothing needs to be changed.' -ForegroundColor Green
        return
    }
    Write-Host ''
    Write-Host ("Total: $totalChanges change(s). A restart/sign-out is required for a fair process count.") -ForegroundColor Yellow

    $backup = [ordered]@{
        SchemaVersion      = 1
        CreatedAt          = (Get-Date).ToString('o')
        Preset             = $Preset
        ProcessCountBefore = $Audit.ProcessCount
        TargetProcessCount = $TargetProcessCount
        Services           = $serviceChanges
        StartupEntries     = $startupChanges
        ScheduledTasks     = $taskChanges
    }

    if (-not $WhatIfPreference) {
        $parent = Split-Path -Parent $backupFile
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        if (@($startupChanges | Where-Object { $_.Type -eq 'StartupFolder' }).Count -gt 0) {
            New-Item -ItemType Directory -Path $assetDirectory -Force | Out-Null
        }
        $backup | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $backupFile -Encoding UTF8
        Write-Host "Rollback backup: $backupFile" -ForegroundColor Green
    }

    foreach ($change in $serviceChanges) {
        if ($PSCmdlet.ShouldProcess($change.Name, "Set service startup to $($change.DesiredStartupType)")) {
            try {
                Set-ServiceStartupType -Name $change.Name -StartupType $change.DesiredStartupType
                if ($change.DesiredStartupType -eq 'Disabled' -and $change.WasRunning) {
                    Stop-Service -Name $change.Name -ErrorAction SilentlyContinue
                }
                Write-Host "[CHANGED] Service $($change.Name)" -ForegroundColor Green
            } catch {
                Write-Warning "Service $($change.Name): $($_.Exception.Message)"
            }
        }
    }

    foreach ($change in $startupChanges) {
        if ($PSCmdlet.ShouldProcess($change.Name, 'Disable startup entry')) {
            try {
                if ($change.Type -eq 'RegistryRun') {
                    Remove-ItemProperty -LiteralPath $change.Location -Name $change.Name -ErrorAction Stop
                } else {
                    Move-Item -LiteralPath $change.Location -Destination $change.StoredPath -ErrorAction Stop
                }
                Write-Host "[DISABLED] Startup item $($change.Name)" -ForegroundColor Green
            } catch {
                Write-Warning "Startup item $($change.Name): $($_.Exception.Message)"
            }
        }
    }

    foreach ($change in $taskChanges) {
        if ($PSCmdlet.ShouldProcess($change.FullName, 'Disable scheduled task')) {
            try {
                Disable-ScheduledTask -TaskName $change.TaskName -TaskPath $change.TaskPath -ErrorAction Stop | Out-Null
                Write-Host "[DISABLED] Task $($change.FullName)" -ForegroundColor Green
            } catch {
                Write-Warning "Task $($change.FullName): $($_.Exception.Message)"
            }
        }
    }

    Write-Section 'Finished'
    if ($WhatIfPreference) {
        Write-Host 'Preview only: nothing was changed and no backup was created.' -ForegroundColor Yellow
    } else {
        Write-Host 'Restart Windows, wait two minutes after signing in, then run Audit again.' -ForegroundColor Green
        Write-Host "Restore command: .\Ultra-Clean-Services.ps1 -Mode Restore -BackupPath `"$backupFile`""
    }
}

function Get-LatestBackup {
    $backupDirectory = Join-Path $DataRoot 'Backups'
    $latest = Get-ChildItem -LiteralPath $backupDirectory -Filter 'Backup-*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($null -eq $latest) { return $null }
    return $latest.FullName
}

function Invoke-Restore {
    $backupFile = if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        Get-LatestBackup
    } else {
        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupPath)
    }
    if ([string]::IsNullOrWhiteSpace($backupFile) -or -not (Test-Path -LiteralPath $backupFile)) {
        throw 'No rollback backup was found. Supply -BackupPath with a valid backup JSON file.'
    }

    $backup = Get-Content -LiteralPath $backupFile -Raw | ConvertFrom-Json
    if ($backup.SchemaVersion -ne 1) {
        throw "Unsupported backup schema version: $($backup.SchemaVersion)"
    }
    Write-Section "Restoring $backupFile"
    foreach ($service in @($backup.Services)) {
        if ($PSCmdlet.ShouldProcess($service.Name, "Restore service to $($service.OriginalStartupType)")) {
            try {
                if ($null -eq (Get-Service -Name $service.Name -ErrorAction SilentlyContinue)) {
                    Write-Host "[NOT PRESENT] $($service.Name)" -ForegroundColor DarkGray
                    continue
                }
                Set-ServiceStartupType -Name $service.Name `
                    -StartupType $service.OriginalStartupType `
                    -DelayedAutomatic ([bool]$service.OriginalDelayedStart)
                if ([bool]$service.WasRunning -and $service.OriginalStartupType -ne 'Disabled') {
                    Start-Service -Name $service.Name -ErrorAction SilentlyContinue
                }
                Write-Host "[RESTORED] Service $($service.Name)" -ForegroundColor Green
            } catch {
                Write-Warning "Service $($service.Name): $($_.Exception.Message)"
            }
        }
    }

    foreach ($entry in @($backup.StartupEntries)) {
        if ($PSCmdlet.ShouldProcess($entry.Name, 'Restore startup entry')) {
            try {
                if ($entry.Type -eq 'RegistryRun') {
                    Set-RegistryRunValue -Path $entry.Location -Name $entry.Name -Value $entry.Value -ValueKind $entry.ValueKind
                } else {
                    if (Test-Path -LiteralPath $entry.Location) {
                        Write-Warning "Original startup path already exists; not overwriting: $($entry.Location)"
                        continue
                    }
                    if (-not (Test-Path -LiteralPath $entry.StoredPath)) {
                        Write-Warning "Stored startup file is missing: $($entry.StoredPath)"
                        continue
                    }
                    Move-Item -LiteralPath $entry.StoredPath -Destination $entry.Location -ErrorAction Stop
                }
                Write-Host "[RESTORED] Startup item $($entry.Name)" -ForegroundColor Green
            } catch {
                Write-Warning "Startup item $($entry.Name): $($_.Exception.Message)"
            }
        }
    }

    foreach ($task in @($backup.ScheduledTasks)) {
        if (-not [bool]$task.WasEnabled) { continue }
        if ($PSCmdlet.ShouldProcess($task.FullName, 'Enable scheduled task')) {
            try {
                Enable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                Write-Host "[RESTORED] Task $($task.FullName)" -ForegroundColor Green
            } catch {
                Write-Warning "Task $($task.FullName): $($_.Exception.Message)"
            }
        }
    }

    Write-Section 'Restore finished'
    if ($WhatIfPreference) {
        Write-Host 'Preview only: nothing was restored.' -ForegroundColor Yellow
    } else {
        Write-Host 'Restart Windows to complete the restore.' -ForegroundColor Green
    }
}

if ($Mode -in @('Apply', 'Restore') -and -not $WhatIfPreference -and -not (Test-IsAdministrator)) {
    throw "Mode '$Mode' requires PowerShell to be run as Administrator."
}

Write-Host 'Ultra Clean Services' -ForegroundColor Cyan
Write-Host 'Safe process reduction with audit and rollback' -ForegroundColor DarkGray

switch ($Mode) {
    'Audit' {
        $null = New-AuditReport -Root $DataRoot -Target $TargetProcessCount -SkipFiles:$WhatIfPreference
    }
    'Apply' {
        $audit = New-AuditReport -Root $DataRoot -Target $TargetProcessCount -SkipFiles:$WhatIfPreference
        Invoke-Apply -Audit $audit
    }
    'Restore' {
        Invoke-Restore
    }
}
