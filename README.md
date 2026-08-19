# Ultra Clean Services

This is a safer replacement for scripts that blindly disable long lists of Windows services. It audits the things that actually tend to create background processes, changes only a reviewed service set or exact items you name, and creates a complete rollback file before applying anything.

The script is local-only: it contains no telemetry, analytics, upload code, or network requests.

It will not promise an exact process count. A clean Windows 11 installation, drivers, security software, RGB tools, launchers, browser background mode, and hardware utilities all change that number. Going from 234 to 120 will usually require trimming third-party startup apps in addition to services.

## Recommended workflow

Open PowerShell as Administrator in this folder.

1. Create the audit:

   ```powershell
   .\Ultra-Clean-Services.ps1 -Mode Audit
   ```

   The script shows the report folder. Open `Startup-Items.csv` and `Third-Party-Tasks.csv`. Look for launchers, updaters, overlays, RGB utilities, phone tools, and apps you do not need at every login. Do not disable security software, touchpad/audio/GPU drivers, backup software, or anything you cannot identify.

2. Preview the conservative cleanup:

   ```powershell
   .\Ultra-Clean-Services.ps1 -Mode Apply -Preset Lean -WhatIf
   ```

3. Add only feature switches that match how you use the PC:

   ```powershell
   .\Ultra-Clean-Services.ps1 -Mode Apply -Preset Lean -NoXbox -NoPhoneLink -NoOfflineMaps -WhatIf
   ```

   Remove `-WhatIf` when the preview is correct.

4. Disable exact third-party startup names found in the audit:

   ```powershell
   .\Ultra-Clean-Services.ps1 -Mode Apply -Preset Lean `
       -DisableStartupItem 'Discord','Spotify' -WhatIf
   ```

5. Restart, wait two minutes after signing in, and audit again:

   ```powershell
   .\Ultra-Clean-Services.ps1 -Mode Audit
   ```

## Feature switches

| Switch | What stops working |
|---|---|
| `-NoXbox` | Xbox Live sign-in, Xbox cloud saves/networking, and Xbox accessory management |
| `-NoPrinting` | All printing, including Microsoft Print to PDF |
| `-NoBluetooth` | Bluetooth devices |
| `-NoSearchIndex` | Fast indexed file and content search |
| `-NoLocation` | Windows location service |
| `-NoPhoneLink` | Phone Link telephony support |
| `-NoOfflineMaps` | Downloaded/offline maps |
| `-NoConnectedDevices` | Nearby Sharing and other cross-device experiences |
| `-NoNotifications` | App and Windows push notifications |
| `-NoNetworkSharing` | Inbound Windows file and printer sharing |
| `-NoVirtualMachinesOrWSL` | Hyper-V, Windows Sandbox, Docker's Hyper-V/WSL backends, and WSL |

The `Safe` preset disables only Fax, Retail Demo, Remote Registry, and legacy Windows Media Player sharing. `Lean` adds optional diagnostics services and changes Windows Error Reporting to manual start.

## Scheduled tasks

Use the exact `FullName` from `Third-Party-Tasks.csv`:

```powershell
.\Ultra-Clean-Services.ps1 -Mode Apply -Preset Lean `
    -DisableScheduledTask '\Vendor\Updater at logon' -WhatIf
```

Vendor updater tasks can be useful for security and driver fixes. Disable them only when you have another update routine.

## Restore

Every real Apply creates a timestamped JSON backup before the first change. Restore the newest one with:

```powershell
.\Ultra-Clean-Services.ps1 -Mode Restore
```

Or restore a specific backup using the exact command printed after Apply.

## Privacy

- Audit reports and rollback data stay under `%LOCALAPPDATA%\UltraCleanServices` unless you explicitly choose another location.
- The PC name and Windows account name are not written to reports or backups.
- User-profile paths in CSV reports are replaced with placeholders such as `%USERPROFILE%` and `%LOCALAPPDATA%`.
- Reports still contain process, installed-application, service, and task names. Review them before sharing.
- The repository ignore rules exclude audit reports and backups from Git.

## What this script refuses to do

- It does not disable Windows Update, Defender, networking, audio, RPC, Task Scheduler, Event Log, Plug and Play, cryptography, firewall, or device-driver services.
- It does not kill arbitrary processes to chase the number 120.
- It does not use undocumented global background-app registry tweaks.
- It does not delete startup files; it moves selected files into the rollback folder.
- It does not merge isolated `svchost.exe` instances just to make Task Manager show a smaller number. That weakens fault isolation without making the services consume less CPU.

Microsoft recommends managing startup apps selectively, and its Autoruns utility is the most complete inspection tool when you need a deeper review:

- [Configure Startup applications in Windows](https://support.microsoft.com/en-us/windows/experience-startup-boot/configure-startup-applications-in-windows)
- [Microsoft Sysinternals Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)

## License

MIT. See [LICENSE](LICENSE).
