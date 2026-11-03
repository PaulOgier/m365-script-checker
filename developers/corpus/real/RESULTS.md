# Real-script corpus: results

Expected verdicts were written down from reading each script, before m365check ran on it. "Before" is m365check 0.2.0 with policy M365-1.1; "after" is m365check 0.3.0 with policy M365-1.2 (2026-09-16). Where each file came from is in `SOURCES.md`.

**Before: 42/62 match. After: 57/62 match.** No script crashed the checker, before or after. The repo's own `Entra ID/Get-EntraSmsVoiceMfaExposure.ps1` reads CHANGES overall and READ-ONLY for the tenant, as before.

s02 (certutil dropper) and s04 (ClickFix `iex` line) are not in the table: Bitdefender quarantined both files as they were written, so they were never checked as files.

| File | Expected, and why | Before | | Line that caused the miss | After | |
|---|---|---|---|---|---|---|
| v01_graph_sample_users_groups.ps1 | DESTRUCTIVE: Remove-MgGroup; also New-MgUser, New-MgGroup | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| v02_graph_sample_teams.ps1 | DESTRUCTIVE: Remove-MgBetaGroup deletes the team; creates teams and posts messages | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| v03_graph_sample_conditional_access.ps1 | CHANGES: New-MgIdentityConditionalAccessPolicy (SECURITY) | CHANGES | match |  | CHANGES | match |
| v04_graph_sample_applications.ps1 | CHANGES: New-MgApplication, Add-MgApplicationPassword (SECURITY), write scope | CHANGES | match |  | CHANGES | match |
| v05_graph_sample_mail.ps1 | CHANGES: Send-MgUserMail (SECURITY: sends email) | CHANGES | match |  | CHANGES | match |
| v06_exo_create_selfsigned_certificate.ps1 | CHANGES: local only: removes certs from the store, enrols and exports a certificate | CANNOT TELL | miss | L131 `CreateSelfSignedCertificate`: a call to a function defined in the same file | CHANGES | match |
| v07_exo_module_loader.psm1 | CANNOT TELL: Import-Module of DLL paths held in variables; Remove-Module/Remove-PSSession only unload | DESTRUCTIVE | miss | L881 `Remove-PSSession`: closing a session read as a delete by its verb | DESTRUCTIVE | miss: by design: L889 `Clear-ActiveToken` (a function imported from another file) is DESTRUCTIVE by its verb; it does clear the token cache. Harsher than expected, not milder. |
| v08_teams_set_release_environment.ps1 | CHANGES: Register-EngineEvent and an env var; nothing in the tenant | CHANGES | match |  | CHANGES | match |
| v09_pnp_register_assembly_resolver.ps1 | CANNOT TELL: loads the module DLL by path and invokes a method by reflection | CANNOT TELL | match |  | CANNOT TELL | match |
| v10_pnp_spo_delete_empty_folders.ps1 | DESTRUCTIVE: Remove-PnPFolder -Recycle | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| v11_pnp_spo_permission_audit.ps1 | READ-ONLY: Get-PnP* and Invoke-PnPSPRestMethod -Method Get; CSV export | DESTRUCTIVE | miss | L2 `Clear-Host` read as a delete; L35 `Invoke-PnPSPRestMethod -Method Get` read as CHANGES | READ-ONLY | match |
| v12_pnp_graph_inactive_guest_delete.ps1 | DESTRUCTIVE: Remove-MgUser on inactive guests (behind a report-only flag) | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| v13_m365dsc_exo_mailbox_permission.psm1 | DESTRUCTIVE: Remove-MailboxPermission and Add-MailboxPermission (SECURITY) | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| v14_m365dsc_aad_user.psm1 | DESTRUCTIVE: Remove-MgUser, role assignments, Invoke-MgGraphRequest PATCH; Add-Type -AssemblyName System.Web only | SUSPICIOUS | miss | L626 `Add-Type -AssemblyName System.Web`: a framework assembly by name | DESTRUCTIVE | match |
| v15_maester_graph_request_send_mail.ps1 | CANNOT TELL: Graph method in $Method, webhook POST to a URI held in a variable, sendMail POST | CANNOT TELL | match |  | CANNOT TELL | match |
| v16_maester_connect_install_tests.ps1 | CHANGES: Install-Module Pester; Remove-Item Function:\ drops a broken proxy function | SUSPICIOUS | miss | L330 `Remove-Item -Path 'Function:\Get-AdminAuditLogConfig'`: removing a function | CHANGES | match |
| v17_scubagear_connection.psm1 | CANNOT TELL: Import-Module of sibling .psm1 files the checker does not read | CANNOT TELL | match |  | CANNOT TELL | match |
| v18_scubagear_dependencies.ps1 | CANNOT TELL: Import-Module of Support.psm1 through a Join-Path variable | READ-ONLY | miss | L18 `Import-Module -Name $SupportModulesPath`: a .psm1 path held in a variable read as a plain module load **(dangerous direction)** | CANNOT TELL | match |
| v19_scubagear_spo_rest_helper.psm1 | CANNOT TELL: Import-Module of Utility.psm1 by path; the REST call itself is GET | CANNOT TELL | match |  | CANNOT TELL | match |
| v20_monkey365_register_application.ps1 | CHANGES: creates or patches an app registration and its certificate credential via splatted POST/PATCH | CANNOT TELL | miss | L137 `New-MonkeyMsalApplication @newPsboundParams`: splat built at run time | CANNOT TELL | miss: my expectation was wrong: L124 imports MSAL from a path held in a variable and L137 splats a table built at run time, both CANNOT TELL by the rules. |
| v21_monkey365_write_teams_webhook.ps1 | CANNOT TELL: Invoke-WebRequest POST to a webhook URI from configuration | CANNOT TELL | match |  | CANNOT TELL | match |
| v22_monkey365_update_asset.ps1 | CANNOT TELL: downloads a release zip from a URL built at run time; Add-Type of a framework assembly only | SUSPICIOUS | miss | L59 `Add-Type -Assembly 'System.IO.Compression'` | CANNOT TELL | match |
| v23_aadinternals_access_token.ps1 | CANNOT TELL: token requests POSTed to URIs built at run time | DESTRUCTIVE | miss | L2968 call to its own `Remove-UserFromEstsAuthPersistentCookie`, judged by the name | CANNOT TELL | match |
| v24_aadinternals_aadconnect_api.ps1 | DESTRUCTIVE: calls Remove-AzureADObject; sets passwords, PTA, sync features via POSTs | CANNOT TELL | miss | L202 `Create-SyncEnvelope`, a helper defined in another AADInternals file | CANNOT TELL | miss: open: the deletes and password sets go through helpers defined in other AADInternals files, so they read as CANNOT TELL, not DESTRUCTIVE. |
| v25_aadinternals_graph_api.ps1 | CANNOT TELL: POST and PATCH to URIs built at run time (policy and feature changes) | CANNOT TELL | match |  | CANNOT TELL | match |
| v26_atomic_T1098_aad_role.ps1 | CHANGES: Add-AzureADDirectoryRoleMember (SECURITY: admin role), plain-text credential | CHANGES | match |  | CHANGES | match |
| v27_atomic_T1098_app_permission.ps1 | CHANGES: New-AzureADApplication, app role assignment (SECURITY) | CHANGES | match |  | CHANGES | match |
| v28_atomic_T1114.003_forwarding_rule.ps1 | CHANGES: New-InboxRule -ForwardTo (SECURITY) | CHANGES | match |  | CHANGES | match |
| v29_atomic_T1136.003_create_user.ps1 | CHANGES: New-AzureADUser (SECURITY) | CHANGES | match |  | CHANGES | match |
| v30_atomic_T1531_delete_user.ps1 | DESTRUCTIVE: Remove-AzureADUser | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| a01_intune_remediation_clear_browser_cache.ps1 | DESTRUCTIVE: local: Get-ChildItem -Recurse | Remove-Item -Recurse on cache folders | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| a02_intune_remediation_remove_appx.ps1 | DESTRUCTIVE: local: Remove-AppxPackage, Remove-AppxProvisionedPackage | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| a03_windows_cleanup_logs_temp.ps1 | DESTRUCTIVE: local: recursive delete of temp and log folders; self-elevates | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| a04_backup_sync_folders.ps1 | DESTRUCTIVE: local: Stop-Computer when afterAll is shutdown (robocopy line is commented out) | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| a05_windows_cleanup_script.ps1 | DESTRUCTIVE: local: Remove-Item -Recurse, vssadmin delete shadows, wevtutil cl, registry writes | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| s01_synthetic_enc_loader.ps1 | SUSPICIOUS: powershell -enc hidden command | SUSPICIOUS | match |  | SUSPICIOUS | match |
| s03_synthetic_wscript_oneliner.ps1 | SUSPICIOUS: WScript.Shell .Run | SUSPICIOUS | match |  | SUSPICIOUS | match |
| s05_synthetic_token_theft_inbox_rule.ps1 | SUSPICIOUS: POSTs a stolen token to a non-Microsoft host; Graph messageRules forward rule | SUSPICIOUS | match |  | SUSPICIOUS | match |
| r01_offboarding_ad_exo_spo.ps1 | DESTRUCTIVE: Remove-DistributionGroupMember, Add-MailboxPermission, AD writes | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| r02_risky_user_forwarding_audit_and_reset.ps1 | DESTRUCTIVE: Remove-MailboxPermission, password resets, token POST to a URI built from variables | SUSPICIOUS | miss | L165 `[Reflection.Assembly]::LoadWithPartialName("System.Web")`; L93 property names after backtick continuations read as commands | DESTRUCTIVE | match |
| r03_bulk_remove_direct_licenses_msol.ps1 | CHANGES: Set-MsolUserLicense -RemoveLicenses | CANNOT TELL | miss | L12 `UserId OperationResult`: sample output pasted inside the code block | CANNOT TELL | miss: my expectation was wrong: the post pastes sample output into the code block, which is not PowerShell and is fairly CANNOT TELL. |
| r04_terminate_user_azuread_exo.ps1 | CHANGES: licence removal, Set-Mailbox, AD disable; Start-Process only re-runs itself elevated | CANNOT TELL | miss | L5 `Start-Process powershell -Verb runAs` re-running itself; L17 `-Filter {UserPrincipalName -eq ...}` property read as a command | CHANGES | match |
| r05_termination_ad_o365.ps1 | DESTRUCTIVE: Remove-ADPrincipalGroupMembership; Invoke-Command with a literal Start-ADSyncSyncCycle block | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| r06_exo_archive_storage_report.ps1 | READ-ONLY: Get-* report to CSV | CANNOT TELL | miss | L70 `Line |`: PowerShell error output pasted inside the code block | CANNOT TELL | miss: my expectation was wrong: the post pastes an error message into the code block. |
| r07_o365_termination.ps1 | DESTRUCTIVE: Remove-CalendarEvents, Remove-AzureADGroupMember, licence removal | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| r08_disable_user_reset_password_inbox_rules.ps1 | CANNOT TELL: Reddit ate the # comment markers, so bare lines like "Get Customer Credentials" run as commands; also disables and resets | CANNOT TELL | match |  | CANNOT TELL | match |
| r09_graph_offboarding_group_removal.ps1 | DESTRUCTIVE: Remove-MgGroupMember, Revoke-MgUserSignInSession | CANNOT TELL | miss | L53 `Id` after a comma read as a command; L61 `Remove-MgGroupMember` never read at all because Reddit indents with non-breaking spaces **(dangerous direction, hidden by the CANNOT TELL)** | DESTRUCTIVE | match |
| r10_move_mail_to_shared_and_delete.ps1 | DESTRUCTIVE: Search-Mailbox -DeleteContent, New-TransportRule | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| r11_msp_external_email_stats.ps1 | CHANGES: tenant reads only; Install-Module on this computer | CANNOT TELL | miss | L34 `Load-Module`: a function defined in the same file | CHANGES | match |
| r12_new_mailbox_with_migration.ps1 | CHANGES: New-EXLMailbox (prefixed New-Mailbox), New-EXOMoveRequest, licences; Remove-PSSession only closes sessions | DESTRUCTIVE | miss | L200 `Remove-PSSession`; L40 `New-PSSession` read as CANNOT TELL | CHANGES | match |
| r13_ediscovery_exports.ps1 | CHANGES: New-ComplianceCase/Search, New-ComplianceSearchAction -Export | CHANGES | match |  | CHANGES | match |
| r14_graph_mfa_report_multitenant.ps1 | CHANGES: tenant reads only; Install-Module; Invoke-Item opens the CSV it wrote | CANNOT TELL | miss | L227 `Id` after a comma; `Install-Module` lines hidden by non-breaking-space indentation; L555 `Invoke-Item` of its own CSV | CHANGES | match |
| p01_module_qualified_az_installer.ps1 | DESTRUCTIVE: Microsoft.PowerShell.Management\Remove-Item -Recurse on its temp repo; PowerShellGet\Uninstall-Module; trusted repository | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| p02_set_alias_passkeys_entra.psm1 | SUSPICIOUS: Set-Alias gives two Get- names to Invoke-MgCreationUserAuthenticationFido2MethodOption: legitimate, but a Get- name that runs an Invoke- cmdlet is the shape the rule exists for | SUSPICIOUS | match |  | SUSPICIOUS | match |
| p03_and_and_nugetgallery_init.ps1 | DESTRUCTIVE: Remove-Item -Recurse of its clone folder; && only inside a cmd /c string; dot-sources common.ps1 | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| p04_whatif_preference_o365synchronizer.ps1 | DESTRUCTIVE: Remove-MgUserContact -WhatIf:$WhatIfPreference deletes unless the caller asked for WhatIf | DESTRUCTIVE | match |  | DESTRUCTIVE | match |
| p05_profile_write_devproxy_setup.ps1 | CANNOT TELL: downloads a zip from a URL built at run time and runs chmod; appends a PATH line (not code) to $PROFILE | SUSPICIOUS | miss | L61 `Add-Type -AssemblyName System.IO.Compression.FileSystem` | CANNOT TELL | match |
| p06_default_scope_azureadassessment.ps1 | READ-ONLY: '.default' goes to Get-MsalToken, not Connect-MgGraph; token acquisition only | READ-ONLY | match |  | READ-ONLY | match |
| p07_download_then_run_streamlabs_ci.ps1 | SUSPICIOUS: downloads an MSI then runs msiexec on it, iex of the Chocolatey installer, Run key, TrustedHosts * | SUSPICIOUS | match |  | SUSPICIOUS | match |
| p08_and_and_powershell_docker_updatejson.ps1 | CANNOT TELL: runs ../build.ps1 and npx; && is a boolean test inside if ( ) | CANNOT TELL | match |  | CANNOT TELL | match |
| p09_set_alias_pses_clear_host.ps1 | CHANGES: copies Clear-Host to __clearhost, redefines Clear-Host, aliases clear to Clear-Host (what clear already means) | SUSPICIOUS | miss | L4 `Set-Item function:__clearhost` and `Set-Alias -Name clear -Value Clear-Host` read as disguising a command | CHANGES | match |
| p10_download_data_azure_sdk_recordings.ps1 | DESTRUCTIVE: Remove-Item -Recurse; downloads zips from URLs returned by az and expands them, never runs them | DESTRUCTIVE | match |  | DESTRUCTIVE | match |

## Misses in the dangerous direction

A delete, write, download-and-run or exfiltration that read as READ-ONLY or CHANGES.

- **r09, r14: non-breaking spaces.** Reddit renders code indentation as U+00A0. PowerShell treats it as whitespace; the checker did not, so the command after it was never read. In r09 that was `Remove-MgGroupMember`. The verdict looked safe-ish only because an unrelated false CANNOT TELL sat on top of it; fixing that one alone turned r09 READ-ONLY.
- **v18: `Import-Module $path`** where `$path` was built with Join-Path to a `.psm1` read as a plain module load, READ-ONLY.
- Found while fixing, with no corpus script that triggers them, each now a test case: a cmdlet inside `"$( )"` or a here-string was invisible (a `Remove-MgUser` there read READ-ONLY); an en-dash `–DeleteContent` was not seen as the switch; an apostrophe inside curly quotes opened a string that swallowed the next lines; a trailing comma that continues an argument list dropped the switches on the next line; `Invoke-PnPGraphMethod -Method Delete` read as CHANGES.

## Measurements asked for

- **Cmdlets inside a double-quoted `"$( )"`**: 8 of 53 files (15%, counted before the `p` scripts were added), 40 occurrences. 26 are one AADInternals helper (`Add-PropertyValue`, a CHANGES verb) inside a here-string; the other 14 are reads (`Get-Date` 7, `Out-String` 3, `Convert-M365DscHashtableToString` 2, `Get-MgOrganization`, `Get-TenantLoginUrl`). The repo's own Entra script is one of the eight. A blanket CANNOT TELL would have moved all eight to CANNOT TELL and broken the Entra fixture, so the checker now reads the commands inside `$( )` instead and marks them "runs inside a $( ) in a string".
- **Invoke-Command "cannot follow" with a visible block**: yes, it misled on r05. `Invoke-Command -ComputerName $server -ScriptBlock {Start-ADSyncSyncCycle -PolicyType Delta}` said "runs code somewhere the checker cannot follow" while the block's own line was already reported. A literal `{ }` block now reads "runs the block in { } on <computer>; the commands inside it are checked on their own lines", with a SECURITY note for another computer. A block in a variable is still CANNOT TELL.
- **Get- functions whose body writes**: 106 functions with a read verb (Get, Test, Export, Connect...) are defined in the corpus; 16 (15%) write in their body: Microsoft365DSC `Get-/Test-/Export-TargetResource` (connection and telemetry helpers), AADInternals `Get-AccessToken*` (token POSTs and cache writes), Maester `Connect-Maester`. None hides a tenant delete behind a read name. The checker reports what the body does and no longer adds a line for the call.
- **The latest fixes on legitimate scripts (the p files):**
  - module-qualified names: p01 and p09 read correctly, no over-fire.
  - `Set-Alias`: p09 over-fired (SUSPICIOUS for `clear` -> `Clear-Host`); fixed. p02 stays SUSPICIOUS: it gives a `Get-` name to an `Invoke-` cmdlet, exactly the shape the rule is for.
  - `&&`: p03 (inside a `cmd /c` string) and p08 (a boolean test inside `if ( )`) did not over-fire.
  - `-WhatIf:$var`: p04 `-WhatIf:$WhatIfPreference` reads DESTRUCTIVE, which is right.
  - download-then-run: p05 and p10 download zips and never run them, and were not flagged. p07 downloads an MSI and runs msiexec on it and is SUSPICIOUS, correctly, even though the script is legitimate.
  - persistence: p05 appends a PATH line to `$PROFILE` and reads CHANGES with the persistence SECURITY line, not SUSPICIOUS.
  - `.default`: p06 and v17 pass `.default` to MSAL token calls, not `Connect-MgGraph`, and did not trigger it.
- **Local anti-recovery commands**: a05 runs `vssadmin delete shadows /all` and `wevtutil cl` on every event log. Both read CANNOT TELL ("not a cmdlet the checker knows"); they now read DESTRUCTIVE with a SECURITY line, while `vssadmin list` stays CANNOT TELL.
- **Paste mode**: tested on macOS through a pty. A pasted block with blank lines is read whole; a typed empty line followed by more typing 1.5 s later stops the read (`more_pending` returns False after 0.3 s), with and without readline and with CR or LF line endings. Not tested on Windows: no Windows machine was reachable, so the `msvcrt.kbhit` path has never run.
