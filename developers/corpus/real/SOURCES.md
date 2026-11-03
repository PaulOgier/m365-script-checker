# Real-script corpus: sources

Every file here was fetched on 2026-09-16 with a browser User-Agent and kept only after an HTTP 200 whose body was not an HTML block page. PowerShell Gallery packages came from the v2 API (`https://www.powershellgallery.com/api/v2/package/NAME/VERSION`), unzipped, never through `Save-Module`. No script was run.

**Edits made to the downloaded text**, and nothing else:

- Personal names, social handles and a personal site in comment headers replaced with `<author redacted>` or `<handle redacted>` (Monkey365, AADInternals, the two Intune remediations, the backup script, two Reddit posts). The licence and upstream URL below point at the unredacted original.
- Literal passwords in Reddit posts replaced with `REDACTED`; one tenant address, two group and user object ids, and Microsoft's own tenant id (p06) replaced with placeholders; sixteen site codes in r12's OU names replaced with `SITE01` to `SITE16`.
- Monkey365's project homepage host in v20 replaced with `example.github.io`.
- Slices: v10 to v12 are the PowerShell code block of a README; v15 and v16 are named functions cut from the 73,000-line `Maester.psm1`; v26 to v30 are the `executor.command` block of one Atomic test, placeholders like `#{password}` left as they are.

Upstream URLs keep the repository owner in the path, which is sometimes a person's GitHub name. They stay because the URL is the provenance.

## Vendor and Gallery (v)

| File | Source | Licence | Why |
|---|---|---|---|
| v01_graph_sample_users_groups.ps1 | https://raw.githubusercontent.com/microsoftgraph/msgraph-sdk-powershell/main/samples/4-UsersAndGroups.ps1 | repo LICENSE not a standard SPDX id | Graph SDK doc sample: users and groups, creates and deletes |
| v02_graph_sample_teams.ps1 | .../samples/5-Teams.ps1 | same | Graph beta cmdlets, backtick-continued hashtables |
| v03_graph_sample_conditional_access.ps1 | .../samples/8-ConditionalAccess.ps1 | same | creates a Conditional Access policy |
| v04_graph_sample_applications.ps1 | .../samples/9-Applications.ps1 | same | app registrations, secrets, splats, write scope |
| v05_graph_sample_mail.ps1 | .../samples/A-Mail.ps1 | same | Send-MgUserMail |
| v06_exo_create_selfsigned_certificate.ps1 | Gallery ExchangeOnlineManagement 3.10.1, `netFramework/Create-SelfSignedCertificate.ps1` | http://aka.ms/azps-license | local certificate work through COM, calls its own functions |
| v07_exo_module_loader.psm1 | Gallery ExchangeOnlineManagement 3.10.1, `netCore/ExchangeOnlineManagement.psm1` | same | module loader: imports DLLs by path, removes sessions |
| v08_teams_set_release_environment.ps1 | Gallery MicrosoftTeams 8.0.0, `SetMSTeamsReleaseEnvironment.ps1` | https://raw.githubusercontent.com/MicrosoftDocs/office-docs-powershell/master/teams/LICENSE.txt | engine event and environment variable |
| v09_pnp_register_assembly_resolver.ps1 | Gallery PnP.PowerShell 3.4.1, `RegisterPnPAssemblyResolver.ps1` | MIT | loads a DLL by path and calls it by reflection |
| v10_pnp_spo_delete_empty_folders.ps1 | https://raw.githubusercontent.com/pnp/script-samples/main/scripts/spo-delete-empty-folders/README.md | MIT | PnP sample that deletes |
| v11_pnp_spo_permission_audit.ps1 | .../scripts/spo-get-permission-audit/README.md | MIT | PnP read-only audit using Invoke-PnPSPRestMethod |
| v12_pnp_graph_inactive_guest_delete.ps1 | .../scripts/aad-inactive-guest-delete/README.md | MIT | guest cleanup, "script to delete" |
| v13_m365dsc_exo_mailbox_permission.psm1 | Gallery Microsoft365DSC 1.26.909.1, `DscResources/MSFT_EXOMailboxPermission/` | MIT | DSC resource that adds and removes mailbox permissions |
| v14_m365dsc_aad_user.psm1 | Gallery Microsoft365DSC 1.26.909.1, `DscResources/MSFT_AADUser/` | MIT | DSC resource: users, licences, roles, Add-Type |
| v15_maester_graph_request_send_mail.ps1 | Gallery Maester 2.2.0, `Maester.psm1`: Invoke-MtGraphRequest, Send-MtMail, Send-MtTeamsMessage | MIT | variable HTTP methods, sendMail, Teams webhook |
| v16_maester_connect_install_tests.ps1 | Gallery Maester 2.2.0, `Maester.psm1`: Connect-Maester, Install-MaesterTests, Update-MaesterTests | MIT | Install-Module, removes a function from the Function: drive |
| v17_scubagear_connection.psm1 | Gallery ScubaGear 1.8.0, `Modules/Connection/Connection.psm1` | CC0-1.0 | imports sibling modules, `.default` scope string |
| v18_scubagear_dependencies.ps1 | Gallery ScubaGear 1.8.0, `Dependencies.ps1` | CC0-1.0 | Import-Module through a Join-Path variable |
| v19_scubagear_spo_rest_helper.psm1 | Gallery ScubaGear 1.8.0, `Modules/Providers/ProviderHelpers/SPORestHelper.psm1` | CC0-1.0 | REST helper |
| v20_monkey365_register_application.ps1 | Gallery Monkey365 0.99, `core/utils/Register-Monkey365Application.ps1` | Apache-2.0 | creates an app registration through splatted POST and PATCH |
| v21_monkey365_write_teams_webhook.ps1 | Gallery Monkey365 0.99, `core/modules/monkeylogger/clients/Write-Teams.ps1` | Apache-2.0 | legitimate POST to a webhook URL from configuration |
| v22_monkey365_update_asset.ps1 | Gallery Monkey365 0.99, `core/modules/monkeyutils/public/Update-MonkeyAsset.ps1` | Apache-2.0 | downloads release assets from GitHub, Add-Type |
| v23_aadinternals_access_token.ps1 | https://raw.githubusercontent.com/Gerenios/AADInternals/master/AccessToken.ps1 | MIT | offensive tooling: token theft and replay by design |
| v24_aadinternals_aadconnect_api.ps1 | .../AADInternals/master/AzureADConnectAPI.ps1 | MIT | sets passwords, enables pass-through auth, deletes sync objects |
| v25_aadinternals_graph_api.ps1 | .../AADInternals/master/GraphAPI.ps1 | MIT | policy and feature changes through raw HTTP |
| v26_atomic_T1098_aad_role.ps1 | https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1098/T1098.yaml, test "Azure AD - adding user to Azure AD role" | MIT | attack simulation: admin role grant |
| v27_atomic_T1098_app_permission.ps1 | same file, test "Azure AD - adding permission to application" | MIT | attack simulation: app permission grant |
| v28_atomic_T1114.003_forwarding_rule.ps1 | .../atomics/T1114.003/T1114.003.yaml, "Office365 - Email Forwarding" | MIT | attack simulation: forwarding inbox rule |
| v29_atomic_T1136.003_create_user.ps1 | .../atomics/T1136.003/T1136.003.yaml, "Azure AD - Create a new user" | MIT | attack simulation: new account |
| v30_atomic_T1531_delete_user.ps1 | .../atomics/T1531/T1531.yaml, "Azure AD - Delete user via Azure AD PowerShell" | MIT | attack simulation: account deletion |

The Gallery packages MSOnline 1.0.51 and AzureAD 2.4.71.0 were downloaded and hold no `.ps1` or `.psm1` (binary modules), so their cmdlets are covered through the Reddit and Atomic scripts that call them. The AADInternals Gallery download (0.9.8) was replaced on this Mac by a Bitdefender block page served with HTTP 200, so its files came from the GitHub repository instead. The repo's own `Entra ID/Get-EntraSmsVoiceMfaExposure.ps1` is run from where it lives, not copied.

## Reddit (r)

Read through a headless Chromium render of the thread (the anonymous Atom feed flattens every newline). Only the code blocks of the original post are kept, not comments. No licence is stated on Reddit posts.

| File | Thread | Posted | Why |
|---|---|---|---|
| r01_offboarding_ad_exo_spo.ps1 | https://www.reddit.com/r/PowerShell/comments/17piaeu/ | 2023-11-07 | offboarding across AD, Exchange Online, SharePoint |
| r02_risky_user_forwarding_audit_and_reset.ps1 | https://www.reddit.com/r/PowerShell/comments/cb4he6/ | 2019-07-09 | forwarding audit, delegate removal, password reset |
| r03_bulk_remove_direct_licenses_msol.ps1 | https://www.reddit.com/r/PowerShell/comments/zxd30l/ | 2022-12-28 | bulk licence removal, MSOnline |
| r04_terminate_user_azuread_exo.ps1 | https://www.reddit.com/r/PowerShell/comments/ip4sxg/ | 2020-09-08 | termination, AzureAD module, self-elevation |
| r05_termination_ad_o365.ps1 | https://www.reddit.com/r/PowerShell/comments/elvps9/ | 2020-01-08 | termination with Invoke-Command to the sync server |
| r06_exo_archive_storage_report.ps1 | https://www.reddit.com/r/PowerShell/comments/1erl6ty/ | 2024-08-13 | read-only mailbox report |
| r07_o365_termination.ps1 | https://www.reddit.com/r/PowerShell/comments/jk7enp/ | 2020-10-29 | cancels meetings, removes groups and licences |
| r08_disable_user_reset_password_inbox_rules.ps1 | https://www.reddit.com/r/PowerShell/comments/cxgu24/ | 2019-08-30 | Azure Automation runbooks as Reddit rendered them |
| r09_graph_offboarding_group_removal.ps1 | https://www.reddit.com/r/PowerShell/comments/1f58gr3/ | 2024-08-30 | Graph offboarding, non-breaking-space indentation |
| r10_move_mail_to_shared_and_delete.ps1 | https://www.reddit.com/r/Office365/comments/1be65hn/ | 2024-03-13 | Search-Mailbox -DeleteContent, transport rule |
| r11_msp_external_email_stats.ps1 | https://www.reddit.com/r/msp/comments/o6dno6/ | 2021-06-23 | MSP reporting script |
| r12_new_mailbox_with_migration.ps1 | https://www.reddit.com/r/PowerShell/comments/981ych/ | 2018-08-17 | hybrid mailbox creation, curly quotes |
| r13_ediscovery_exports.ps1 | https://www.reddit.com/r/PowerShell/comments/135n3nv/ | 2023-05-02 | eDiscovery case, search and export |
| r14_graph_mfa_report_multitenant.ps1 | https://www.reddit.com/r/PowerShell/comments/1wddfsb/ | 2026-09-11 | MFA status report across tenants |

## Written from public write-ups (s), synthetic-from-writeup

Not functional: hosts are under `.invalid` and the encoded payload only prints a line.

| File | Write-up | Shape |
|---|---|---|
| s01_synthetic_enc_loader.ps1 | https://attack.mitre.org/techniques/T1027/010/ | hidden `powershell -enc` |
| s02_synthetic_certutil_dropper.ps1 | https://lolbas-project.github.io/lolbas/Binaries/Certutil/ | `certutil -urlcache -split -f` then run |
| s03_synthetic_wscript_oneliner.ps1 | https://attack.mitre.org/techniques/T1559/001/ | `WScript.Shell` `.Run` |
| s04_synthetic_clickfix_downloadstring_iex.ps1 | https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/ | `iex (New-Object Net.WebClient).DownloadString(...)` |
| s05_synthetic_token_theft_inbox_rule.ps1 | https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/ | stolen token, hidden forwarding inbox rule, token posted out |

**s02 and s04 are not in this folder.** Bitdefender on the authoring Mac quarantined both the moment they were written, so they were never checked as files. Their shapes are covered by the `iex download` and native-program cases in `test_m365check.py`. Expect the same on any machine with endpoint protection.

## Ordinary admin scripts (a)

| File | Source | Licence | Why |
|---|---|---|---|
| a01_intune_remediation_clear_browser_cache.ps1 | https://raw.githubusercontent.com/JayRHa/EndpointAnalyticsRemediationScripts/main/Clear-BrowserCache/remediation_Clear-BrowserCacheRemediation.ps1 | MIT | Intune remediation |
| a02_intune_remediation_remove_appx.ps1 | https://raw.githubusercontent.com/aaronparker/remediations/main/AppX-Remove/Remediate-BlockedAppXPackages.ps1 | MIT | Intune remediation |
| a03_windows_cleanup_logs_temp.ps1 | https://raw.githubusercontent.com/virtualox/Cleanup-WindowsLogsAndTempFiles.ps1/main/Cleanup-WindowsLogsAndTempFiles.ps1 | GPL-3.0 | Windows cleanup, self-elevation |
| a04_backup_sync_folders.ps1 | https://raw.githubusercontent.com/mmichaelis/ps-backup-folders/master/Sync-Folders.ps1 | Apache-2.0 | robocopy backup wrapper |
| a05_windows_cleanup_script.ps1 | https://raw.githubusercontent.com/arslaan5/Cleanup-Script/main/cleanup.ps1 | MIT | aggressive cleanup: shadow copies, event logs |

## Legitimate uses of the latest fixes (p)

Found with GitHub code search for each pattern, to check the fixes do not fire on ordinary use.

| File | Source | Licence | Pattern |
|---|---|---|---|
| p01_module_qualified_az_installer.ps1 | https://raw.githubusercontent.com/Azure/azure-powershell/HEAD/tools/Az.Tools.Installer/internal/Install-AzModule_ByPath.ps1 | repo LICENSE not a standard SPDX id; file header Apache-2.0 | module-qualified names |
| p02_set_alias_passkeys_entra.psm1 | https://raw.githubusercontent.com/MichaelGrafnetter/webauthn-interop/HEAD/Src/DSInternals.Passkeys/DSInternals.Passkeys.Entra.psm1 | MIT | Set-Alias in a Graph module |
| p03_and_and_nugetgallery_init.ps1 | https://raw.githubusercontent.com/NuGet/NuGetGallery/HEAD/build/init.ps1 | Apache-2.0 | `&&` |
| p04_whatif_preference_o365synchronizer.ps1 | https://raw.githubusercontent.com/EvotecIT/O365Synchronizer/HEAD/Private/Remove-O365InternalContact.ps1 | none stated | `-WhatIf:$WhatIfPreference` |
| p05_profile_write_devproxy_setup.ps1 | https://raw.githubusercontent.com/dotnet/dev-proxy/HEAD/scripts/setup.ps1 | MIT | writes to `$PROFILE`, downloads a zip |
| p06_default_scope_azureadassessment.ps1 | https://raw.githubusercontent.com/AzureAD/AzureADAssessment/HEAD/src/internal/Confirm-ModuleAuthentication.ps1 | MIT | `.default` scope |
| p07_download_then_run_streamlabs_ci.ps1 | https://raw.githubusercontent.com/streamlabs/desktop/HEAD/scripts/ci/install.ps1 | GPL-3.0 | download then run (a real CI machine setup) |
| p08_and_and_powershell_docker_updatejson.ps1 | https://raw.githubusercontent.com/PowerShell/PowerShell-Docker/HEAD/tools/updateJson.ps1 | MIT | `&&` as a boolean test |
| p09_set_alias_pses_clear_host.ps1 | https://raw.githubusercontent.com/PowerShell/PowerShellEditorServices/HEAD/module/PowerShellEditorServices/Commands/Public/Clear-Host.ps1 | MIT | Set-Alias and the Function: drive |
| p10_download_data_azure_sdk_recordings.ps1 | https://raw.githubusercontent.com/Azure/azure-sdk-for-net/HEAD/eng/scripts/Download-DevOpsRecordings.ps1 | MIT | downloads data that is never run |
