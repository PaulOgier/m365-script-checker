#!/usr/bin/env python3
"""Rerun m365check over developers/corpus/real and compare each verdict with the one expected from reading the script.

Run:  python3 developers/check_real_corpus.py
Not part of test_m365check.py: a few scripts still differ by design or for reasons
RESULTS.md explains, so this reports a count instead of failing.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import m365check  # noqa: E402

EXPECT = {
    'v01_graph_sample_users_groups.ps1': ('DESTRUCTIVE', 'Remove-MgGroup; also New-MgUser, New-MgGroup'),
    'v02_graph_sample_teams.ps1': ('DESTRUCTIVE', 'Remove-MgBetaGroup deletes the team; creates teams and posts messages'),
    'v03_graph_sample_conditional_access.ps1': ('CHANGES', 'New-MgIdentityConditionalAccessPolicy (SECURITY)'),
    'v04_graph_sample_applications.ps1': ('CHANGES', 'New-MgApplication, Add-MgApplicationPassword (SECURITY), write scope'),
    'v05_graph_sample_mail.ps1': ('CHANGES', 'Send-MgUserMail (SECURITY: sends email)'),
    'v06_exo_create_selfsigned_certificate.ps1': ('CHANGES', 'local only: removes certs from the store, enrols and exports a certificate'),
    'v07_exo_module_loader.psm1': ('CANNOT TELL', 'Import-Module of DLL paths held in variables; Remove-Module/Remove-PSSession only unload'),
    'v08_teams_set_release_environment.ps1': ('CHANGES', 'Register-EngineEvent and an env var; nothing in the tenant'),
    'v09_pnp_register_assembly_resolver.ps1': ('CANNOT TELL', 'loads the module DLL by path and invokes a method by reflection'),
    'v10_pnp_spo_delete_empty_folders.ps1': ('DESTRUCTIVE', 'Remove-PnPFolder -Recycle'),
    'v11_pnp_spo_permission_audit.ps1': ('READ-ONLY', 'Get-PnP* and Invoke-PnPSPRestMethod -Method Get; CSV export'),
    'v12_pnp_graph_inactive_guest_delete.ps1': ('DESTRUCTIVE', 'Remove-MgUser on inactive guests (behind a report-only flag)'),
    'v13_m365dsc_exo_mailbox_permission.psm1': ('DESTRUCTIVE', 'Remove-MailboxPermission and Add-MailboxPermission (SECURITY)'),
    'v14_m365dsc_aad_user.psm1': ('DESTRUCTIVE', 'Remove-MgUser, role assignments, Invoke-MgGraphRequest PATCH; Add-Type -AssemblyName System.Web only'),
    'v15_maester_graph_request_send_mail.ps1': ('CANNOT TELL', 'Graph method in $Method, webhook POST to a URI held in a variable, sendMail POST'),
    'v16_maester_connect_install_tests.ps1': ('CANNOT TELL', 'Install-Module Pester; Remove-Item Function:\\ drops a proxy function; Get-Mt* helpers are defined elsewhere in Maester.psm1, so a Get verb proves nothing'),
    'v17_scubagear_connection.psm1': ('CANNOT TELL', 'Import-Module of sibling .psm1 files the checker does not read'),
    'v18_scubagear_dependencies.ps1': ('CANNOT TELL', 'Import-Module of Support.psm1 through a Join-Path variable'),
    'v19_scubagear_spo_rest_helper.psm1': ('CANNOT TELL', 'Import-Module of Utility.psm1 by path; the REST call itself is GET'),
    'v20_monkey365_register_application.ps1': ('CHANGES', 'creates or patches an app registration and its certificate credential via splatted POST/PATCH'),
    'v21_monkey365_write_teams_webhook.ps1': ('CANNOT TELL', 'Invoke-WebRequest POST to a webhook URI from configuration'),
    'v22_monkey365_update_asset.ps1': ('CANNOT TELL', 'downloads a release zip from a URL built at run time; Add-Type of a framework assembly only'),
    'v23_aadinternals_access_token.ps1': ('CANNOT TELL', 'token requests POSTed to URIs built at run time'),
    'v24_aadinternals_aadconnect_api.ps1': ('DESTRUCTIVE', 'calls Remove-AzureADObject; sets passwords, PTA, sync features via POSTs'),
    'v25_aadinternals_graph_api.ps1': ('CANNOT TELL', 'POST and PATCH to URIs built at run time (policy and feature changes)'),
    'v26_atomic_T1098_aad_role.ps1': ('CHANGES', 'Add-AzureADDirectoryRoleMember (SECURITY: admin role), plain-text credential'),
    'v27_atomic_T1098_app_permission.ps1': ('CHANGES', 'New-AzureADApplication, app role assignment (SECURITY)'),
    'v28_atomic_T1114.003_forwarding_rule.ps1': ('CHANGES', 'New-InboxRule -ForwardTo (SECURITY)'),
    'v29_atomic_T1136.003_create_user.ps1': ('CHANGES', 'New-AzureADUser (SECURITY)'),
    'v30_atomic_T1531_delete_user.ps1': ('DESTRUCTIVE', 'Remove-AzureADUser'),
    'a01_intune_remediation_clear_browser_cache.ps1': ('DESTRUCTIVE', 'local: Get-ChildItem -Recurse | Remove-Item -Recurse on cache folders'),
    'a02_intune_remediation_remove_appx.ps1': ('DESTRUCTIVE', 'local: Remove-AppxPackage, Remove-AppxProvisionedPackage'),
    'a03_windows_cleanup_logs_temp.ps1': ('DESTRUCTIVE', 'local: recursive delete of temp and log folders; self-elevates'),
    'a04_backup_sync_folders.ps1': ('DESTRUCTIVE', 'local: Stop-Computer when afterAll is shutdown (robocopy line is commented out)'),
    'a05_windows_cleanup_script.ps1': ('DESTRUCTIVE', 'local: Remove-Item -Recurse, vssadmin delete shadows, wevtutil cl, registry writes'),
    's01_synthetic_enc_loader.ps1': ('SUSPICIOUS', 'powershell -enc hidden command'),
    's03_synthetic_wscript_oneliner.ps1': ('SUSPICIOUS', 'WScript.Shell .Run'),
    's05_synthetic_token_theft_inbox_rule.ps1': ('SUSPICIOUS', 'POSTs a stolen token to a non-Microsoft host; Graph messageRules forward rule'),
    'r01_offboarding_ad_exo_spo.ps1': ('DESTRUCTIVE', 'Remove-DistributionGroupMember, Add-MailboxPermission, AD writes'),
    'r02_risky_user_forwarding_audit_and_reset.ps1': ('DESTRUCTIVE', 'Remove-MailboxPermission, password resets, token POST to a URI built from variables'),
    'r03_bulk_remove_direct_licenses_msol.ps1': ('CHANGES', 'Set-MsolUserLicense -RemoveLicenses'),
    'r04_terminate_user_azuread_exo.ps1': ('CHANGES', 'licence removal, Set-Mailbox, AD disable; Start-Process only re-runs itself elevated'),
    'r05_termination_ad_o365.ps1': ('DESTRUCTIVE', 'Remove-ADPrincipalGroupMembership; Invoke-Command with a literal Start-ADSyncSyncCycle block'),
    'r06_exo_archive_storage_report.ps1': ('READ-ONLY', 'Get-* report to CSV'),
    'r07_o365_termination.ps1': ('DESTRUCTIVE', 'Remove-CalendarEvents, Remove-AzureADGroupMember, licence removal'),
    'r08_disable_user_reset_password_inbox_rules.ps1': ('CANNOT TELL', 'Reddit ate the # comment markers, so bare lines like "Get Customer Credentials" run as commands; also disables and resets'),
    'r09_graph_offboarding_group_removal.ps1': ('DESTRUCTIVE', 'Remove-MgGroupMember, Revoke-MgUserSignInSession'),
    'r10_move_mail_to_shared_and_delete.ps1': ('DESTRUCTIVE', 'Search-Mailbox -DeleteContent, New-TransportRule'),
    'r11_msp_external_email_stats.ps1': ('CHANGES', 'tenant reads only; Install-Module on this computer'),
    'r12_new_mailbox_with_migration.ps1': ('CHANGES', 'New-EXLMailbox (prefixed New-Mailbox), New-EXOMoveRequest, licences; Remove-PSSession only closes sessions'),
    'r13_ediscovery_exports.ps1': ('CHANGES', 'New-ComplianceCase/Search, New-ComplianceSearchAction -Export'),
    'r14_graph_mfa_report_multitenant.ps1': ('CHANGES', 'tenant reads only; Install-Module; Invoke-Item opens the CSV it wrote'),
}
EXPECT.update({
    'p01_module_qualified_az_installer.ps1': ('DESTRUCTIVE', 'Microsoft.PowerShell.Management\\Remove-Item -Recurse on its temp repo; PowerShellGet\\Uninstall-Module; trusted repository'),
    'p02_set_alias_passkeys_entra.psm1': ('SUSPICIOUS', 'Set-Alias gives two Get- names to Invoke-MgCreationUserAuthenticationFido2MethodOption: legitimate, but a Get- name that runs an Invoke- cmdlet is the shape the rule exists for'),
    'p03_and_and_nugetgallery_init.ps1': ('DESTRUCTIVE', 'Remove-Item -Recurse of its clone folder; && only inside a cmd /c string; dot-sources common.ps1'),
    'p04_whatif_preference_o365synchronizer.ps1': ('DESTRUCTIVE', 'Remove-MgUserContact -WhatIf:$WhatIfPreference deletes unless the caller asked for WhatIf'),
    'p05_profile_write_devproxy_setup.ps1': ('CANNOT TELL', 'downloads a zip from a URL built at run time and runs chmod; appends a PATH line (not code) to $PROFILE'),
    'p06_default_scope_azureadassessment.ps1': ('CANNOT TELL', "'.default' goes to Get-MsalToken, not Connect-MgGraph; Write-AppInsightsDependency is defined elsewhere and sends telemetry"),
    'p07_download_then_run_streamlabs_ci.ps1': ('SUSPICIOUS', 'downloads an MSI then runs msiexec on it, iex of the Chocolatey installer, Run key, TrustedHosts *'),
    'p08_and_and_powershell_docker_updatejson.ps1': ('CANNOT TELL', 'runs ../build.ps1 and npx; && is a boolean test inside if ( )'),
    'p09_set_alias_pses_clear_host.ps1': ('CHANGES', 'copies Clear-Host to __clearhost, redefines Clear-Host, aliases clear to Clear-Host (what clear already means)'),
    'p10_download_data_azure_sdk_recordings.ps1': ('DESTRUCTIVE', 'Remove-Item -Recurse; downloads zips from URLs returned by az and expands them, never runs them'),
})


def run():
    """Print one line per script that differs, then the match count."""
    checker, names = m365check.Checker(), m365check.LEVEL_NAMES
    ok = 0
    for name, (want, why) in EXPECT.items():
        path = HERE / 'corpus' / 'real' / name
        if not path.is_file():
            print(f'MISSING {name} (fetch it from the URL in corpus/real/SOURCES.md)')
            continue
        got = names[m365check.verdict(checker.check_file(path))]
        ok += got == want
        if got != want:
            print(f'differs {name}: expected {want} ({why}), got {got}')
    print(f'{ok}/{len(EXPECT)} real scripts match their expected verdict')


if __name__ == '__main__':
    run()
