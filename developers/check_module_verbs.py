#!/usr/bin/env python3
"""Rate every cmdlet in the Microsoft 365 modules with m365check and list the ones whose verdict disagrees with
what the vendor says the cmdlet does.

Run:  python3 developers/check_module_verbs.py [WORKDIR]
Downloads (into WORKDIR, default ./module-verbs-cache) the PowerShell Gallery command lists of the Graph, Entra,
PnP, SharePoint Online, Teams and retired AzureAD modules, MSOnline's names from its package help file (its Gallery
entry carries no command tags and its Learn pages are gone), and Microsoft.Graph.Authentication's MgCommandMetadata.json, which holds
the HTTP method of every Graph cmdlet. Nothing is installed or run; the downloads are read as data.

Prints three lists to work through by hand against each cmdlet's Learn or PnP page:
  1. Graph cmdlets m365check rates READ-ONLY whose HTTP method is POST, PATCH, PUT or DELETE (most POSTs here are
     reads such as checkMemberGroups; the writes go into verbs/policy.json cmdlet_overrides).
  2. Non-Graph cmdlets rated READ-ONLY whose verb is not Get (Import, Request and Connect were writes in 2026-10).
  3. Cmdlets rated CANNOT TELL because their verb is not an approved one (Exchange's Delete-, Release-, ...).
Exchange and Purview cmdlets are not on the Gallery (they are generated at sign-in); their list comes from the
Learn module index page.
"""
import io
import json
import re
import sys
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import m365check  # noqa: E402

GALLERY = 'https://www.powershellgallery.com/api/v2/'
MODULES = re.compile(r'(?i)^(Microsoft\.Graph(\.|$)|PnP\.PowerShell$|Microsoft\.Online\.SharePoint\.PowerShell$'
                     r'|MicrosoftTeams$|Microsoft\.Entra(\.|$)|ExchangeOnlineManagement$|AzureAD(Preview)?$)')
RETIRED = re.compile(r'^Microsoft\.Graph\.(PlusPlus|Intune|Migration\.Tool|Copilot)$|\.Enrolment$')  # not Microsoft's current SDK
EXCHANGE_INDEX = 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/?view=exchange-ps'
METHOD_LEVEL = {'GET': m365check.READ, 'POST': m365check.CHANGES, 'PATCH': m365check.CHANGES, 'PUT': m365check.CHANGES,
                'DELETE': m365check.DESTRUCTIVE}


def get(url):
    """Fetch a URL as bytes; the Gallery and Learn refuse Python's default User-Agent less often with one set."""
    return urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'm365check-module-verbs'}), timeout=120).read()


def gallery_commands():
    """{module: [command, ...]} for the latest version of each module, from the Gallery's PSCommand_ tags."""
    found = {}
    for term in ('Microsoft.Graph', 'Microsoft.Entra', 'PnP.PowerShell', 'Microsoft.Online.SharePoint.PowerShell',
                 'MicrosoftTeams', 'ExchangeOnlineManagement', 'AzureAD'):
        skip = 0
        while True:
            xml = get(f"{GALLERY}Search()?searchTerm={urllib.parse.quote(repr(term))}&targetFramework=''"
                      f"&includePrerelease=false&$filter=IsLatestVersion&$top=100&$skip={skip}").decode('utf-8', 'replace')
            entries = re.findall(r'<entry>(.*?)</entry>', xml, re.S)
            for e in entries:
                name = re.search(r'<d:Id>([^<]+)', e) or re.search(r'<title[^>]*>([^<]+)', e)
                tags = re.search(r'<d:Tags>([^<]*)', e)
                if name and MODULES.match(name.group(1)) and not RETIRED.search(name.group(1)):
                    found[name.group(1)] = sorted(set(re.findall(r'PSCommand_(\S+)', tags.group(1) if tags else '')))
            if len(entries) < 100:
                break
            skip += 100
    return found


def graph_methods(cache):
    """{Graph cmdlet: {HTTP methods}} from MgCommandMetadata.json in the latest Microsoft.Graph.Authentication."""
    path = cache / 'MgCommandMetadata.json'
    if not path.is_file():
        pkg = zipfile.ZipFile(io.BytesIO(get(GALLERY + 'package/Microsoft.Graph.Authentication')))
        path.write_bytes(pkg.read('custom/common/MgCommandMetadata.json'))
    methods = defaultdict(set)
    for e in json.loads(path.read_text(encoding='utf-8')):
        if e.get('Method'):
            methods[e['Command']].add(e['Method'].upper())
    return methods


def msonline_commands():
    """MSOnline cmdlet names from the MAML help files inside its last Gallery package."""
    pkg = zipfile.ZipFile(io.BytesIO(get(GALLERY + 'package/MSOnline')))
    names = set()
    for n in pkg.namelist():
        if n.lower().endswith('-help.xml') and '/' not in n:
            names |= set(re.findall(r'<command:name>\s*([A-Za-z]+-Msol\w+)\s*</command:name>', pkg.read(n).decode('utf-8', 'replace')))
    return sorted(names)


def exchange_commands():
    """Exchange and Purview cmdlet names from the Learn module index."""
    page = get(EXCHANGE_INDEX).decode('utf-8', 'replace')
    return sorted(set(re.findall(r'>([A-Z][a-z]+-[A-Za-z0-9]+)<', page)))


def main():
    """Download, rate, and print the three disagreement lists."""
    cache = Path(sys.argv[1] if len(sys.argv) > 1 else 'module-verbs-cache')
    cache.mkdir(exist_ok=True)
    checker, names = m365check.Checker(), set()
    for cmds in gallery_commands().values():
        names.update(cmds)
    names.update(exchange_commands())
    names.update(msonline_commands())
    methods = graph_methods(cache)
    rated = {n: m365check.verdict(checker.check_text(n + '\n', 'x')) for n in sorted(names | set(methods))}
    graph_writes = [n for n, ms in methods.items()
                    if rated.get(n) == m365check.READ and max(METHOD_LEVEL[m] for m in ms) > m365check.READ]
    other_reads = [n for n, lvl in rated.items() if lvl == m365check.READ and n not in methods and not n.startswith('Get-')]
    no_verb = [n for n, lvl in rated.items() if lvl == m365check.UNKNOWN and n.split('-')[0].lower() not in checker.policy.verb_level]
    for title, items in (('Graph cmdlets rated READ-ONLY that call POST/PATCH/PUT/DELETE', graph_writes),
                         ('Other cmdlets rated READ-ONLY with a verb other than Get', other_reads),
                         ('Cmdlets with an unapproved verb (CANNOT TELL)', no_verb)):
        print(f'## {title}: {len(items)}')
        for n in sorted(items):
            print(f'  {n}' + (f'  {"/".join(sorted(methods[n]))}' if n in methods else ''))
    print(f'\n{len(rated)} cmdlets rated against policy {checker.policy.version}')


if __name__ == '__main__':
    main()
