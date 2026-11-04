#!/usr/bin/env python3
"""
M365 Script Checker (m365check)
=============================================================================
Copyright (c) 2026 Paul Ogier, Outsource House (South Africa)
Website: https://osh.co.za | Email: support@osh.co.za
Training provided by Taming.Tech (https://taming.tech)

Licence: Apache License 2.0 (full text in LICENSE at the repository root)

In plain English:
  - Free to use, including for commercial purposes.
  - Modify and redistribute freely; closed-source derivatives are allowed.
  - PLEASE KEEP THE ATTRIBUTION above intact. If you redistribute this
    file (modified or not), the copyright and contact block at the top must
    stay in place (Apache 2.0 clause 4(c)).
  - No warranty: the disclaimer below is part of the licence terms.
  - "OSH", "Outsource House", and "Taming.Tech" are trademarks and are
    not licensed for use in your own product or marketing names
    (Apache 2.0 clause 6).

DISCLAIMER & LIMITATION OF LIABILITY:
This software is provided "AS IS", without warranty of any kind, express or
implied. The authors (Paul Ogier, Outsource House) accept NO RESPONSIBILITY
for any damages, data loss, or system issues that may arise from its use. A
READ-ONLY verdict is a reading of the script text, not a guarantee that
running it is safe.

YOU ASSUME ALL RISK ASSOCIATED WITH THE USE OF THIS SOFTWARE.
=============================================================================

Author:       Paul Ogier
Created:      2026-09-15
Updated:      2026-11-04
Version:      0.6.0
Status:       Pre-release
Python:       3.9+
Dependencies: None. Stdlib only; never runs PowerShell or the script it checks.

Reads a Microsoft 365 PowerShell script (Graph SDK, Exchange Online, Teams,
SharePoint, the legacy AzureAD and MSOnline modules) and reports what it would
do to the tenant and to your computer, without running it.

Sibling of the GAM Script Checker (github.com/PaulOgier/GAMScripts) and built
to the same shape: five levels, one finding per command, anything decided at
run time is CANNOT TELL, exit code is the worst level.

Every cmdlet is classified by its PowerShell verb (Get reads, Set changes,
Remove deletes) unless verbs/policy.json says otherwise for that cmdlet.
Raw Graph and HTTP calls are classified by their literal -Method; a -Method
held in a variable is CANNOT TELL. Text run as code, downloaded code, and
data posted to a host that is not Microsoft's are SUSPICIOUS.

Usage:
    python3 m365check.py SCRIPT [SCRIPT ...] [--json] [--quiet] [--pin-dir DIR]
    python3 m365check.py              asks you to paste commands (so does --paste)
    some-command | python3 m365check.py -

Exit code is the worst verdict found:
    0 READ-ONLY, 1 CHANGES, 2 CANNOT TELL, 3 DESTRUCTIVE, 4 SUSPICIOUS

This is a tokeniser, not the PowerShell AST. It does not follow string
concatenation that builds a command name, values that arrive from a file or a
pipeline, or helpers defined in another file. Each of those reads as CANNOT
TELL or is invisible; the README lists them.
"""
import argparse
import bisect
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

__version__ = '0.6.0'

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / 'verbs' / 'policy.json'

LEVEL_NAMES = ['READ-ONLY', 'CHANGES', 'CANNOT TELL', 'DESTRUCTIVE', 'SUSPICIOUS']
READ, CHANGES, UNKNOWN, DESTRUCTIVE, SUSPICIOUS = range(5)
LEVEL_OF = {name: i for i, name in enumerate(LEVEL_NAMES)}


@dataclass
class Finding:
    """One thing the script would do, located by file and line."""
    file: str
    line: int
    level: int
    what: str
    command: str = ''
    security: str = ''
    note: str = ''
    undo: str = ''
    docs: str = ''
    target: str = ''  # 'tenant', 'local', or '' when it could be either

    def as_dict(self):
        """Serialise for --json, with the level spelled out."""
        d = asdict(self)
        d['level'] = LEVEL_NAMES[self.level]
        return d


class Policy:
    """The tables in verbs/policy.json, compiled once."""

    def __init__(self, path=POLICY_FILE):
        with open(path, encoding='utf-8') as fh:
            raw = json.load(fh)
        self.version = raw['version']
        self.verb_level = {}
        for name, verbs in raw['verb_levels'].items():
            for v in verbs:
                self.verb_level[v.lower()] = LEVEL_OF[name]
        self.scopes = [(label, re.compile('|'.join(f'(?:{p})' for p in pats), re.I)) for label, pats in raw['scopes'].items()]
        self.local_harmless = {c.lower() for c in raw['local_harmless']}
        self.local_rules = [(LEVEL_OF[lvl], re.compile(pat, re.I), param, what, sec)
                            for lvl, pat, param, what, sec in raw['local_rules']]
        self.native = {}
        for lvl, names in raw['native_exes'].items():
            for n in names:
                self.native[n.lower()] = LEVEL_OF[lvl]
        self.native_rules = [(LEVEL_OF[lvl], re.compile(exe, re.I), re.compile(args, re.I), what, sec)
                             for lvl, exe, args, what, sec in raw['native_rules']]
        self.dotnet_rules = [(LEVEL_OF[lvl], re.compile(pat), what) for lvl, pat, what in raw['dotnet_rules']]
        self.overrides = [(LEVEL_OF[lvl], re.compile(pat, re.I), param, what, sec, undo, docs)
                          for lvl, pat, param, what, sec, undo, docs in raw['cmdlet_overrides']]
        self.security = [(re.compile(pat), what) for pat, what in raw['security_rules']]
        self.undo = [(re.compile(pat, re.I), text, docs) for pat, text, docs in raw['undo']]
        self.param_notes = [(re.compile(pat, re.I), names, text) for pat, names, text in raw['param_notes']]
        self.aliases = {k.lower(): v for k, v in raw['aliases'].items()}
        self.known_hosts = tuple(h.lower() for h in raw['known_hosts'])
        self.code_hosts = tuple(h.lower() for h in raw['code_hosts'])
        self.tenant_hosts = tuple(h.lower() for h in raw['tenant_hosts'])
        self.sink_hosts = tuple(h.lower() for h in raw.get('sink_hosts', []))
        self.path_rules = [(LEVEL_OF[lvl], re.compile(cmd, re.I), re.compile(pat, re.I), what, sec)
                           for lvl, cmd, pat, what, sec in raw['path_rules']]
        self.code_in_text = re.compile(raw['code_in_text'])
        self.write_cmdlets = {c.lower() for c in raw['write_cmdlets']}
        self.known_scripts = [(LEVEL_OF[lvl], re.compile(pat, re.I), param, what, sec, undo, target)
                              for lvl, pat, param, what, sec, undo, target in raw['known_scripts']]

    def scope_of(self, noun):
        """The Microsoft 365 workload a cmdlet noun belongs to, or '' when it is not a tenant cmdlet we know."""
        for label, pat in self.scopes:
            if pat.search(noun):
                return label
        return ''

    @staticmethod
    def _under(host, suffixes):
        return any(host == k or host.endswith('.' + k) for k in suffixes)

    def host_kind(self, host):
        """'microsoft' for a Microsoft API host, 'code' for a module or code-hosting site (fine to download
        from, not to post to), 'tenant' for an address any Microsoft 365 tenant can own, 'sink' for an address
        anyone can create in their own Azure or Microsoft 365 tenant to receive data (a webhook, a Logic App,
        storage, a web app), '' for the rest."""
        host = (host or '').lower()
        if self._under(host, self.sink_hosts):
            return 'sink'
        if self._under(host, self.known_hosts):
            return 'microsoft'
        if self._under(host, self.code_hosts):
            return 'code'
        if self._under(host, self.tenant_hosts):
            return 'tenant'
        return ''


# ---------------------------------------------------------------- masking --

PLACEHOLDER = re.compile(r'\x00(\d+)\x00')
HERE_NL = '\x1f\n'  # a here-string's own newline: a line for numbering, never the end of a command (\x1f is whitespace to str.isspace and \s)


def subexpr_end(text, i):
    """Index just past the ) closing a $( whose body starts at i.

    Quotes inside the body are skipped as whole strings, so the inner quotes of
    "$(Get-Date -Format "yyyy")" do not end the outer string.
    """
    depth, n = 1, len(text)
    while i < n:
        c = text[i]
        if c == '`':
            i += 2
            continue
        if c in '\'"':
            j = i + 1
            while j < n and text[j] != c:
                if c == '"' and text[j] == '`':
                    j += 1
                elif c == '"' and text.startswith('$(', j):
                    j = subexpr_end(text, j + 2)
                    continue
                j += 1
            i = j + 1
            continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def subexprs_in(text, start, stop):
    """(body_start, body_end) of every top-level $( ) between start and stop, the parts of an expanding string that run."""
    spans, j = [], start
    while j < stop:
        if text[j] == '`':
            j += 2
            continue
        if text.startswith('$(', j):
            e = subexpr_end(text, j + 2)
            spans.append((j + 2, e - 1))
            j = e
            continue
        j += 1
    return spans


def in_bare_word(text, i):
    """True when text[i] continues an unquoted bare word (abc#def, a URL, a path), where PowerShell reads # as a
    character. After a quote, a bracket, a variable ($a#x) or a number, # opens a comment: reading it as text
    instead would let a quote inside that comment hide the lines after it."""
    j = i
    while j > 0 and re.match(r'[\w.\\/:\-~%+*?!@,=]', text[j - 1]) and text[j - 1] not in ',=':
        j -= 1
    word = text[j:i]
    if not word or (j > 0 and text[j - 1] in '$\'"`)]}') or word.startswith('@'):
        return False
    return not re.fullmatch(r'[\d.]+', word)


HASH_MODES = ('word', 'all', 'space')


def hash_comment(text, i, mode):
    """Whether the # (or <#) at i opens a comment under one reading. PowerShell's own rule (a # inside a bare word
    is text) is approximated three ways, and check_text scans with each reading that changes the result:
    'word' asks in_bare_word, 'all' treats every # as a comment, 'space' only a # after whitespace or an operator."""
    if mode == 'all':
        return True
    if mode == 'space':
        return i == 0 or text[i - 1].isspace() or text[i - 1] in ';|&(){},='
    return not in_bare_word(text, i)


def mask(text, mode='word'):
    """Replace comments with spaces and string literals with \\x00N\\x00 placeholders.

    Line numbers survive: a masked here-string keeps its newlines after the
    placeholder. Returns (masked_text, strings, subexprs) where strings[N] is the
    literal content, quotes stripped, and subexprs lists the (start, end) of each
    $( ) body inside a double-quoted string or here-string, which PowerShell runs.
    """
    out, strings, subs = [], [], []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == '<#' and hash_comment(text, i, mode):  # block comment
            j = text.find('#>', i + 2)
            j = n if j == -1 else j + 2
            out.append(re.sub(r'[^\n]', ' ', text[i:j]))
            i = j
        elif c == '#' and hash_comment(text, i, mode):  # line comment
            j = text.find('\n', i)
            j = n if j == -1 else j
            out.append(' ' * (j - i))
            i = j
        elif two in ('@"', "@'") and text[i + 2:i + 3] in ('\n', '\r'):  # here-string
            close = '\n' + two[1] + '@'
            j = text.find(close, i + 2)
            j = n if j == -1 else j + len(close)
            body = text[i:j]
            if two == '@"':
                subs += subexprs_in(text, i + 2, j)
            strings.append(body[3:-3] if j < n or body.endswith(close) else body[3:])
            out.append(f'\x00{len(strings) - 1}\x00' + HERE_NL * body.count('\n'))
            i = j
        elif c == "'":
            j = i + 1
            while j < n:
                if text[j] == "'":
                    if text[j + 1:j + 2] == "'":
                        j += 2
                        continue
                    break
                j += 1
            strings.append(text[i + 1:j].replace("''", "'"))
            out.append(f'\x00{len(strings) - 1}\x00' + '\n' * text[i:j].count('\n'))
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n and (text[j] != '"' or text[j + 1:j + 2] == '"'):
                if text[j] == '"':  # "" inside a double-quoted string is one quote
                    j += 2
                    continue
                if text[j] == '`':
                    j += 1
                elif text.startswith('$(', j):
                    e = subexpr_end(text, j + 2)
                    subs.append((j + 2, e - 1))
                    j = e
                    continue
                j += 1
            strings.append(text[i + 1:j].replace('""', '"'))
            out.append(f'\x00{len(strings) - 1}\x00' + '\n' * text[i:j].count('\n'))
            i = j + 1
        else:
            out.append(c)
            i += 1
    return ''.join(out), strings, subs


def unmask(fragment, strings):
    """Put the literal text back into a masked fragment, for display."""
    return PLACEHOLDER.sub(lambda m: "'" + strings[int(m.group(1))] + "'", fragment)


# ------------------------------------------------------------- tokenising --

# A command name at a command position: start of text, after a newline, | ; { ( = & ! && or a keyword.
# Not after a comma: `Select-Object DisplayName, Id` is one argument list, never a second command.
# The name can be a script path, a relative or drive path (.\tool.exe, C:\x\y.exe), a module-qualified
# cmdlet (Microsoft.Graph\Get-MgUser), a bare word, an alias symbol, or & / . followed by a target.
COMMAND_POS = re.compile(
    r'(?:^|[\n|;{}(=!]|&&|\b(?:if|elseif|while|until|return|throw|else|in|do|try|finally|catch|switch)\s'
    r'|-(?:not|and|or)\s)[ \t]*'
    r'(?P<name>[\w.\\:/-]+\.ps1|(?:\.{1,2}[\\/]|[A-Za-z]:[\\/])\S+|[A-Za-z_][\w.]*\\[A-Za-z]+-[A-Za-z0-9_]+'
    r'|[A-Za-z_][\w.-]*|\?|%|&\s*(?!\{)\S+|\.\s+(?!\{)\S+)', re.M)  # & { ... } is not a name: its { starts the commands inside
PATH_LIKE = re.compile(r'^(?:\.{1,2}[\\/]|[A-Za-z]:[\\/]|\\\\)')
REQUIRES_ADMIN = re.compile(r'(?im)^[ \t]*#Requires\s+-RunAsAdministrator\b')
KEYWORDS = {'if', 'elseif', 'else', 'while', 'until', 'do', 'for', 'foreach', 'switch', 'try', 'catch', 'finally',
            'function', 'filter', 'param', 'return', 'throw', 'break', 'continue', 'exit', 'begin', 'process', 'end',
            'in', 'trap', 'data', 'class', 'enum', 'true', 'false', 'null', 'default'}
VERB_NOUN = re.compile(r'^([A-Za-z]+)-([A-Za-z0-9_]+)$')
GAM_LINE = re.compile(r'(?m)^[ \t]*gam7?\s+\S')
# A bare word followed by a comparison is a property in a filter block ({UserPrincipalName -eq $upn}), not a command.
COMPARISON = re.compile(r'(?i)-[ci]?(?:eq|ne|gt|ge|lt|le|like|notlike|match|notmatch|contains|notcontains|in|notin)\b')
FUNCTION_DEF = re.compile(r'(?i)\b(?:function|filter)\s+(?:(?:global|script|local|private):)?([\w-]+)')
SELF_PATH = re.compile(r'(?i)\$(?:MyInvocation|PSCommandPath)\b')
REPORT_FILE = re.compile(r'(?i)\.(?:csv|html?|txt|log|json|xml|xlsx?|pdf|md)[\'"]?\s*$')
SCRIPT_VARS = re.compile(r'(?i)\$\{?(HOME|PSScriptRoot|env:(\w+))\}?')
SCRIPT_PATH = re.compile(r'(?i)[\\/]|\.(?:psm1|psd1|dll)\b|Join-Path|PSScriptRoot')
# if ((Get-FileHash <path> [-Algorithm SHA256]).Hash -ne|-eq '<literal>') {: the shape of a SHA-256 pin on a download
CASE_FOLD = r'(?:\.To(?:Upper|Lower)(?:Invariant)?\(\))?'  # .Hash.ToLower() or 'abc...'.ToUpper(): the same comparison
HASH_PIN = re.compile(r'(?i)\bif\s*\(\s*\(\s*Get-FileHash\b(?P<args>[^()]*)\)\.Hash' + CASE_FOLD + r'\s+-(?P<op>[ic]?(?:eq|ne))\s+'
                      r'\x00(?P<lit>\d+)\x00' + CASE_FOLD + r'\s*\)\s*\{')


def ends_continued(masked, i):
    """True when the text before index i, ignoring trailing spaces, ends in a backtick or a comma (the line goes
    on). A backward walk, not masked[:i].rstrip(): that copy made a long script quadratic."""
    j = i - 1
    while j >= 0 and masked[j] in ' \t\r':
        j -= 1
    return j >= 0 and masked[j] in '`,'


def line_starts(masked):
    """The index of every newline in masked, for line_at."""
    return [i for i, c in enumerate(masked) if c == '\n']


def line_at(newlines, pos):
    """1-based line number of pos, from line_starts."""
    return bisect.bisect_left(newlines, pos) + 1


def arg_span(masked, start):
    """The end index of a command's arguments: the next | ; && newline } ) at depth 0. A backtick continues a line."""
    depth, i, n = 0, start, len(masked)
    while i < n:
        c = masked[i]
        if c in '({[':
            depth += 1
        elif c in ')}]':
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and (c in '|;' or masked[i:i + 2] == '&&'):
            return i
        elif depth == 0 and c == '\n' and masked[i - 1:i] != '\x1f':
            if not ends_continued(masked, i):  # a trailing comma continues the argument list too
                return i
        i += 1
    return n


BLOCK_WORDS = KEYWORDS | {'parallel', 'sequence', 'inlinescript', 'configuration', 'workflow', 'dynamicparam', 'clean'}


def closes_statement_block(masked, close):
    """False only when the } at close ends a { } passed as an argument to a command (ForEach-Object { },
    bcdedit /set {default}): the words after it are still that command's arguments. True otherwise, so a
    statement written after an if, switch, function, class or any block the checker does not recognise is read."""
    depth = 0
    for i in range(close - 1, -1, -1):
        c = masked[i]
        if c == '}':
            depth += 1
        elif c == '{':
            if depth:
                depth -= 1
                continue
            if masked[i - 1:i] == '@':
                return False  # @{ } is a hashtable
            if masked[:i].rstrip()[-1:] in (')', ']'):
                return True  # if (...) {, param(...) {, catch [T] {: a statement's block
            def stmt_before(k):
                nl = masked.rfind('\n', 0, k)  # the others are looked for only after it, so each search is one line
                return max(nl, *(masked.rfind(x, max(nl, 0), k) for x in (';', '|', '{', '}', '(', '=', '&&')))
            stmt = stmt_before(i)
            while stmt > 0 and masked[stmt] == '\n' and ends_continued(masked, stmt):
                stmt = stmt_before(stmt)
            first = re.match(r'\s*([^\s({]+)', masked[stmt + 1:i])
            if not first:
                return True
            word = first.group(1).lower()
            return word in BLOCK_WORDS or word.startswith(('$', '[', '@', '.', '&'))
    return True


def split_args(argtext):
    """Whitespace-split arguments, keeping (...) and @{...} groups together."""
    toks, cur, depth = [], [], 0
    for c in argtext.replace('`\n', ' ').replace('`\r\n', ' '):
        if c in '({[':
            depth += 1
        elif c in ')}]':
            depth -= 1
        if c.isspace() and depth <= 0:
            if cur:
                toks.append(''.join(cur))
                cur = []
        else:
            cur.append(c)
    if cur:
        toks.append(''.join(cur))
    return toks


def params_of(argtext, strings, variables=None):
    """Map -Name -> value for a command's arguments. Value: (literal_text or None if dynamic, kind)."""
    params, positional, toks = {}, [], []
    for t in split_args(argtext):  # "a", "b": one array argument split by the space after its comma
        if toks and (toks[-1].endswith(',') or t.startswith(',')):
            toks[-1] += t
        else:
            toks.append(t)
    i = 0
    while i < len(toks):
        t = toks[i]
        if re.match(r'^-[A-Za-z]', t):
            name, _, inline = t[1:].partition(':')
            if inline:
                params[name.lower()] = literal(inline, strings, variables)
            elif i + 1 < len(toks) and not re.match(r'^-[A-Za-z]', toks[i + 1]):
                params[name.lower()] = literal(toks[i + 1], strings, variables)
                i += 1
            else:
                params[name.lower()] = ('$true', 'switch')
        else:
            positional.append(literal(t, strings, variables))
        i += 1
    return params, positional


def literal(tok, strings, variables=None):
    """Resolve one argument token to (text, kind). kind is 'literal', 'dynamic' or 'splat'.

    A bare $name whose only assignments in the file are literals resolves to
    that literal (one level, no expressions), so `Connect-MgGraph -Scopes $scopes`
    can be read when $scopes = @('User.Read.All', ...).
    """
    if tok.startswith('@') and re.match(r'^@[\w]+$', tok):
        return (tok[1:], 'splat')
    if variables and re.fullmatch(r'\$\w+', tok) and tok[1:].lower() in variables:
        return variables[tok[1:].lower()]
    if tok.startswith('$') or tok.startswith('(') or tok.startswith('@(') or tok.startswith('@{'):
        m = PLACEHOLDER.fullmatch(tok)
        if tok.startswith('@(') and not re.search(r'\$|\(.*\(', tok[2:]):
            return (unmask(tok, strings), 'literal')  # @('a','b') is a literal array
        return (None if not m else strings[int(m.group(1))], 'dynamic')
    m = PLACEHOLDER.fullmatch(tok)
    if m:
        s = strings[int(m.group(1))]
        # a double-quoted string that expands a variable is dynamic
        return (s, 'dynamic') if '$' in s else (s, 'literal')
    if '\x00' in tok:
        s = unmask(tok, strings)
        if '$' in s or not re.fullmatch(r'(?:\x00\d+\x00|[\w.-]+)(?:,(?:\x00\d+\x00|[\w.-]+))*', tok):
            return (s, 'dynamic')  # 'Remove'+'-MgUser' or 'x'.ToUpper() is an expression; 'a','b' is a literal list
        return (s, 'literal')
    return (tok, 'literal')


def param(params, name):
    """Look up a parameter by full name or unambiguous prefix, as PowerShell does."""
    name = name.lower()
    if name in params:
        return params[name]
    hits = [v for k, v in params.items() if name.startswith(k)]  # PowerShell accepts any unambiguous prefix (-r for -Recurse)
    return hits[0] if len(hits) == 1 else None


def var_table(masked, strings):
    """$name -> (text, kind) for every variable assigned only literals (strings or @( ) arrays of strings).

    `+=` of a literal appends (even inside an if: the scopes asked for are then
    at most these); any assignment of an expression, or a second plain `=`, or
    one written any other way (see reassigned), makes the variable dynamic. One level only: a variable built
    from another variable is dynamic.
    """
    table, read = {}, {}
    for m in re.finditer(r'(?m)(?:^|[;{(])[ \t]*\$(\w+)[ \t]*(\+?=)[ \t]*(?!@\{)(?=\S)', masked):
        name, op = m.group(1).lower(), m.group(2)
        read[name] = read.get(name, 0) + 1
        value = masked[m.end():arg_span(masked, m.end())].strip()
        val = literal(value, strings)
        if re.search(r'\s', value) and not value.startswith('@('):
            val = (None, 'dynamic')  # `$x = Get-Content f` is a command's output, not a literal
        if val[1] != 'literal' or (op == '=' and name in table):
            table[name] = (None, 'dynamic')
        elif op == '+=' and name in table:
            table[name] = (table[name][0] + ', ' + val[0], 'literal') if table[name][1] == 'literal' else (None, 'dynamic')
        elif op == '=':
            table[name] = val
        else:
            table[name] = (None, 'dynamic')
    for name in reassigned(masked, strings, table, read):
        table[name] = (None, 'dynamic')
    return table


# Any assignment to $name: after ; { ( |, with a type cast, a scope prefix, ${name}, or a compound operator.
ASSIGN_ANY = re.compile(r'(?i)(?<![\w$`])\$\{?(?:(?:global|script|local|private):)?(\w+)\}?[ \t]*((?:[-+*/%]|\?\?)?=)(?!=)')


def reassigned(masked, strings, names, read):
    """The names among names that may hold something other than the literal var_table read for them.

    read counts the assignments var_table took in. The whole text is searched again with the strings put back,
    so an assignment inside a $( ) in a string, or written any way var_table does not read, is counted too: any
    assignment beyond those, or any other way of setting the variable (Set-Variable, the variable: drive, [ref],
    a multiple assignment, a foreach or -OutVariable target, a parameter), makes it dynamic."""
    if not names:
        return set()
    raw = unmask(masked, strings)
    if re.search(r'(?i)SessionState|PSVariable|\$ExecutionContext', raw):
        return set(names)  # a variable set by name through the engine: none of them can be trusted
    dyn = set()
    counts = {}
    for m in ASSIGN_ANY.finditer(raw):
        counts[m.group(1).lower()] = counts.get(m.group(1).lower(), 0) + 1
    dyn |= {n for n in names if counts.get(n, 0) != read.get(n, 0)}
    for n in names:
        if n in dyn:
            continue
        w = re.escape(n)
        if re.search(r'(?i)variable:\\?' + w + r'\b|\[ref\]\s*\$' + w + r'\b'
                     r'|(?:^|[\s;|{(])(?:Set-Variable|New-Variable|Clear-Variable|Remove-Variable|Get-Variable|sv|set|nv|clv|rv|gv)\b[^\n;|]*?'
                     r'(?:\s|[\'"]|:)' + w + r'\b'
                     r'|-(?:OutVariable|ov|ErrorVariable|ev|WarningVariable|wv|InformationVariable|iv|PipelineVariable|pv)[\s:]+[\'"]?\+?' + w + r'\b'
                     r'|\bforeach\s*\(\s*\$' + w + r'\s+in\b', raw):
            dyn.add(n)
    for m in re.finditer(r'(?:\$[\w:{}]+\s*,\s*)+\$[\w:{}]+\s*=(?!=)', raw):
        dyn.update(x.lower() for x in re.findall(r'\$(?:\w+:)?\{?(\w+)', m.group(0)))
    for m in re.finditer(r'(?i)\bparam\s*\(|\bfunction\s+\S+?\s*\(', masked):
        dyn.update(x.lower() for x in re.findall(r'\$(\w+)', masked[m.end():subexpr_end(masked, m.end())]))
    return dyn & set(names)


def top_level(body):
    """body with everything inside a nested (), [], {} or @{ } blanked, so only its own Key = value lines show."""
    out, depth = [], 0
    for c in body:
        if c in ')]}':
            depth = max(depth - 1, 0)
        out.append(c if depth == 0 or c == '\n' else ' ')
        if c in '([{':
            depth += 1
    return ''.join(out)


def table_key(k, strings):
    """A hashtable key as written: a bare word or a single-quoted or literal string; None for "$expanding" keys."""
    if not k.startswith('\x00'):
        return k.lower()
    text = strings[int(k.strip('\x00'))]
    return None if '$' in text or '`' in text else text.lower()


def hashtable_entries(body, strings, variables=None):
    """Key -> (text, kind) for the top-level Key = value lines of a hashtable body, or None when a key is built
    at run time. A key given twice with different values is dynamic."""
    entries = {}
    for k, v in re.findall(r'(\w+|\x00\d+\x00)\s*=(?!=)\s*([^\n;]+)', top_level(body)):
        key = table_key(k, strings)
        if key is None:
            return None
        val = literal(v.strip().rstrip(','), strings, variables)
        entries[key] = val if key not in entries or entries[key] == val else (None, 'dynamic')
    return entries


def splat_table(masked, strings, variables=None):
    """$name -> list of (position, entries) for the tables assigned to $name and the changes made to them, in file
    order: a hashtable assignment opens a new table, $p.Key = v, $p['Key'] = v, $p.Add('Key', v) and
    $p += @{ } add to the one before them. entries is None for a table the checker cannot read: assigned from
    anything but a literal @{ }, given a key built at run time, changed some other way, changed before it was
    first assigned, or copied to another variable that could change it."""
    events = []
    for m in ASSIGN_ANY.finditer(masked):
        rest = masked[m.end():]
        lead = re.match(r'(?i)\s*(?:\[ordered\]\s*)?@\{', rest)
        name = m.group(1).lower()
        if lead and m.group(2) in ('=', '+='):
            body = masked[m.end() + lead.end():block_end(masked, m.end() + lead.end())]
            events.append((m.start(), name, 'def' if m.group(2) == '=' else 'add', hashtable_entries(body, strings, variables)))
        else:
            events.append((m.start(), name, 'def', None))
    key = r'(\x00\d+\x00|\w+)'
    for pat in (r'\$(\w+)\.' + key + r'\s*=(?!=)\s*([^\n;]+)', r'\$(\w+)\[\s*' + key + r'\s*\]\s*=(?!=)\s*([^\n;]+)',
                r'(?i)\$(\w+)\.Add\(\s*' + key + r'\s*,\s*([^)\n]+)\)'):
        for m in re.finditer(pat, masked):
            k = table_key(m.group(2), strings)
            events.append((m.start(), m.group(1).lower(), 'add',
                           None if k is None else {k: literal(m.group(3).strip(), strings, variables)}))
    unread = (r'(?i)\$(\w+)(?:\.(?:Remove|Clear|Set_Item|Item)\s*\(|\.Add\(\s*[^\s\x00\w]|\[\s*[^\]\x00\w]|\.[$(])'
              r'|=\s*(?:\[[\w.]+\]\s*)?\$(\w+)\s*(?:$|[;\n|)}])|\[ref\]\s*\$(\w+)|\bforeach\s*\(\s*\$(\w+)\s+in\b')
    for m in re.finditer(unread, masked, re.M):
        events.append((m.start(), next(g for g in m.groups() if g).lower(), 'unread', None))
    known_pos = {pos for pos, *_ in events}
    for m in re.finditer(r'(?i)\$\{?(?:(?:global|script|local|private):)?(\w+)\}?', masked):
        if m.start() in known_pos:
            continue
        if re.match(r'(?i)\.(?:Count|Keys|Values|ContainsKey|ContainsValue)\b|\[\s*(?:\x00\d+\x00|\w+)\s*\](?!\s*=)', masked[m.end():]):
            continue  # read-only uses
        events.append((m.start(), m.group(1).lower(), 'unread', None))  # any other use could change it or pass it on
    tables, early = {}, set()
    in_block = {name for pos, name, _, _ in events if enclosing_open(masked, pos) >= 0}
    for pos, name, kind, entries in sorted(events, key=lambda e: e[0]):
        defs = tables.get(name)
        if kind == 'def':
            tables.setdefault(name, []).append([pos, None if entries is None or name in early else dict(entries)])
            continue
        if not defs:
            early.add(name)  # changed before any table was assigned: from a function, a loop, or another file
            continue
        last = defs[-1]
        if last[1] is None:
            continue
        if kind == 'unread' or entries is None:
            last[1] = None
            continue
        for k, v in entries.items():
            old = last[1].get(k)
            last[1][k] = v if old is None or old == v else (None, 'dynamic')
    return {name: ([(d[0], d[1]) for d in defs], name in in_block) for name, defs in tables.items()}


# --------------------------------------------------------------- checking --

# PowerShell reads these as ordinary spaces, dashes and quotes, and web pages (Reddit, blogs, Word) put them into
# scripts people copy. Unread, a non-breaking-space indent hides the command after it and an en-dash -DeleteContent
# hides the switch, so they are mapped to ASCII before anything else. One character each, so columns survive.
TYPOGRAPHY = str.maketrans({**{c: ' ' for c in '\x00\x1f\x0b\x0c\x85               　'},
                            '–': '-', '—': '-', '―': '-',
                            '“': '"', '”': '"', '„': '"', '‘': "'", '’': "'", '‚': "'", '‛': "'"})

# Commands whose arguments can carry code for another program to run
CODE_CARRIERS = {'start-process', 'saps', 'start', 'new-scheduledtaskaction', 'new-service', 'register-scheduledjob',
                 'invoke-cimmethod', 'invoke-wmimethod', 'iwmi', 'set-wmiinstance', 'swmi'}
HTTP_CMDLETS = {'invoke-mggraphrequest', 'invoke-restmethod', 'invoke-webrequest', 'invoke-azrestmethod', 'invoke-msgraphrequest'}
METHOD_LEVEL = {'get': READ, 'head': READ, 'options': READ, 'post': CHANGES, 'put': CHANGES, 'patch': CHANGES,
                'merge': CHANGES, 'delete': DESTRUCTIVE}
SIGNIN_SCOPES = {'openid', 'profile', 'email', 'offline_access', 'user.read'}


def expand_script_path(text, base):
    """The path a script call names, with $HOME, $env:NAME, $PSScriptRoot and a leading ~ filled in from this
    computer; relative paths are taken from base. None while any other variable is left in it."""
    def fill(m):
        name = m.group(1).lower()
        if name == 'home':
            return str(Path.home())
        if name == 'psscriptroot':
            return str(base)
        return os.environ.get(m.group(2), m.group(0))
    out = SCRIPT_VARS.sub(fill, text.strip())
    if out.startswith('~'):
        out = str(Path.home()) + out[1:]
    if '$' in out:
        return None
    path = Path(out.replace('\\', '/'))
    return path if path.is_absolute() else base / path


def url_host(uri):
    """(host, userinfo) for an address: the host lower-cased, or '' when it is not a literal dotted name, and True
    when a user name sits before an @ (https://graph.microsoft.com@evil.example/ goes to evil.example)."""
    rest = re.sub(r'(?i)^\s*https?://', '', uri.strip())
    authority = re.split(r'[/?#\\]', rest, maxsplit=1)[0]
    userinfo = '@' in authority
    authority = re.sub(r':\d*$', '', authority.rsplit('@', 1)[-1])
    if re.fullmatch(r'(?i)[a-z0-9-]+(?:\.[a-z0-9-]+)+', authority):
        return authority.lower(), userinfo
    return '', userinfo


def norm_path(text):
    """A file path as written, compared loosely: quotes, a leading ./ and the slash direction do not matter."""
    return re.sub(r'^\./', '', text.strip().strip('\'"').replace('\\', '/')).lower()


def enclosing_open(masked, pos):
    """The index of the { of the innermost block holding pos, or -1 at the top level."""
    depth = 0
    for i in range(pos - 1, -1, -1):
        if masked[i] == '}':
            depth += 1
        elif masked[i] == '{':
            if depth == 0:
                return i
            depth -= 1
    return -1


def block_end(masked, start):
    """The index of the } that closes the block whose body starts at start (just after its {)."""
    depth = 0
    for i in range(start, len(masked)):
        if masked[i] == '{':
            depth += 1
        elif masked[i] == '}':
            if depth == 0:
                return i
            depth -= 1
    return len(masked)


def find_pins(masked, strings):
    """Every SHA-256 pin in a masked text: Get-FileHash of a literal path compared with -eq or -ne to a 64-hex
    literal. Each is (path, sha256, line, branch), where branch is the (start, end) of the code that runs only
    when the hash matched: the if block for -eq; for -ne, the else block, or, when the if block always ends in
    exit, throw or return, the rest of the block the check sits in. MD5, SHA1, a variable or a computed
    comparison value, and a -ne whose block can fall through, are not pins."""
    pins = []
    for m in HASH_PIN.finditer(masked):
        sha = strings[int(m.group('lit'))]
        if not re.fullmatch(r'[0-9a-fA-F]{64}', sha):
            continue
        params, positional = params_of(m.group('args'), strings)
        alg = param(params, 'algorithm')
        if alg and (alg[1] != 'literal' or (alg[0] or '').lower() != 'sha256'):
            continue
        path = param(params, 'path') or param(params, 'literalpath') or (positional[0] if positional else None)
        if not path or path[1] != 'literal' or not path[0]:
            continue
        then_end = block_end(masked, m.end())
        if m.group('op').lower().endswith('eq'):
            branch = (m.end(), then_end)
        else:
            e = re.match(r'\s*else\s*\{', masked[then_end + 1:], re.I)
            last = [x for x in re.split(r'[;\n]', masked[m.end():then_end]) if x.strip()][-1:]
            if e:
                start = then_end + 1 + e.end()
            elif (last and re.match(r'(?i)\s*(?:exit|throw|return)\b', last[0]) and '{' not in masked[m.end():then_end]
                  and not re.search(r'(?i)\btrap\b', masked)):  # trap { continue } resumes after the throw
                start = then_end + 1  # if (mismatch) { ...; exit 1 }: everything after it in this block ran only on a match
            else:
                continue
            branch = (start, block_end(masked, start))
        pins.append((norm_path(path[0]), sha.lower(), masked.count('\n', 0, m.start()) + 1, branch))
    return pins


_FILE_HASHES = {}  # path -> sha256, so a folder is hashed once per run


def file_sha256(path):
    """The SHA-256 of a file on this computer, or None when it cannot be read or is over 5 MB."""
    if path not in _FILE_HASHES:
        try:
            _FILE_HASHES[path] = hashlib.sha256(path.read_bytes()).hexdigest() if path.stat().st_size <= 5_000_000 else None
        except OSError:
            _FILE_HASHES[path] = None
    return _FILE_HASHES[path]


def batch_methods(text):
    """The HTTP methods of every request in a literal Graph $batch body, or None when the body is not JSON or any
    request's method is missing or not a plain HTTP method: one unread request could be the delete."""
    try:
        requests = json.loads(text or '').get('requests')
    except (ValueError, AttributeError):
        return None
    if not isinstance(requests, list) or not requests:
        return None
    methods = set()
    for r in requests:
        m = next((v for k, v in r.items() if k.lower() == 'method'), None) if isinstance(r, dict) else None
        if not isinstance(m, str) or m.lower() not in METHOD_LEVEL:
            return None
        methods.add(m.upper())
    return methods


def whatif(lvl, params, note):
    """(level, note) after a bare -WhatIf: a change or a delete only reports what it would do. -WhatIf:$x is
    whatever $x is at run time, and a level the checker cannot read, or SUSPICIOUS, stays as it is."""
    w = param(params, 'whatif')
    if lvl in (CHANGES, DESTRUCTIVE) and w and w[1] == 'switch':
        return READ, '; '.join(x for x in (note, 'has -WhatIf, so it only reports what it would do') if x)
    return lvl, note


def write_scope(scope):
    """True unless the scope is plainly read-only.

    Graph scopes are Resource.Permission[.Qualifier]; only a Permission of Read or
    ReadBasic is a read. Everything else (ReadWrite, Create, Send, Invite,
    ManageAsApp, AccessAsUser, Selected, EnableDisableAccount, .default) is
    treated as a write, because a denylist of write words misses new ones.
    """
    if scope.lower() in SIGNIN_SCOPES:
        return False
    parts = scope.split('.')
    return not (len(parts) >= 2 and re.fullmatch(r'(?i)read(?:basic)?', parts[1]))


class Checker:
    """Reads a script's text and turns each command into a Finding."""

    def __init__(self, policy=None, depth=0, seen=frozenset()):
        self.policy = policy or Policy()
        self.depth, self.seen = depth, seen  # scripts this one was called from, so a script that calls itself stops
        self.pin_dirs = []  # --pin-dir: more folders to look in for a file whose SHA-256 a script pins

    def check_file(self, path):
        return self.check_bytes(path.read_bytes(), str(path), path.resolve().parent)

    def check_bytes(self, data, name, base=None):
        """Findings for script bytes, by check_readings of decode_candidates."""
        return self.check_readings(decode_candidates(data), name, base)

    def check_readings(self, texts, name, base=None):
        """Findings for one or two readings of the same bytes. Bytes that are neither marked UTF-16 nor valid UTF-8
        are read as UTF-8 and as Windows-1252: the code page decides which bytes are quotes, so both readings are
        kept, the worst on each line."""
        findings = self.check_text(texts[0], name, base)
        if len(texts) > 1:
            worst = {}
            for f in findings:
                worst[f.line] = max(worst.get(f.line, -1), f.level)
            findings += [f for f in self.check_text(texts[1], name, base) if f.level > worst.get(f.line, -1)]
            findings.append(Finding(name, 0, UNKNOWN, 'the file is not UTF-8; it was read as UTF-8 and as Windows-1252',
                                    note='save it as UTF-8 to get one reading'))
        return findings

    def check_text(self, text, name, base=None):
        self.base = base or Path.cwd()  # where a relative script path in this text is looked for
        if self.depth == 0:
            self.memo = {}  # called scripts already read in this check, by path, so a fan-out is read once
        text = text.translate(TYPOGRAPHY)
        findings, seen_masks, seen_findings = [], set(), set()
        for mode in HASH_MODES:  # where the reading of a # is unclear, every reading is checked and the worst kept
            masked, strings, subs = mask(text, mode)
            if masked in seen_masks:
                continue
            seen_masks.add(masked)
            self.hash_mode = mode
            first = not findings and len(seen_masks) == 1
            worst = {}
            for f in findings:
                worst[(f.file, f.line)] = max(worst.get((f.file, f.line), -1), f.level)
            for f in self.check_masked(text, masked, strings, subs, name):
                key = (f.file, f.line, f.level, f.what, f.command)
                if key in seen_findings or (not first and f.level <= worst.get((f.file, f.line), -1)):
                    continue  # another reading of a # only adds what is worse than the first reading on that line
                seen_findings.add(key)
                findings.append(f)
        self.hash_mode = 'word'
        for hit in REQUIRES_ADMIN.finditer(text):
            findings.insert(0, Finding(name, text.count('\n', 0, hit.start()) + 1, READ,
                                       'demands Administrator rights on this computer (#Requires -RunAsAdministrator)',
                                       security='everything in it runs with full rights over this computer', target='local'))
        self.mark_tenant_guard(text, findings)
        if not findings:
            findings.append(Finding(name, 0, UNKNOWN, 'found nothing it can read',
                                    note='no PowerShell command the checker recognises; if you were told this script does '
                                         'something, that is a warning in itself, not a pass'))
        return findings

    def check_masked(self, text, masked, strings, subs, name):
        """The findings for one masked reading of text."""
        variables = var_table(masked, strings)
        self.splats = splat_table(masked, strings, variables)
        self.variables = variables
        self.masked, self.strings = masked, strings
        self.functions = {f.lower() for f in FUNCTION_DEF.findall(masked)}  # their bodies are checked where they are defined
        self.downloads = set()  # file names this script saves from the internet; running one later is SUSPICIOUS
        # a script that redefines Get-FileHash or Unblock-File decides for itself what the check says
        redefined = {'get-filehash', 'unblock-file'} & self.functions or re.search(
            r'(?i)\b(?:Set|New)-Alias\b[^\n;]*\b(?:Get-FileHash|Unblock-File)\b|(?:function|alias):\\?(?:Get-FileHash|Unblock-File)\b', unmask(masked, strings))
        self.pins = [] if redefined else find_pins(masked, strings)
        self.pos = None  # where in masked the command being classified starts; None inside a $( ) body
        self.remote_drives = {}  # New-PSDrive X to a share: drive letter -> line
        self.user_aliases = {}  # Set-Alias gmu Remove-MgUser: a call to gmu is judged as Remove-MgUser
        for m in re.finditer(r'(?im)(?:^|[;{|(&}])[ \t]*(?:Set-Alias|New-Alias|sal|nal)\b', masked):
            params, positional = params_of(masked[m.end():arg_span(masked, m.end())], strings)
            new = param(params, 'name') or (positional[0] if positional else None)
            target = param(params, 'value') or (positional[1] if len(positional) > 1 else None)
            if new and target and new[1] == target[1] == 'literal' and new[0] and target[0]:
                self.user_aliases[new[0].lower()] = (target[0], masked.count('\n', 0, m.end()) + 1)
        return self.scan(masked, strings, subs, text, name, 0, '')

    def known_name(self, raw):
        """True when raw is a command the checker has a rule for: a cmdlet in a known workload, a local rule,
        an override, an HTTP cmdlet, a built-in alias or a program. A function the script defines under such a name
        does not hide the real one: whether a call runs the function or the cmdlet depends on whether the
        definition ran first (it may sit in a branch never taken), so calls are judged as the real command."""
        p, low = self.policy, raw.lower()
        if low in HTTP_CMDLETS or low in p.aliases or low in p.native or low in p.local_harmless or low in p.write_cmdlets:
            return True
        if any(pat.search(raw) for _, pat, *_ in p.local_rules) or any(pat.search(raw) for _, pat, *_ in p.overrides):
            return True
        vn = VERB_NOUN.match(raw)
        return bool(vn and vn.group(1).lower() in p.verb_level and p.scope_of(vn.group(2)))

    def scan(self, masked, strings, subs, text, name, line_base, where):
        """Findings for every command in one masked text, then for the $( ) bodies inside its expanding strings.

        text is the unmasked source masked came from; line_base is the number of
        lines before it in the file, so a command inside "...$(...)" on line 40
        is reported on line 40.
        """
        findings = []
        newlines = line_starts(masked)
        for m in COMMAND_POS.finditer(masked):
            raw = m.group('name').strip()
            if not raw or raw.lower() in KEYWORDS or raw.startswith('-'):
                continue
            if raw.lower() == 'foreach' and masked[m.end():m.end() + 2].strip().startswith('('):
                continue  # the foreach keyword, not the alias
            if re.fullmatch(r'\$[\w:]+|\d[\w.]*|\.\.?', raw):
                continue  # a variable or number at the start of an expression
            sep = m.start()
            if masked[sep:sep + 1] == '\n' and ends_continued(masked, sep):
                continue  # the line before continues onto this one, so this word is an argument
            if masked[sep:sep + 1] == '}' and not closes_statement_block(masked, sep):
                continue  # the } of a script block passed as an argument: what follows is still that command's arguments
            if masked[sep:sep + 1] == '(' and sep and (masked[sep - 1].isalnum() or masked[sep - 1] == '_'):
                k = sep
                while k > 0 and (masked[k - 1].isalnum() or masked[k - 1] == '_'):
                    k -= 1
                word = masked[k:sep]
                if word.lower() not in KEYWORDS:
                    continue  # [Parameter(Mandatory)] or $x.Method(arg): an argument, not a command
            after = masked[m.end():m.end() + 40].lstrip()
            if '-' not in raw and (after.startswith('=') or after.startswith('{') or COMPARISON.match(after)):
                continue  # a hashtable key (Name = value), a switch case (default { ... }) or a filter property (Name -eq $x)
            line = line_base + line_at(newlines, m.start('name'))  # not m.start(): the separator may be the previous line's newline
            end = arg_span(masked, m.end())
            argtext = masked[m.end():end]
            shown = re.sub(r'\s+', ' ', unmask(masked[m.start('name'):end], strings)).strip()[:160]
            nl = masked.rfind('\n', 0, m.start())
            stmt_start = max(nl, masked.rfind(';', max(nl, 0), m.start())) + 1
            self.pos = None if where else m.start('name')
            f = self.classify(raw, argtext, strings, self.splats, name, line, shown, masked[stmt_start:end])
            if isinstance(f, list):
                findings += f
            elif f:
                findings.append(f)
        for lvl, pat, what in self.policy.dotnet_rules:
            for hit in pat.finditer(masked):
                line = line_base + line_at(newlines, hit.start())
                start = masked.rfind('\n', 0, hit.start()) + 1
                stop = masked.find('\n', hit.end())
                shown = re.sub(r'\s+', ' ', unmask(masked[start:stop if stop != -1 else None], strings)).strip()[:160]
                findings.append(Finding(name, line, lvl, what, command=shown))
        for hit in GAM_LINE.finditer(masked):
            line = line_base + line_at(newlines, hit.start())
            findings.append(Finding(name, line, UNKNOWN, 'runs gam; check this script with the GAM Script Checker too',
                                    command=unmask(masked[hit.start():masked.find('\n', hit.start())].strip(), strings)[:160]))
        if where:
            for f in findings:
                f.note = '; '.join(x for x in (f.note, where) if x)
        for s, e in subs:
            body = text[s:e]
            b_masked, b_strings, b_subs = mask(body, getattr(self, 'hash_mode', 'word'))
            findings += self.scan(b_masked, b_strings, b_subs, body, name, line_base + text.count('\n', 0, s),
                                  'runs inside a $( ) in a string')
        return findings

    def assigned(self, var):
        """The unmasked right-hand side of every `$var = ...` or `$var += ...` in the file, joined; '' when there is none."""
        pat = re.compile(r'(?im)(?:^|[;{(])[ \t]*(?:\[[\w.\[\]]+\][ \t]*)?\$' + re.escape(var) + r'[ \t]*\+?=[ \t]*([^\n;]*)')
        return ' '.join(unmask(m.group(1), self.strings) for m in pat.finditer(self.masked))

    def target_text(self, argtext, params, positional, name):
        """What a -Path/-FilePath style argument says: its literal text, or the text assigned to the variable it names."""
        v = param(params, name) or (positional[0] if positional else None)
        m = re.match(r'\s*(?:-\w+\s+)?\$(\w+)\s*(?:$|\s)', argtext)
        if m and (v is None or v[0] is None):
            return self.assigned(m.group(1))
        return v[0] if v and v[0] else ''

    def splat_at(self, name):
        """The table @name splats at the command being classified, or None when the checker cannot say.

        In straight-line top-level code (the command, and every assignment and change of that table, outside any
        block) the latest table before the command is the one in force. Anywhere else (a function, a loop, a
        branch, a $( ) in a string) every table assigned to that name is merged, and a key they disagree on is
        dynamic: which one is in force depends on how the script runs."""
        if name not in self.splats:
            return None
        defs, in_block = self.splats[name]
        pos = self.pos
        straight = pos is not None and not in_block and enclosing_open(self.masked, pos) < 0
        before = [entries for p, entries in defs if p < pos] if straight else []
        chosen = before[-1:] if before else [entries for _, entries in defs]
        if any(c is None for c in chosen):
            return None
        merged = {}
        for entries in chosen:
            for k, v in entries.items():
                merged[k] = v if k not in merged or merged[k] == v else (None, 'dynamic')
        if len(chosen) > 1:  # a key only some of the tables set may be missing at the call
            for k in merged:
                if any(k not in c for c in chosen):
                    merged[k] = (None, 'dynamic')
        return merged

    def alias_finding(self, raw, low, params, positional, argtext, argraw, strings, file, line, shown, note):
        """Set-Alias, New-Alias or a write to the Alias: or Function: drive.

        SUSPICIOUS only when the new name can disguise what runs: it is already an
        alias for something else, it is a program name, or it is a Verb-Noun name
        whose verb reads milder than the command behind it (Get-MgUser -> Remove-MgUser).
        A new short name (ll, __clearhost) cannot pass for anything, so it is CHANGES.
        """
        p = self.policy
        if low in ('set-alias', 'new-alias'):
            name_v = param(params, 'name') or (positional[0] if positional else None)
            value_v = param(params, 'value') or (positional[1] if len(positional) > 1 else None)
            suspicious_what = 'renames a command; nothing after this line can be trusted to be what it looks like'
        else:
            m = re.search(r'(?i)(?:^|[\s\'"])(?:alias|function):\\?([\w-]+)', argraw)
            name_v = (m.group(1), 'literal') if m else None
            rest = [v for v in positional if not (v[0] and re.search(r'(?i)(?:alias|function):', v[0]))]
            value_v = param(params, 'value') or (rest[0] if rest else None)
            suspicious_what = 'defines or renames a command; nothing after this line can be trusted to be what it looks like'
            if low == 'remove-item':
                return Finding(file, line, CHANGES, f'removes a function or alias definition{": " + name_v[0] if name_v else ""}',
                               command=shown, note=note, target='local')
        sec = 'a harmless-looking name can now run a different command'
        if not name_v or name_v[1] != 'literal' or self.writes_code(argtext, strings):
            return Finding(file, line, SUSPICIOUS, suspicious_what, command=shown, security=sec, note=note)
        new, target = name_v[0], (value_v[0] if value_v and value_v[1] == 'literal' else None)
        new_vn, target_vn = VERB_NOUN.match(new), VERB_NOUN.match(target or '')
        target_lvl = p.verb_level.get(target_vn.group(1).lower(), UNKNOWN) if target_vn else UNKNOWN
        existing = p.aliases.get(new.lower())
        disguises = ((existing and (target or '').lower() != existing.lower())
                     or new.lower() in p.native
                     or (self.known_name(new) and (target or '').lower() not in (new.lower(), (existing or '').lower()))
                     or (new_vn and target_lvl > p.verb_level.get(new_vn.group(1).lower(), UNKNOWN)))
        if disguises:
            return Finding(file, line, SUSPICIOUS, suspicious_what, command=shown, security=sec, note=note)
        if low not in ('set-alias', 'new-alias'):
            self.functions.add(new.lower())  # a function: copy; later calls run that copy, reported here
        return Finding(file, line, CHANGES, f'creates an alias or function {new}' + (f' for {target}' if target else ''),
                       command=shown, note=note, target='local')

    def restarts_itself(self, argtext, argraw, params, positional):
        """True for the self-elevation idiom: Start-Process powershell -Verb RunAs with this script's own path
        ($MyInvocation or $PSCommandPath) in the arguments, literally or through the variable -ArgumentList names."""
        program = self.target_text(argtext, params, positional, 'filepath')
        verb = (param(params, 'verb') or ('',))[0] or ''
        if not re.fullmatch(r'(?i)(?:powershell|pwsh)(?:\.exe)?', program) or verb.lower() != 'runas':
            return False
        m = re.search(r'(?i)-ArgumentList\s+\$(\w+)', argtext)
        return bool(SELF_PATH.search(argraw + ' ' + (self.assigned(m.group(1)) if m else '')))

    def pin_for(self, target):
        """The pin whose matched-hash branch holds the command being classified and names target, or None.

        None as well when anything but an Unblock-File of that file or a Write-Host style message sits between
        the start of that branch and this command: a Set-Location, a copy over the file, or a second download
        after the check would each run something that was never hashed."""
        if self.pos is None or not target:
            return None
        want = norm_path(target)
        name = want.rsplit('/', 1)[-1]
        for pin in self.pins:
            start, end = pin[3]
            if pin[0] != want or not start <= self.pos < end:
                continue
            for stmt in re.split(r'[;\n]', self.masked[start:self.pos]):
                said = unmask(stmt, self.strings).replace('\\', '/').lower()
                if not stmt.strip() or (re.match(r'(?i)\s*Unblock-File\b', stmt) and name in said) or \
                        (re.match(r'(?i)\s*Write-(?:Host|Output|Verbose|Warning|Information)\b', stmt) and name not in said):
                    continue
                return None
            return pin
        return None

    def pinned_file(self, sha, name):
        """A file on this computer with that SHA-256: next to the script, in the current folder or in a --pin-dir.
        A file with the same name as the download is preferred."""
        dirs = [self.base, Path.cwd(), *self.pin_dirs]
        for d in dict.fromkeys(Path(x).resolve() for x in dirs):
            try:
                files = sorted((f for f in d.iterdir() if f.is_file()), key=lambda f: f.name.lower() != name.lower())
            except OSError:
                continue
            for f in files:
                if file_sha256(f) == sha:
                    return f
        return None

    def pinned_call(self, pin, raw, params, file, line, shown, splat_dynamic):
        """Run a downloaded script inside its hash pin: read the local file with that hash, or CANNOT TELL."""
        name = Path(raw.replace('\\', '/')).name
        match = self.pinned_file(pin[1], name)
        said = f'pinned to sha256 {pin[1]} on line {pin[2]}'
        if not match:
            return Finding(file, line, UNKNOWN, f'runs {name}, a download {said}; no file with that hash is on this computer to read',
                           command=shown, note='pass --pin-dir with the folder that holds a copy')
        out = self.script_call(str(match), params, file, line, shown, splat_dynamic)
        head = out[0] if isinstance(out, list) else out
        head.note = '; '.join(x for x in (said, head.note) if x)  # head.note already says read from <match>
        return out

    def runs_download(self, text):
        """True when text names a file this script saved from the internet earlier."""
        low = text.lower()
        return any(name and re.search(r'(?<![\w.-])' + re.escape(name) + r'(?![\w.-])', low) for name in self.downloads)

    @staticmethod
    def copy_target(params, positional, name='destination'):
        """Where Copy-Item, Move-Item or Expand-Archive writes, bound as PowerShell binds it: -Destination, else the
        first positional left once -Path is named, else the second positional."""
        if param(params, name):
            return param(params, name)
        taken = param(params, 'path') or param(params, 'literalpath')
        rest = positional if taken else positional[1:]
        return rest[0] if rest else None

    def inner_command(self, argtext, strings, params, file, line, shown):
        """powershell -Command <code...> or -EncodedCommand <base64>: the code it runs, checked as PowerShell and
        reported on this line, after a CANNOT TELL line for the call itself. PowerShell joins every argument after
        -Command (or every argument, when none names a parameter) into the command, so the code is rebuilt the
        same way. None, leaving the call CANNOT TELL, when any part is not a literal or a parameter is unclear."""
        toks = [t for t in split_args(argtext)]
        code, how = None, ''
        enc = param(params, 'encodedcommand')
        if any(re.match(r'(?i)^-e', t) for t in toks) and not enc:
            return None  # -e... that is not plainly -EncodedCommand: the checker will not guess
        if enc:
            if enc[1] != 'literal' or not enc[0]:
                return None
            try:
                import base64
                code, how = base64.b64decode(enc[0].strip(), validate=True).decode('utf-16-le'), 'decoded from -EncodedCommand'
            except (ValueError, UnicodeDecodeError):
                return None
        else:
            idx = next((i for i, t in enumerate(toks) if re.fullmatch(r'(?i)-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?', t)), None)
            if idx is not None:
                rest = toks[idx + 1:]
            elif toks and not toks[0].startswith('-'):
                rest = toks  # powershell 'Remove-Item ...': the arguments are the command
            else:
                rest = toks
                while rest and rest[0].startswith('-') and not re.match(r'(?i)^-(?:f|file)$', rest[0]):
                    rest = rest[2:] if len(rest) > 1 and not rest[1].startswith('-') and \
                        re.match(r'(?i)^-(?:ex|executionpolicy|wi|windowstyle|ver|version|config|outputformat|inputformat|wd|workingdirectory)', rest[0]) \
                        else rest[1:]
                if not rest or rest[0].startswith('-'):
                    return None
            parts = [literal(t, strings) for t in rest]
            if not parts or any(k != 'literal' or v is None for v, k in parts):
                return None
            code, how = ' '.join(v for v, _ in parts), 'inside powershell -Command'
        if code is None or self.depth >= 3:
            return None
        sub = Checker(self.policy, self.depth + 1, self.seen)
        sub.memo, sub.pin_dirs = self.memo, self.pin_dirs
        inner = [f for f in sub.check_text(code, file, self.base) if f.line]
        for f in inner:
            f.line, f.note = line, '; '.join(x for x in (f.note, f'runs {how}') if x)
        head = Finding(file, line, SUSPICIOUS if how.startswith('decoded') else UNKNOWN,
                       'starts PowerShell with code given on the command line; that code is checked below', command=shown,
                       target='local')
        return [head] + inner

    def add_download(self, value):
        """Remember a path this script saves something from the internet (or a share) to: its file or folder name."""
        if value and value[0]:
            name = Path(value[0].strip().strip('\'"').replace('\\', '/')).name.lower()
            if name and name not in ('.', '..'):
                self.downloads.add(name)

    def classify(self, raw, argtext, strings, splats, file, line, shown, masked_stmt):
        """One Finding for a command name and its argument text, or None for a harmless local cmdlet."""
        p = self.policy
        params, positional = params_of(argtext, strings, self.variables)
        # Splatted arguments: merge the literal hashtable in if there is one.
        for k, (v, kind) in list(params.items()):
            if kind == 'splat':
                del params[k]
        splat_dynamic = False
        for tok in split_args(argtext):
            if re.match(r'^@\w+$', tok):
                tbl = self.splat_at(tok[1:].lower())
                if tbl is None:
                    splat_dynamic = True
                else:
                    params.update(tbl)
        note = ''
        argraw = unmask(argtext, strings)
        # & "cmd" / & $cmd / . $cmd : the command is chosen at run time, unless $cmd is a literal in this file
        if (raw[0] == '&' or (raw[0] == '.' and raw[1:2].isspace())) and raw[1:].strip():
            target = literal(raw[1:].strip(), strings, self.variables)
            if target[1] != 'literal' and not (target[0] and target[0].strip().lower().endswith('.ps1')):
                if target[0] and self.runs_download(target[0]):
                    return Finding(file, line, SUSPICIOUS, f'runs {target[0]}, a file this script downloaded from the internet', command=shown)
                return Finding(file, line, UNKNOWN, 'runs a command chosen when the script runs', command=shown)
            raw = target[0].strip()  # "$HOME/x.ps1" names a script; its variables are filled in when it is looked for
        # A file path at a command position: a downloaded file, a script, or a program
        if PATH_LIKE.match(raw) and not raw.lower().endswith('.ps1'):
            if self.runs_download(raw):
                return Finding(file, line, SUSPICIOUS, f'runs {raw}, a file this script downloaded from the internet', command=shown)
            return Finding(file, line, UNKNOWN, f'runs the file {raw}, which the checker cannot read', command=shown, target='local')
        if raw.lower().endswith('.ps1') or (param(params, 'file') and str(param(params, 'file')[0]).lower().endswith('.ps1')):
            if self.runs_download(raw + ' ' + argraw):
                script = raw if raw.lower().endswith('.ps1') else str(param(params, 'file')[0])
                rest = argraw if script is raw else argraw.replace(script, '', 1)
                pin = None if self.runs_download(rest) else self.pin_for(script)
                if pin:
                    return self.pinned_call(pin, script, params, file, line, shown, splat_dynamic)
                return Finding(file, line, SUSPICIOUS, 'runs a script this script downloaded from the internet', command=shown)
            script = raw if raw.lower().endswith('.ps1') else str(param(params, 'file')[0])
            return self.script_call(script, params, file, line, shown, splat_dynamic)
        alias = p.aliases.get(raw.lower())
        if alias:
            note = f'alias for {alias}; write the full name in an audit script'
            raw = alias
        for _ in range(3):  # an alias the script defines, possibly for another alias
            mine = self.user_aliases.get(raw.lower())
            if not mine or mine[0].lower() == raw.lower():
                break
            if self.known_name(raw) and mine[0].lower() != (p.aliases.get(raw.lower()) or '').lower():
                # Set-Alias Remove-MgUser Get-Date may never run: judge the real command
                note = '; '.join(x for x in (note, f'line {mine[1]} may make this name an alias for {mine[0]}') if x)
                break
            note = '; '.join(x for x in (note, f'alias for {mine[0]}, defined on line {mine[1]} of this script') if x)
            raw = p.aliases.get(mine[0].lower(), mine[0])
        if '\\' in raw:  # Microsoft.Graph\Get-MgUser: module-qualified, same cmdlet
            raw = raw.rsplit('\\', 1)[1]
        low = raw.lower()
        if low in self.functions and not note:
            if not self.known_name(raw):
                return None  # a function defined in this script: what it does is reported from its body, whatever its name says
            note = 'a function of this name is also defined in this script; this may run it or the real command'
        if low == 'using':  # using module X loads and runs X; using namespace and using assembly X name types
            kind = re.match(r'(?i)\s*(module|namespace|assembly)\b\s*(.*)', argraw)
            if not kind or kind.group(1).lower() == 'namespace':
                return None
            target = kind.group(2).strip().strip('\'"')
            if kind.group(1).lower() == 'module' and re.search(r'(?i)\.psm1$', target):
                return self.script_call(target, params, file, line, shown, splat_dynamic)
            if kind.group(1).lower() == 'assembly' and not re.search(r'[\\/]|\.dll\b', target):
                return Finding(file, line, READ, f'loads the .NET assembly {target} by name', command=shown, target='local')
            return Finding(file, line, UNKNOWN, 'loads code from a file the checker did not read; check that file too', command=shown, note=note)
        known = self.known_script(raw, params, file, line, shown, unsure=splat_dynamic)
        if known:
            return known
        # Native programs: a few are judged by their first argument (vssadmin delete, wevtutil cl)
        if re.fullmatch(r'(?i)(?:powershell|pwsh)(?:\.exe)?', raw):
            inner = self.inner_command(argtext, strings, params, file, line, shown)
            if inner:
                return inner
        if (low in CODE_CARRIERS or low in p.native or low.endswith('.exe')) and self.writes_code(argtext, strings):
            return Finding(file, line, SUSPICIOUS, f'{raw} is handed PowerShell code or an encoded command to run', command=shown,
                           note=note, security='the code it runs is hidden from a reading of this line')
        for lvl, exe, args, what, sec in p.native_rules:
            if exe.search(low) and args.search(argraw):
                return Finding(file, line, lvl, what, command=shown, security=sec, note=note, target='local')
        if low in p.native or low.endswith('.exe'):
            lvl = p.native.get(low, UNKNOWN)
            if self.runs_download(argraw):
                return Finding(file, line, SUSPICIOUS, f'runs {raw} on a file this script downloaded from the internet', command=shown, note=note)
            return Finding(file, line, lvl, f'runs {raw}, a program outside PowerShell the checker cannot read', command=shown, note=note, target='local')
        vn = VERB_NOUN.match(raw)
        if not vn:
            if low in KEYWORDS:
                return None
            if re.fullmatch(r'[\w.-]+', raw):
                return Finding(file, line, UNKNOWN, f'runs {raw}, which is not a cmdlet the checker knows', command=shown, note=note)
            return Finding(file, line, UNKNOWN, f'runs {raw}, which is not a name the checker can read', command=shown, note=note)
        verb, noun = vn.group(1), vn.group(2)
        stmt_raw = unmask(masked_stmt, strings)
        if ((verb.lower() == 'get' and noun.lower().endswith('content') and p.scope_of(noun))  # Get-MgDriveItemContent -OutFile
                or (low in ('expand-archive', 'copy-item', 'move-item') and self.runs_download(argraw))
                or (low in ('out-file', 'set-content', 'add-content')
                    and re.search(r'(?i)Invoke-(?:WebRequest|RestMethod)|\b(?:iwr|irm|curl|wget)\b|Download(?:String|Data)', stmt_raw))):
            if low in ('copy-item', 'move-item', 'expand-archive'):
                self.add_download(self.copy_target(params, positional, 'destinationpath' if low == 'expand-archive' else 'destination'))
            else:
                named = next((param(params, k) for k in ('outfile', 'outputfilepath', 'filepath', 'path', 'literalpath')
                              if param(params, k)), None)
                self.add_download(named or (positional[0] if positional and low in ('out-file', 'set-content', 'add-content') else None))
        security = ''
        named = ' '.join('-' + k for k in params)  # parameters from a literal splat table are not in argraw
        for pat, what in p.security:
            if pat.search(raw) or pat.search(raw + ' ' + argraw + ' ' + named):
                security = what
                break
        # Raw HTTP: classified by the literal method and where it goes. Start-BitsTransfer is a GET with -Destination.
        if low in HTTP_CMDLETS or low == 'start-bitstransfer':
            f = self.http(low, params, positional, file, line, shown, splat_dynamic)
            f.security = f.security or security
            f.note = '; '.join(x for x in (f.note, note) if x)
            f.target = 'tenant' if f.level < SUSPICIOUS else ''
            return f
        if low in ('invoke-pnpsprestmethod', 'invoke-pnpgraphmethod'):  # PnP's own REST calls: the connected site or Graph, by -Method
            method = param(params, 'method') or ('GET', 'literal')
            if method[1] != 'literal' or not method[0]:
                return Finding(file, line, UNKNOWN, f'{raw}: the HTTP method is decided when the script runs', command=shown, note=note, target='tenant')
            lvl = METHOD_LEVEL.get(method[0].lower(), UNKNOWN)
            what = {READ: 'reads', CHANGES: 'changes something', DESTRUCTIVE: 'deletes something', UNKNOWN: 'calls'}[lvl]
            where = 'Microsoft Graph' if low == 'invoke-pnpgraphmethod' else 'SharePoint Online'
            return Finding(file, line, lvl, f'{what} via HTTP {method[0].upper()} in {where}: {raw}', command=shown,
                           security=security, note=note, target='tenant')
        if low == 'import-module' and (re.search(r'[\\/]|\.(?:psm1|psd1|dll)\b', argraw)
                                                  or SCRIPT_PATH.search(self.target_text(argtext, params, positional, 'name'))):
            module = self.target_text(argtext, params, positional, 'name')
            if not module:  # an unquoted $PSScriptRoot\x.psm1 is one token that literal() calls dynamic
                m = re.match(r'\s*(?:-Name\s+)?(\S+\.psm1)\b', argraw, re.I)
                module = m.group(1) if m else ''
            if re.search(r'(?i)\.psm1$', module):
                return self.script_call(module, params, file, line, shown, splat_dynamic)  # a .psm1 reads like a .ps1
            return Finding(file, line, UNKNOWN, 'loads code from a file the checker did not read; check that file too', command=shown, note=note)
        if low in ('set-alias', 'new-alias') or (
                low in ('set-item', 'new-item', 'copy-item', 'rename-item', 'set-content', 'remove-item')
                and re.search(r'(?i)(?:^|[\s\'"])(?:alias|function):', argraw)):
            return self.alias_finding(raw, low, params, positional, argtext, argraw, strings, file, line, shown, note)
        if low == 'add-type':
            name_v = param(params, 'assemblyname')
            if (name_v and name_v[1] == 'literal' and not re.search(r'[\\/]|\.dll\b', name_v[0])
                    and not any(param(params, k) for k in ('typedefinition', 'memberdefinition', 'path', 'literalpath'))):
                return Finding(file, line, READ, f'loads the .NET assembly {name_v[0]} by name', command=shown, note=note, target='local')
        # Where a local write goes decides what it means: an alias drive, a Run key, the hosts file, a share.
        if low in ('new-psdrive', 'ndr', 'mount'):
            root = param(params, 'root') or (positional[2] if len(positional) > 2 else None)
            drive = param(params, 'name') or (positional[0] if positional else None)
            if root and root[0] and re.match(r'^\s*(?:\\\\|//|https?:)', root[0]) and drive and drive[0]:
                self.remote_drives[drive[0].strip().rstrip(':').lower()] = line
                return Finding(file, line, UNKNOWN, f'maps drive {drive[0]}: to {root[0]}, on another computer', command=shown,
                               note='anything written to that drive later leaves this computer', target='local')
        if low in ('resolve-dnsname', 'test-netconnection', 'test-connection', 'nslookup', 'ping', 'ping.exe', 'nslookup.exe'):
            name_v = param(params, 'name') or param(params, 'computername') or param(params, 'targetname') or \
                (positional[0] if positional else None)
            if name_v and name_v[1] == 'dynamic' and name_v[0] and '$' in name_v[0] and \
                    re.search(r'\.[a-z0-9-]+\.[a-z]{2,}\s*$', name_v[0], re.I) and \
                    self.policy.host_kind(re.sub(r'^.*?\$\S*?\.', '', name_v[0])) != 'microsoft':
                return Finding(file, line, UNKNOWN, f'looks up a name built when the script runs: {name_v[0]}', command=shown,
                               note='data put into a DNS name reaches whoever runs that domain', security='a DNS lookup can carry data out')
        copying = low in ('copy-item', 'move-item')
        if self.remote_drives and low in ('copy-item', 'move-item', 'out-file', 'set-content', 'add-content', 'export-csv',
                                          'export-clixml', 'new-item', 'start-bitstransfer'):
            hit = next((d for d in self.remote_drives if re.search(r'(?i)(?<![\w])' + re.escape(d) + r':[\\/]?', argraw)), None)
            if hit:
                return Finding(file, line, UNKNOWN, f'writes to drive {hit}:, which line {self.remote_drives[hit]} maps to another computer',
                               command=shown, note=note, security='collected data can leave this way')
        dest = self.copy_target(params, positional) if copying else None
        where_to = dest[0] if dest and dest[1] == 'literal' and dest[0] else argraw  # unread destination: judge it all
        for lvl, cmd, pat, what, sec in p.path_rules:
            if cmd.search(raw) and pat.search(where_to if copying else argraw):
                if self.writes_code(argtext, strings):
                    lvl, what = SUSPICIOUS, what + ', and the text it writes looks like PowerShell code'
                lvl, note = whatif(lvl, params, note)
                return Finding(file, line, lvl, what, command=shown, security=security or sec, note=note,
                               target='' if lvl in (UNKNOWN, SUSPICIOUS) else 'local')
        source = (param(params, 'path') or param(params, 'literalpath') or (positional[0] if positional else None)) if copying else None
        if source and source[0] and re.match(r'^\s*[\'"]?(?:\\\\|//)[\w.${}:()-]+', source[0]):
            self.add_download(dest)
            return Finding(file, line, UNKNOWN, 'copies a file from a network share; the checker cannot read what it is',
                           command=shown, note=note, target='local')
        # Cmdlet-specific overrides (Search-Mailbox -DeleteContent, Connect-*, ...)
        for lvl, pat, need, what, sec, undo, docs in p.overrides:
            if pat.search(raw) and (not need or param(params, need[1:]) is not None):
                f = Finding(file, line, lvl, what, command=shown, security=security or sec, note=note, undo=undo, docs=docs, target='tenant')
                if low.startswith('connect-'):
                    self.connect_notes(f, params, splat_dynamic)
                return f
        # Local-machine rules
        for lvl, pat, need, what, sec in p.local_rules:
            if pat.search(raw) and (not need or param(params, need[1:]) is not None):
                if low == 'invoke-expression':
                    what = self.iex_what(masked_stmt, strings, what)
                    if what.startswith('runs the script file'):
                        lvl = UNKNOWN
                if low == 'remove-item' and lvl < DESTRUCTIVE and re.search(r'(?i)\b(?:Get-ChildItem|gci|ls|dir)\b[^|]*-Rec', unmask(masked_stmt, strings)):
                    lvl, what = DESTRUCTIVE, 'deletes a local folder tree (everything the Get-ChildItem -Recurse before it finds)'
                if low == 'unblock-file' and self.runs_download(argraw) and \
                        (pin := self.pin_for(self.target_text(argtext, params, positional, 'path'))):
                    what, sec = f'removes the downloaded-file warning from a file pinned to sha256 {pin[1]} on line {pin[2]}', ''
                elif low in ('invoke-item', 'start-process', 'unblock-file') and self.runs_download(argraw):
                    lvl, what = SUSPICIOUS, f'{raw} on a file this script downloaded from the internet'
                elif low in ('invoke-item', 'ii') and REPORT_FILE.search(self.target_text(argtext, params, positional, 'path')):
                    lvl, what = READ, 'opens a report file with its default program'
                elif low in ('start-process', 'saps', 'start') and self.restarts_itself(argtext, argraw, params, positional):
                    lvl, what = READ, 'starts this same script again as Administrator'
                    sec = 'everything in it runs with full rights over this computer'
                elif low in ('invoke-command', 'icm', 'start-job', 'sajb', 'start-threadjob') and not param(params, 'filepath') \
                        and re.search(r'(?i)(?:^\s*|-s\w*\s+)\{', argtext):
                    on = param(params, 'computername') or param(params, 'session')
                    lvl, what = READ, (f'runs the block in {{ }} on {on[0] or "another computer"}' if on else 'runs the block in { } as a job') \
                        + '; the commands inside it are checked on their own lines'
                    sec = 'runs commands on another computer with your credentials' if on else sec
                lvl, note = whatif(lvl, params, note)
                return Finding(file, line, lvl, what, command=shown, security=security or sec, note=note,
                               target='' if lvl in (UNKNOWN, SUSPICIOUS) else 'local')
        if low == 'new-object':
            kind = param(params, 'comobject')
            tname = kind or param(params, 'typename') or (positional[0] if positional else None)
            if tname and tname[1] == 'literal' and tname[0] and '\x00' in argtext:  # quoted: the .NET rules only see unquoted names
                probe = f'-ComObject {tname[0]}' if kind else f'New-Object {tname[0]}'
                for lvl, pat, what in p.dotnet_rules:
                    if pat.search(probe):
                        return Finding(file, line, lvl, what, command=shown, note=note)
            elif tname and tname[1] != 'literal':
                return Finding(file, line, UNKNOWN, 'creates a .NET or COM object whose type is decided when the script runs',
                               command=shown, note=note)
        if low in p.write_cmdlets and self.writes_code(argtext, strings):
            return Finding(file, line, SUSPICIOUS, f'{raw} writes text that looks like PowerShell code to a file or registry key', command=shown, note=note)
        if low in p.local_harmless:
            return Finding(file, line, READ, f'{raw}: local, changes nothing in the tenant', command=shown, security=security, note=note, target='local') if (security or note) else None
        scope = p.scope_of(noun)
        lvl = p.verb_level.get(verb.lower())
        if lvl is None:
            return Finding(file, line, UNKNOWN, f'{raw}: {verb} is not a standard PowerShell verb, so the checker cannot tell what it does', command=shown, security=security, note=note)
        where = f'in {scope}' if scope else 'somewhere the checker does not know'
        what = {READ: f'reads {where}', CHANGES: f'changes something {where}', DESTRUCTIVE: f'deletes or clears something {where}'}[lvl] + f': {raw}'
        if not scope:
            note = '; '.join(x for x in (note, 'not a cmdlet the checker knows; the level comes from its verb only') if x)
            if lvl == READ:  # a Get- name proves nothing: Get-WindowsAutopilotInfo -Online writes to the tenant
                lvl = UNKNOWN
                what = f'{raw}: not a cmdlet the checker knows, so its {verb} verb is not proof that it only reads'
        if splat_dynamic:
            lvl = max(lvl, UNKNOWN)
            note = '; '.join(x for x in (note, 'its arguments are splatted from a table the checker could not read') if x)
        lvl, note = whatif(lvl, params, note)
        if lvl > READ and re.search(r'(?i)-Confirm:\$false', argraw):
            note = '; '.join(x for x in (note, 'has -Confirm:$false, so it will not ask before doing it') if x)
        for pat, names, text in p.param_notes:
            if pat.search(raw) and any(param(params, n[1:]) is not None for n in names):
                note = '; '.join(x for x in (note, text) if x)
        undo = docs = ''
        if lvl == DESTRUCTIVE:
            for pat, text, link in p.undo:
                if pat.search(raw):
                    undo, docs = text, link
                    break
            if any(param(params, k) is not None for k in ('removefromrecyclebin', 'permanentlydelete', 'permanent')):
                undo, docs = 'none: this skips the recycle bin, so it cannot be restored', ''
        return Finding(file, line, lvl, what, command=shown, security=security, note=note, undo=undo, docs=docs,
                       target='tenant' if scope else '')  # a write to an unknown noun may be local (Set-TimeZone)

    @staticmethod
    def mark_tenant_guard(text, findings):
        """Turn "no tenant named" on a sign-in into "tenant guarded" when a later line compares the session's
        TenantId with a literal tenant id and stops (throw, exit, return, break, or an else that holds the work)
        before the first change. The house guard checks every Connected row of Get-ConnectionInformation, or
        (Get-MgContext).TenantId, after a Connect-* that names no tenant."""
        lines = text.splitlines()
        guid = r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}'
        for i, ln in enumerate(lines):
            if not (re.search(r'(?i)TenantI[dD]\b', ln) and re.search(r'(?i)-c?(?:ne|eq|notin|in|notmatch|match)\b', ln)):
                continue
            m = re.search(guid, ln)
            stops = re.search(r'(?i)\b(?:throw|exit|return|break)\b|\belse\b', ' '.join(lines[i:i + 4]))
            if not (m and stops):
                continue
            line = i + 1
            first = min((f.line for f in findings if f.level in (CHANGES, DESTRUCTIVE) and f.target == 'tenant'), default=None)
            for f in findings:
                if 'no tenant named' in f.note and f.line <= line:
                    said = (f'tenant guarded: line {line} stops unless the session is on {m.group(0)}' if first is None or line <= first
                            else f'no tenant named, and the tenant check on line {line} comes after the first change on line {first}')
                    f.note = f.note.replace('no tenant named: it signs in to whichever tenant the account defaults to', said)
            return

    def known_script(self, name, params, file, line, shown, how='', unsure=False):
        """The verbs/policy.json known_scripts row for a community script run by name or path, or None.

        unsure (a file judged only by its name, or arguments in a splat the checker could not read) never
        reads milder than CANNOT TELL: anyone can name a script Get-WindowsAutopilotInfo.ps1.
        """
        for lvl, pat, need, what, sec, undo, target in self.policy.known_scripts:
            if pat.search(name) and (not need or param(params, need[1:]) is not None):
                return Finding(file, line, max(lvl, UNKNOWN) if unsure else lvl, what, command=shown, security=sec,
                               undo=undo, note=how, target='' if unsure and lvl == READ else target)  # unread: either side
        return None

    def script_call(self, script, params, file, line, shown, splat_dynamic=False):
        """A .ps1 this script runs: that file's own findings when it is on this computer, else what the policy
        knows about a script of that name (never milder than CANNOT TELL), else CANNOT TELL."""
        name = Path(script.replace('\\', '/')).name
        unc = script.strip().startswith(('\\\\', '//'))  # never stat a share: on Windows that opens an SMB connection
        path = None if unc else expand_script_path(script, self.base)
        if path is None or not path.is_file():
            known = self.known_script(name[:-4], params, file, line, shown,
                                      'judged by the script name; the file is not on this computer to read', unsure=True)
            kind = 'module' if name.lower().endswith('.psm1') else 'script'
            return known or Finding(file, line, UNKNOWN, f'runs the {kind} {name}, which the checker cannot find or read here',
                                    command=shown, note='check that file with m365check where it is')
        st = path.stat()
        key = (st.st_dev, st.st_ino)  # the file itself, so .\A.PSM1 and .\a.psm1 on a case-insensitive disk are one
        if key in self.seen or self.depth >= 3:
            return Finding(file, line, UNKNOWN, f'runs {name} from inside a script it called; the checker stops following here',
                           command=shown)
        if key in self.memo:
            return Finding(file, line, self.memo[key], f'runs {name} again; its commands are listed once, under {name}',
                           command=shown)
        sub = Checker(self.policy, self.depth + 1, self.seen | {key})
        sub.memo, sub.pin_dirs = self.memo, self.pin_dirs
        try:
            inner = sub.check_file(path)
        except Exception as e:  # a checker bug in the called file must read as CANNOT TELL, never as nothing
            inner = [Finding(str(path), 0, UNKNOWN, f'm365check could not read this script ({type(e).__name__}: {e})')]
        self.memo[key] = verdict(inner)
        return [Finding(file, line, READ, f'runs the script {name}; its commands are listed under {name}',
                        command=shown, note=f'read from {path}', target='local')] + inner

    def writes_code(self, argtext, strings):
        """True when a string literal among the arguments looks like PowerShell code (iex, irm, -enc, powershell -...)."""
        return any(self.policy.code_in_text.search(strings[int(m.group(1))]) for m in PLACEHOLDER.finditer(argtext))

    def http(self, low, params, positional, file, line, shown, splat_dynamic):
        """Invoke-MgGraphRequest / Invoke-RestMethod / Invoke-WebRequest by literal -Method and -Uri.

        The host is read even from a double-quoted URI whose path holds a variable
        ("https://graph.microsoft.com/v1.0/users/$id"), as long as the host part is literal.
        """
        bits = low == 'start-bitstransfer'
        method = None if bits else (param(params, 'method') or param(params, 'custommethod') or param(params, 'httpmethod'))
        uri = param(params, 'source') if bits else (param(params, 'uri') or param(params, 'url') or (positional[0] if positional else None))
        if low == 'invoke-azrestmethod' and not param(params, 'uri') and param(params, 'path'):
            uri = ('https://management.azure.com' + (param(params, 'path')[0] or ''), param(params, 'path')[1])  # -Path is always ARM
        body = None if bits else (param(params, 'body') or param(params, 'infile') or param(params, 'form') or param(params, 'content'))
        if bits and re.match(r'(?i)upload', (param(params, 'transfertype') or ('',))[0] or ''):
            uri, body, method = param(params, 'destination'), param(params, 'source') or ('', 'literal'), ('POST', 'literal')
            bits = False  # an upload sends -Source to -Destination
        outfile = param(params, 'destination') if bits else (param(params, 'outfile') or param(params, 'outputfilepath'))
        graph = low in ('invoke-mggraphrequest', 'invoke-msgraphrequest')
        host, userinfo = '', False
        if uri and uri[0]:
            parsed, userinfo = url_host(uri[0])
            # Invoke-MgGraphRequest resolves 'v1.0/...' against Graph; the web cmdlets would prepend http:// and call a host v1.0
            if parsed and not (graph and re.match(r'(?i)^\s*/?(?:v1\.0|beta)(?:[/?]|$)', uri[0])):
                host = parsed
        absolute = bool(uri and uri[0] and uri[0].lstrip().lower().startswith('http'))
        if graph and not host and not absolute:
            host = 'graph.microsoft.com'
        if absolute and not host and uri[1] == 'literal':
            return Finding(file, line, UNKNOWN, f'{low}: the checker could not read the host in this address', command=shown,
                           note='an address it cannot read could send the request anywhere')
        if userinfo:
            shown_note = f'the address hides its real host behind a user name: the request goes to {host}'
            return self._with_note(self.http_to(low, params, file, line, shown, splat_dynamic, method, body, outfile, graph, host, uri),
                                   shown_note)
        return self.http_to(low, params, file, line, shown, splat_dynamic, method, body, outfile, graph, host, uri)

    @staticmethod
    def _with_note(f, note):
        """f with note added in front of its own."""
        f.note = '; '.join(x for x in (note, f.note) if x)
        return f

    def http_to(self, low, params, file, line, shown, splat_dynamic, method, body, outfile, graph, host, uri):
        """The finding for an HTTP call once its host is known ('' when the address is decided at run time)."""
        if method is None:
            m_text, m_kind = 'GET', 'literal'
        else:
            m_text, m_kind = method
        if splat_dynamic:
            return Finding(file, line, UNKNOWN, f'{low}: its arguments are splatted from a table the checker could not read', command=shown)
        if m_kind != 'literal' or not m_text:
            return Finding(file, line, UNKNOWN, f'{low}: the HTTP method is decided when the script runs', command=shown)
        lvl = METHOD_LEVEL.get(m_text.lower(), CHANGES if param(params, 'custommethod') else UNKNOWN)
        saved = ''
        if outfile and outfile[0]:
            saved = outfile[0]
            self.add_download(outfile)
        save_note = f'saves the download as {saved}' if saved else ''
        kind = self.policy.host_kind(host) if host else ''
        if host and kind != 'microsoft':
            if lvl > READ or body:
                if kind == 'tenant':
                    what = {CHANGES: 'changes something', DESTRUCTIVE: 'deletes something', UNKNOWN: 'calls', READ: 'sends data'}[lvl]
                    return Finding(file, line, max(lvl, CHANGES), f'{what} via HTTP {m_text.upper()} at {host}', command=shown,
                                   note='any Microsoft 365 tenant can own an address like this; if it is not yours, tenant data is being sent to someone else')
                why = {'code': 'a code-hosting site, not somewhere a Microsoft 365 script needs to post to',
                       'sink': 'an address anyone can create in their own tenant to receive data (a webhook, Logic App, storage or web app)'
                       }.get(kind, 'which is not Microsoft')
                return Finding(file, line, SUSPICIOUS, f'sends data to {host}, {why}', command=shown,
                               note='tenant data collected earlier in the script can leave this way')
            if kind == 'tenant':
                return Finding(file, line, READ, f'reads via HTTP GET at {host}', command=shown, note=save_note)
            if kind != 'code' and uri and uri[1] == 'dynamic' and re.search(r'[/?#][^\s]*\$', uri[0] or ''):
                return Finding(file, line, SUSPICIOUS, f'sends data to {host} in the address it asks for', command=shown,
                               note='a value built when the script runs is put into the address; tenant data can leave this way')
            pin = next((p for p in self.pins if saved and p[0] == norm_path(saved) and self.pos is not None
                        and self.pos < p[3][0]), None)
            match = pin and self.pinned_file(pin[1], Path(saved.replace('\\', '/')).name)
            if match:
                return Finding(file, line, READ, f'downloads from {host} a file pinned to sha256 {pin[1]} on line {pin[2]}',
                               command=shown, note=f'{save_note}; the same file is on this computer at {match}')
            return Finding(file, line, UNKNOWN, f'downloads from {host}; what happens to the download depends on the script', command=shown, note=save_note)
        if not host and not graph:
            if lvl > READ or body:
                return Finding(file, line, UNKNOWN, f'{m_text.upper()} to a host decided when the script runs', command=shown,
                               note='could send tenant data anywhere; read where $uri comes from')
            return Finding(file, line, UNKNOWN, 'GET from a host decided when the script runs', command=shown, note=save_note)
        if uri and uri[0] and re.search(r'/`?\$batch\b', uri[0]) and lvl > READ:
            # a Graph $batch is one POST carrying up to 20 requests; what it does is their methods
            inner = batch_methods(body[0] if body and body[1] == 'literal' else None)
            if not inner:
                return Finding(file, line, UNKNOWN, f'sends a Graph $batch to {host} whose requests the checker cannot read',
                               command=shown, note='a $batch can carry deletes as well as reads')
            lvl = max(METHOD_LEVEL[m.lower()] for m in inner)
            what = {READ: 'reads', CHANGES: 'changes something', DESTRUCTIVE: 'deletes something'}[lvl]
            return Finding(file, line, lvl, f'{what} via a Graph $batch ({", ".join(sorted(inner))}) at {host}', command=shown)
        what = {READ: 'reads', CHANGES: 'changes something', DESTRUCTIVE: 'deletes something', UNKNOWN: 'calls'}[lvl]
        return Finding(file, line, lvl, f'{what} via HTTP {m_text.upper()} at {host}', command=shown, note=save_note)

    def connect_notes(self, f, params, splat_dynamic):
        """Connect-MgGraph -Scopes: say which scopes are write scopes; Connect-* -TenantId: say which tenant."""
        scopes = param(params, 'scopes')
        if scopes and scopes[1] == 'literal' and scopes[0]:
            names = [s for s in re.findall(r"[\w./-]+", scopes[0]) if re.search(r'[A-Za-z]', s)]
            writes = [s for s in names if write_scope(s)]
            if any(s.lower().endswith('.default') for s in names):
                f.security = 'asks for .default: every permission this app was ever granted, which the checker cannot see'
            elif writes:
                f.security = f'asks for permissions that are not read-only: {", ".join(writes)}'
            else:
                f.note = '; '.join(x for x in (f.note, f'read-only scopes: {", ".join(names)}') if x)
        elif scopes or splat_dynamic:
            f.note = '; '.join(x for x in (f.note, 'the permission scopes are decided when the script runs') if x)
        app_only = [k for k in ('clientsecretcredential', 'certificatethumbprint', 'certificate', 'certificatename',
                                'accesstoken', 'identity') if param(params, k) is not None]
        if not scopes and app_only:
            f.security = '; '.join(x for x in (f.security, 'signs in as an app (no -Scopes): it holds every permission '
                                               'the app was granted, which the checker cannot see') if x)
        if param(params, 'delegatedorganization') is not None:
            f.security = f.security or 'signs in to another organisation\'s tenant as its partner (delegated access)'
            return
        tenant = param(params, 'tenantid') or param(params, 'organization') or param(params, 'tenant') or param(params, 'url')
        if tenant is None:
            f.note = '; '.join(x for x in (f.note, 'no tenant named: it signs in to whichever tenant the account defaults to') if x)

    @staticmethod
    def iex_what(masked_stmt, strings, default):
        """Invoke-Expression fed by a download is 'runs downloaded code'; fed by Get-Content of a .ps1 is 'runs that file'."""
        stmt = unmask(masked_stmt, strings)
        if re.search(r'(?i)Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|DownloadString|WebClient|HttpClient', stmt):
            return 'runs code downloaded from the internet'
        m = re.search(r'(?i)Get-Content\s+(?:-Path\s+)?[\'"]?(\S+?\.ps1)', stmt)
        if m:
            return f'runs the script file {m.group(1)}; check that file with m365check'
        return default


# ---------------------------------------------------------------- output --

def verdict(findings):
    """The worst level among the findings."""
    return max((f.level for f in findings), default=UNKNOWN)


DOTS = ['\U0001F7E2', '\U0001F7E0', '⚪', '\U0001F534', '\U0001F534']


def can_print_dots(stream):
    """True when the stream can encode the level dots (a legacy Windows console cannot)."""
    try:
        ''.join(DOTS).encode(stream.encoding or 'ascii')
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def render(path, findings, policy, quiet=False, dots=False):
    """Plain-text report, the same layout as gamcheck's."""
    v = verdict(findings)
    dot = (lambda lvl: DOTS[lvl] + ' ') if dots else (lambda lvl: '')
    pad = '   ' if dots else ''
    counts = {name: sum(1 for f in findings if f.level == lvl) for lvl, name in enumerate(LEVEL_NAMES)}
    sec = sum(1 for f in findings if f.security)
    out = [f'm365check {__version__}: {path}', f'Checked against policy {policy.version}', '',
           f'VERDICT: {dot(v)}{LEVEL_NAMES[v]}',
           '  ' + ', '.join(f'{n} {k.lower()}' for k, n in counts.items() if n)
           + (f'; {sec} security-sensitive' if sec else ''), '']
    tenant = max((f.level for f in findings if f.target == 'tenant'), default=READ)
    local = max((f.level for f in findings if f.target == 'local'), default=READ)
    unsure = [f for f in findings if not f.target]
    if v > READ:
        out.insert(-1, f'  Tenant: {LEVEL_NAMES[tenant]}. This computer: {LEVEL_NAMES[local]}.'
                   + (f' Could be either: {LEVEL_NAMES[max(f.level for f in unsure)]}.' if unsure else ''))
    writes = sum(1 for f in findings if f.level in (CHANGES, DESTRUCTIVE))
    if writes > 1:  # a run that stops at change 11 leaves changes 1 to 10 in place
        out.insert(-1, f'  Not all-or-nothing: {writes} changes run one after another, and if a later one fails, '
                       'the ones before it have already happened.')
    for f in sorted(findings, key=lambda x: (x.file != str(path), x.file, x.line)):  # a called script's lines after the caller's
        if quiet and f.level == READ and not f.security:
            continue
        where = f'L{f.line}' if f.file == str(path) else f'{Path(f.file).name}:L{f.line}'
        out.append(f'  {where:<8} {dot(f.level)}{LEVEL_NAMES[f.level]:<12} {f.what}')
        if f.security:
            out.append(f'  {"":<8} {pad}{"SECURITY":<12} {f.security}')
        if f.note:
            out.append(f'  {"":<8} {pad}{"":<12} ({f.note})')
        if f.undo:
            out.append(f'  {"":<8} {pad}{"UNDO":<12} {f.undo}')
        if f.command:
            out.append(f'  {"":<8} {pad}{"":<12} > {f.command}')
        if f.docs and f.level > READ:
            out.append(f'  {"":<8} {pad}{"":<12} docs: {f.docs}')
    out += ['', 'This is a reading of the script text, not a guarantee. Values chosen at runtime show as CANNOT TELL.']
    return '\n'.join(out)


PROMPT_PREFIX = re.compile(r'^[ \t]*(?:PS [^>\n]*>+|PS>+|>+)[ \t]*', re.M)
STRAIGHTEN = str.maketrans({'“': '"', '”': '"', '„': '"', '‘': "'", '’': "'"})


def decode_candidates(data):
    """The readings of script bytes: UTF-16 by its byte-order mark (ISE and older editors save that way), or
    UTF-8; bytes that are not valid UTF-8 give two readings, UTF-8 with replacements and Windows-1252 (the ANSI
    code page an old .ps1 is usually in). Universal newlines, as read_text gives."""
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        texts = [data.decode('utf-16', errors='replace')]
    else:
        try:
            texts = [data.decode('utf-8-sig')]
        except UnicodeDecodeError:
            texts = [data.decode('utf-8-sig', errors='replace'), data.decode('cp1252', errors='replace')]
    return [t.replace('\r\n', '\n').replace('\r', '\n') for t in texts]


def read_paste():
    """Read pasted commands from the terminal until an empty line, or all of a pipe."""
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()  # bytes: check_bytes decides the encoding
    try:
        import readline  # noqa: F401  (macOS truncates a terminal line at 1024 bytes without it)
    except ImportError:
        pass
    print('Paste the PowerShell command(s) or the whole script, then press Enter on an empty line.', file=sys.stderr)
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            if not lines:
                continue
            if more_pending():  # a blank line inside a paste: the rest of the paste is already waiting
                lines.append('')
                continue
            break
        lines.append(line)
    return '\n'.join(lines) + '\n'


def more_pending():
    """True when more pasted input is already waiting on the terminal (a paste arrives all at once)."""
    try:
        if sys.platform == 'win32':
            import msvcrt
            return msvcrt.kbhit()
        import select
        return bool(select.select([sys.stdin], [], [], 0.3)[0])
    except Exception:
        return False


def main(argv=None):
    """Check each script named on the command line; exit with the worst verdict."""
    if sys.version_info < (3, 9):
        print('m365check needs Python 3.9 or newer', file=sys.stderr)
        return UNKNOWN
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(errors='replace')
    ap = argparse.ArgumentParser(description='Report what a Microsoft 365 PowerShell script would do, without running it.')
    ap.add_argument('scripts', nargs='*', help='script files to check; none, or --paste, asks you to paste; - reads a pipe')
    ap.add_argument('--paste', action='store_true', help='ask for commands to paste in')
    ap.add_argument('--json', action='store_true', help='machine-readable output')
    ap.add_argument('--quiet', action='store_true', help='hide read-only lines')
    ap.add_argument('--pin-dir', action='append', default=[], metavar='DIR',
                    help='a folder holding a copy of a download the script pins by SHA-256 (repeatable)')
    opts = ap.parse_args(argv)
    try:
        checker = Checker()
    except Exception as e:  # a broken or missing policy file must not exit 1, which reads as CHANGES
        print(f'm365check: could not load {POLICY_FILE} ({type(e).__name__}: {e})', file=sys.stderr)
        return UNKNOWN
    checker.pin_dirs = opts.pin_dir
    worst, reports = READ, []
    if opts.paste or not opts.scripts:
        opts.scripts = ['-'] + [s for s in opts.scripts if s != '-']
    for s in opts.scripts:
        if s == '-':
            text = read_paste()
            readings = decode_candidates(text) if isinstance(text, bytes) else [text]
            text = readings[0]
            if not text.strip():
                print('m365check: nothing was pasted', file=sys.stderr)
                worst = max(worst, UNKNOWN)
                continue
            s = '<pasted>'
            curly = text.translate(STRAIGHTEN) != text
            try:
                findings = checker.check_readings([PROMPT_PREFIX.sub('', t.translate(STRAIGHTEN)) for t in readings], s)
            except Exception as e:  # a checker bug must read as CANNOT TELL, never as a mild exit code
                findings = [Finding(s, 0, UNKNOWN, f'm365check could not read this paste ({type(e).__name__}: {e})',
                                    note='report this at the repository; the verdict is not a reading of the script')]
            print(f'Read {len(text.splitlines())} line(s).', file=sys.stderr)
            if curly:
                findings.append(Finding(s, 0, UNKNOWN, 'the paste contains curly quotes',
                                        note='web pages turn " into curly quotes; PowerShell accepts them but they hide what is a string'))
        elif not Path(s).is_file():
            print(f'm365check: {s}: file not found', file=sys.stderr)
            worst = max(worst, UNKNOWN)
            continue
        else:
            try:
                findings = checker.check_file(Path(s))
            except Exception as e:  # a checker bug must read as CANNOT TELL, never as a mild exit code
                findings = [Finding(s, 0, UNKNOWN, f'm365check could not read this script ({type(e).__name__}: {e})',
                                    note='report this at the repository; the verdict is not a reading of the script')]
        worst = max(worst, verdict(findings))
        if opts.json:
            reports.append({'file': s, 'policy': checker.policy.version, 'verdict': LEVEL_NAMES[verdict(findings)],
                            'findings': [f.as_dict() for f in findings]})
        else:
            print(render(s, findings, checker.policy, opts.quiet, can_print_dots(sys.stdout)))
            print()
    if opts.json:
        print(json.dumps(reports, indent=2))
    return worst


if __name__ == '__main__':
    sys.exit(main())
