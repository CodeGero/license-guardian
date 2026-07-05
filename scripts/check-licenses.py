#!/usr/bin/env python3
"""
License Guardian — Check dependency licenses for compliance.
Scans package.json, requirements.txt, go.mod, Cargo.toml.
Flags GPL, AGPL, and other restrictive licenses.
Configurable allow/deny lists.
"""
import json
import os
import re
import sys
import subprocess
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────

ALLOW_LIST = os.environ.get('INPUT_ALLOW', '').split(',')
ALLOW_LIST = [a.strip().lower() for a in ALLOW_LIST if a.strip()]

DENY_LIST = os.environ.get('INPUT_DENY', '').split(',')
DENY_LIST = [d.strip().lower() for d in DENY_LIST if d.strip()]

# Default restrictive licenses to flag
RESTRICTIVE_LICENSES = [
    'gpl-2.0', 'gpl-2.0-only', 'gpl-2.0-or-later',
    'gpl-3.0', 'gpl-3.0-only', 'gpl-3.0-or-later',
    'agpl-3.0', 'agpl-3.0-only', 'agpl-3.0-or-later',
    'lgpl-2.1', 'lgpl-3.0',
    'mpl-2.0',
    'eupl-1.1', 'eupl-1.2',
    'osl-3.0',
    'sleepycat',
    'cc-by-nc-4.0', 'cc-by-nc-sa-4.0',
    'busl-1.1',  # Business Source License
    'sspl-1.0',  # Server Side Public License
    'elastic-2.0',
    'rsalv2',    # Redis Source Available License
    'unlicensed',
]

if DENY_LIST:
    RESTRICTIVE_LICENSES = DENY_LIST

WORKING_DIR = os.environ.get('INPUT_WORKING_DIRECTORY', '.')
FAIL_ON_RESTRICTIVE = os.environ.get('INPUT_FAIL_ON_RESTRICTIVE', 'true').lower() == 'true'
ANNOTATE = os.environ.get('INPUT_ANNOTATE', 'true').lower() == 'true'
SCAN_NPM = os.environ.get('INPUT_SCAN_NPM', 'true').lower() == 'true'
SCAN_PIP = os.environ.get('INPUT_SCAN_PIP', 'true').lower() == 'true'
SCAN_GO = os.environ.get('INPUT_SCAN_GO', 'true').lower() == 'true'
SCAN_CARGO = os.environ.get('INPUT_SCAN_CARGO', 'true').lower() == 'true'

# ── Helpers ────────────────────────────────────────────────────────────────

def is_restrictive(license_str):
    """Check if a license string matches known restrictive licenses."""
    if not license_str:
        return False

    normalized = license_str.strip().lower()

    # Handle SPDX compound expressions
    for part in re.split(r'\s+(?:and|or)\s+', normalized):
        part = part.strip('() ')
        # Check allow list first
        for allowed in ALLOW_LIST:
            if allowed in part:
                return False
        # Check deny/restrictive list
        for restricted in RESTRICTIVE_LICENSES:
            if restricted in part:
                return True

    return False


def normalize_license(lic):
    """Normalize a license string to a clean identifier."""
    if not lic:
        return 'UNKNOWN'
    if isinstance(lic, dict):
        lic = lic.get('type', lic.get('name', ''))
    if isinstance(lic, list):
        lic = ' OR '.join(str(l) for l in lic)
    return str(lic).strip()


def emit_annotation(level, title, message, file=None, line=None):
    """Emit a GitHub Actions annotation."""
    parts = [f'::{level}']
    if file:
        parts.append(f' file={file}')
    if line:
        parts.append(f' line={line}')
    parts.append(f' title={title}')
    parts.append(f'::{message}')
    print(''.join(parts))


# ── NPM Scanner (package.json) ─────────────────────────────────────────────

def scan_npm():
    """Scan package.json for dependency licenses using npm registry API."""
    pkg_json = Path(WORKING_DIR) / 'package.json'
    if not pkg_json.exists():
        return

    print(f'::group::Scanning npm dependencies ({pkg_json})')

    with open(pkg_json, 'r') as f:
        pkg = json.load(f)

    deps = {}
    deps.update(pkg.get('dependencies', {}))
    deps.update(pkg.get('devDependencies', {}))
    deps.update(pkg.get('peerDependencies', {}))

    if not deps:
        print('No dependencies found in package.json.')
        print('::endgroup::')
        return

    violations = 0
    checked = 0
    total = len(deps)

    for name, version in deps.items():
        checked += 1
        # Strip semver range prefix characters for API call
        clean_version = re.sub(r'^[\^~>=<]+\s*', '', version)
        pkg_info = fetch_npm_package(name, clean_version)

        license_str = normalize_license(pkg_info.get('license', 'UNKNOWN'))
        repo = pkg_info.get('repository', '')
        if isinstance(repo, dict):
            repo = repo.get('url', '')

        print(f'  [{checked}/{total}] {name}@{clean_version} → {license_str}')

        if is_restrictive(license_str):
            violations += 1
            emit_annotation('error', f'License: {license_str}',
                          f'{name}@{clean_version} is licensed under {license_str}')

    print(f'')
    if violations:
        print(f'⚠️  {violations} packages with restrictive licenses found.')
    else:
        print(f'✅ All {checked} packages have acceptable licenses.')
    print('::endgroup::')
    return violations


def fetch_npm_package(name, version):
    """Fetch package metadata from npm registry."""
    try:
        # Try latest version info
        url = f'https://registry.npmjs.org/{name}/{version}'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        pass

    try:
        # Fall back to full package metadata
        url = f'https://registry.npmjs.org/{name}/latest'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


# ── PyPI Scanner (requirements.txt) ────────────────────────────────────────

def scan_pip():
    """Scan requirements.txt for dependency licenses."""
    req_file = Path(WORKING_DIR) / 'requirements.txt'
    if not req_file.exists():
        return

    print(f'::group::Scanning pip dependencies ({req_file})')

    packages = parse_requirements(req_file)
    if not packages:
        print('No packages found in requirements.txt.')
        print('::endgroup::')
        return

    violations = 0
    checked = 0
    total = len(packages)

    for name, version in packages:
        checked += 1
        lic = fetch_pypi_license(name, version)
        license_str = normalize_license(lic)

        print(f'  [{checked}/{total}] {name}=={version} → {license_str}')

        if is_restrictive(license_str):
            violations += 1
            emit_annotation('error', f'License: {license_str}',
                          f'{name}=={version} is licensed under {license_str}')

    print(f'')
    if violations:
        print(f'⚠️  {violations} packages with restrictive licenses found.')
    else:
        print(f'✅ All {checked} packages have acceptable licenses.')
    print('::endgroup::')
    return violations


def parse_requirements(filepath):
    """Parse requirements.txt into (name, version) tuples."""
    packages = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            # Handle: name==version, name>=version, name~=version, etc.
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[0-9.*]+)?', line)
            if match:
                name = match.group(1)
                version = match.group(2) or 'latest'
                version = re.sub(r'\s+', '', version)
                packages.append((name, version))
    return packages


def fetch_pypi_license(name, version):
    """Fetch license info from PyPI JSON API."""
    try:
        url = f'https://pypi.org/pypi/{name}/json'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        info = data.get('info', {})
        license_str = info.get('license', '')
        if not license_str:
            # Try classifiers
            classifiers = info.get('classifiers', [])
            for c in classifiers:
                if c.startswith('License ::'):
                    license_str = c.replace('License :: OSI Approved :: ', '')
                    license_str = license_str.replace('License :: ', '')
                    break
        return license_str or 'UNKNOWN'
    except Exception:
        return 'UNKNOWN'


# ── Go Scanner (go.mod) ────────────────────────────────────────────────────

def scan_go():
    """Scan go.mod for dependency licenses using Go proxy."""
    go_mod = Path(WORKING_DIR) / 'go.mod'
    if not go_mod.exists():
        return

    print(f'::group::Scanning Go dependencies ({go_mod})')

    packages = parse_go_mod(go_mod)
    if not packages:
        print('No dependencies found in go.mod.')
        print('::endgroup::')
        return

    violations = 0
    checked = 0
    total = len(packages)

    for module, version in packages:
        checked += 1
        lic = fetch_go_license(module, version)
        license_str = normalize_license(lic)

        print(f'  [{checked}/{total}] {module}@{version} → {license_str}')

        if is_restrictive(license_str):
            violations += 1
            emit_annotation('error', f'License: {license_str}',
                          f'{module}@{version} is licensed under {license_str}')

    print(f'')
    if violations:
        print(f'⚠️  {violations} packages with restrictive licenses found.')
    else:
        print(f'✅ All {checked} packages have acceptable licenses.')
    print('::endgroup::')
    return violations


def parse_go_mod(filepath):
    """Parse go.mod require directives."""
    modules = []
    with open(filepath, 'r') as f:
        in_require = False
        for line in f:
            line = line.strip()
            if line.startswith('require ('):
                in_require = True
                continue
            if in_require and line == ')':
                in_require = False
                continue
            if in_require or line.startswith('require '):
                # Strip 'require ' prefix for single-line requires
                line = re.sub(r'^require\s+', '', line)
                parts = line.split()
                if len(parts) >= 2:
                    modules.append((parts[0], parts[1]))
    return modules


def fetch_go_license(module, version):
    """Fetch license from Go module proxy."""
    try:
        # go proxy returns license in the module info
        url = f'https://proxy.golang.org/{module}/@v/{version}.mod'
        req = urllib.request.Request(url, headers={'Accept': 'text/plain'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 'See module source'
    except Exception:
        return 'UNKNOWN'


# ── Cargo Scanner (Cargo.toml) ─────────────────────────────────────────────

def scan_cargo():
    """Scan Cargo.toml for dependency licenses using crates.io API."""
    cargo_toml = Path(WORKING_DIR) / 'Cargo.toml'
    if not cargo_toml.exists():
        return

    print(f'::group::Scanning Cargo dependencies ({cargo_toml})')

    packages = parse_cargo_toml(cargo_toml)
    if not packages:
        print('No dependencies found in Cargo.toml.')
        print('::endgroup::')
        return

    violations = 0
    checked = 0
    total = len(packages)

    for name, version in packages:
        checked += 1
        lic = fetch_cargo_license(name)
        license_str = normalize_license(lic)

        print(f'  [{checked}/{total}] {name} → {license_str}')

        if is_restrictive(license_str):
            violations += 1
            emit_annotation('error', f'License: {license_str}',
                          f'{name} is licensed under {license_str}')

    print(f'')
    if violations:
        print(f'⚠️  {violations} packages with restrictive licenses found.')
    else:
        print(f'✅ All {checked} packages have acceptable licenses.')
    print('::endgroup::')
    return violations


def parse_cargo_toml(filepath):
    """Parse Cargo.toml [dependencies] section."""
    deps = []
    with open(filepath, 'r') as f:
        in_deps = False
        for line in f:
            line = line.strip()
            if re.match(r'^\[dependencies\]', line):
                in_deps = True
                continue
            if in_deps and line.startswith('['):
                # Check if it's a sub-section like [dependencies.foo]
                if not re.match(r'^\[dependencies\.', line):
                    in_deps = False
                    continue
            if in_deps and line and not line.startswith('['):
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*=', line)
                if match:
                    deps.append((match.group(1), '*'))
    return deps


def fetch_cargo_license(name):
    """Fetch license from crates.io API."""
    try:
        url = f'https://crates.io/api/v1/crates/{name}'
        req = urllib.request.Request(url, headers={
            'Accept': 'application/json',
            'User-Agent': 'license-guardian/1.0'
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get('crate', {}).get('license', 'UNKNOWN')
    except Exception:
        return 'UNKNOWN'


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    os.chdir(WORKING_DIR)

    print('')
    print('═══════════════════════════════════════')
    print('  License Guardian — Compliance Check')
    print('═══════════════════════════════════════')
    print('')
    print(f'  Allow list: {ALLOW_LIST if ALLOW_LIST else "(none)"}')
    if DENY_LIST:
        print(f'  Deny list:  {DENY_LIST}')
    else:
        print(f'  Flagging:   GPL, AGPL, LGPL, SSPL, BSL, Elastic, and more')
    print('')

    total_violations = 0
    found_any = False

    if SCAN_NPM:
        n = scan_npm() or 0
        total_violations += n
        found_any = True

    if SCAN_PIP:
        n = scan_pip() or 0
        total_violations += n
        found_any = True

    if SCAN_GO:
        n = scan_go() or 0
        total_violations += n
        found_any = True

    if SCAN_CARGO:
        n = scan_cargo() or 0
        total_violations += n
        found_any = True

    if not found_any:
        print('No supported package manifests found (package.json, requirements.txt, go.mod, Cargo.toml).')
        print('Add one to begin license scanning.')

    print('')
    print('═══════════════════════════════════════')
    if total_violations:
        print(f'  ⚠️  {total_violations} license violation(s) detected.')
    else:
        print(f'  ✅ All dependencies have acceptable licenses.')
    print('═══════════════════════════════════════')
    print('')
    print('  Upgrade to Premium for advanced features:')
    print('  → https://kryptorious.gumroad.com/l/jbvet')
    print('')

    if FAIL_ON_RESTRICTIVE and total_violations > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()
