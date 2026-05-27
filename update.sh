#!/usr/bin/env bash
#
# update.sh - Fetch the latest upstream version of every tool tracked in this
# repo. Best-effort: any single failure is logged and the script moves on.
#
# Usage:
#   ./update.sh                 # update everything
#   ./update.sh --list          # print the registry without doing anything
#   ./update.sh --only <pat>    # only entries whose name contains <pat> (case-insensitive)
#   ./update.sh --skip <pat>    # skip entries whose name contains <pat>
#   GITHUB_TOKEN=ghp_... ./update.sh   # raises GitHub API rate limit
#
# Each tool entry is a single `begin "Name" && { ... }` block. Helpers handle
# the common patterns: GitHub release assets, raw files from a branch, and
# full-repo exports into a directory.
#
# Local forks / customisations:
#   - Bruteforce/su-bruteforce -> Mag1cByt3s/su-bruteforce (your fork)
# Anything else points at the upstream. If you have local edits you want
# preserved, `git stash` (or commit) them first.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_BASE="$(mktemp -d -t tools-update.XXXXXX)"
trap 'rm -rf "$TMP_BASE"' EXIT

MODE="run"          # run | list
ONLY=""
SKIP=""

while (( $# > 0 )); do
  case "$1" in
    --list)  MODE="list"; shift;;
    --only)  ONLY="${2:-}"; shift 2;;
    --skip)  SKIP="${2:-}"; shift 2;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

# ---------- logging ----------
C_RESET=$'\033[0m'
C_INFO=$'\033[1;34m'
C_OK=$'\033[1;32m'
C_WARN=$'\033[1;33m'
C_DIM=$'\033[2m'

CURRENT_TOOL=""
COUNT_OK=0
COUNT_WARN=0
FAILED=()

log()   { printf '%s[*]%s %s\n' "$C_INFO" "$C_RESET" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_OK"   "$C_RESET" "$*"; COUNT_OK=$((COUNT_OK+1)); }
warn()  { printf '%s[!]%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; COUNT_WARN=$((COUNT_WARN+1)); FAILED+=("${CURRENT_TOOL:-?}: $*"); }
debug() { printf '%s    %s%s\n' "$C_DIM"  "$*" "$C_RESET"; }

# Match name against --only / --skip filters.
should_run() {
  local lc only_lc skip_lc
  lc="${1,,}"
  only_lc="${ONLY,,}"
  skip_lc="${SKIP,,}"
  [[ -n "$ONLY" && "$lc" != *"$only_lc"* ]] && return 1
  [[ -n "$SKIP" && "$lc" == *"$skip_lc"* ]] && return 1
  return 0
}

# Tool gate. Returns 0 only when we should actually perform work.
# In list mode it prints the entry name and returns 1.
begin() {
  CURRENT_TOOL="$1"
  should_run "$1" || return 1
  if [[ "$MODE" == "list" ]]; then
    printf '  %s\n' "$1"
    return 1
  fi
  log "$1"
  return 0
}

# ---------- download helpers ----------

# curl wrapper: fail-on-HTTP-error, follow redirects, retries, optional GH auth.
_curl() {
  local auth=()
  [[ -n "${GITHUB_TOKEN:-}" && "$1" == *github* ]] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
       --user-agent "tools-update.sh" "${auth[@]}" "$@"
}

# fetch_to URL DEST   -- atomic: writes to a tmp file, then mv into place.
fetch_to() {
  local url="$1" dest="$2" tmp
  mkdir -p "$(dirname "$dest")"
  tmp="$(mktemp -p "$TMP_BASE" "$(basename "$dest").XXXXXX")"
  if _curl -o "$tmp" "$url"; then
    mv "$tmp" "$dest"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

# release_asset OWNER/REPO ASSET_NAME DEST
# Uses the redirect URL /releases/latest/download/<asset> -- no API call.
release_asset() {
  local repo="$1" asset="$2" dest="$3"
  local url="https://github.com/${repo}/releases/latest/download/${asset}"
  debug "GET $url"
  if fetch_to "$url" "$dest"; then ok "  -> $dest"; else warn "release asset failed: ${repo} / ${asset}"; return 1; fi
}

# release_asset_match OWNER/REPO ASSET_REGEX DEST
# Lists assets of latest release via API, picks first matching regex.
release_asset_match() {
  local repo="$1" pat="$2" dest="$3" json url
  json="$(_curl "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null || true)"
  url="$(echo "$json" | grep -oE '"browser_download_url":[[:space:]]*"[^"]+"' \
        | sed -E 's/.*"([^"]+)"$/\1/' | grep -E "$pat" | head -1)"
  if [[ -z "$url" ]]; then
    warn "no asset matching '${pat}' in latest release of ${repo}"
    return 1
  fi
  debug "GET $url"
  if fetch_to "$url" "$dest"; then ok "  -> $dest"; else warn "asset download failed: $url"; return 1; fi
}

# raw_file OWNER/REPO BRANCH PATH DEST
raw_file() {
  local repo="$1" branch="$2" path="$3" dest="$4"
  local url="https://raw.githubusercontent.com/${repo}/${branch}/${path}"
  debug "GET $url"
  if fetch_to "$url" "$dest"; then ok "  -> $dest"; else warn "raw file failed: ${repo}@${branch} ${path}"; return 1; fi
}

# git_export OWNER/REPO BRANCH DEST [SUBPATH]
# Shallow-clones repo, rsyncs subpath into DEST. Does NOT delete extra files
# in DEST (so locally-added READMEs, zips you bundled by hand, etc. survive).
git_export() {
  local repo="$1" branch="$2" dest="$3" subpath="${4:-}"
  local url="https://github.com/${repo}.git" work src
  work="$(mktemp -d -p "$TMP_BASE" "$(basename "$repo").XXXXXX")"
  debug "git clone --depth 1 --branch ${branch} ${url}"
  if ! git clone --depth 1 --branch "$branch" --quiet "$url" "$work" 2>/dev/null; then
    git clone --depth 1 --quiet "$url" "$work" 2>/dev/null || { warn "git clone failed: ${repo}"; return 1; }
  fi
  src="$work"; [[ -n "$subpath" ]] && src="$work/$subpath"
  [[ -d "$src" ]] || { warn "subpath '${subpath}' missing in ${repo}"; return 1; }
  mkdir -p "$dest"
  rsync -a --exclude='.git' --exclude='.github' "$src/" "$dest/"
  ok "  -> $dest/"
}

# git_export_replace: same but wipes DEST first so directory mirrors upstream.
git_export_replace() {
  local repo="$1" branch="$2" dest="$3" subpath="${4:-}"
  local url="https://github.com/${repo}.git" work src
  work="$(mktemp -d -p "$TMP_BASE" "$(basename "$repo").XXXXXX")"
  debug "git clone --depth 1 --branch ${branch} ${url}"
  if ! git clone --depth 1 --branch "$branch" --quiet "$url" "$work" 2>/dev/null; then
    git clone --depth 1 --quiet "$url" "$work" 2>/dev/null || { warn "git clone failed: ${repo}"; return 1; }
  fi
  src="$work"; [[ -n "$subpath" ]] && src="$work/$subpath"
  [[ -d "$src" ]] || { warn "subpath '${subpath}' missing in ${repo}"; return 1; }
  mkdir -p "$dest"
  rsync -a --delete --exclude='.git' --exclude='.github' "$src/" "$dest/"
  ok "  -> $dest/"
}

# extract_release_zip OWNER/REPO ASSET_REGEX DEST_DIR
# Downloads the matching release asset (a zip), extracts everything into DEST_DIR.
extract_release_zip() {
  local repo="$1" pat="$2" dest_dir="$3" zip
  zip="$(mktemp -p "$TMP_BASE" rel.XXXXXX.zip)"
  if ! release_asset_match "$repo" "$pat" "$zip"; then return 1; fi
  mkdir -p "$dest_dir"
  unzip -oq "$zip" -d "$dest_dir" && ok "  -> $dest_dir/ (extracted)"
}

# pluck_from_zip ZIPFILE MEMBER_REGEX DEST
pluck_from_zip() {
  local zip="$1" pat="$2" dest="$3" entry
  entry="$(unzip -Z1 "$zip" 2>/dev/null | grep -E "$pat" | head -1)"
  [[ -z "$entry" ]] && { warn "no entry matching '$pat' in zip"; return 1; }
  mkdir -p "$(dirname "$dest")"
  unzip -p "$zip" "$entry" > "$dest" 2>/dev/null && ok "  -> $dest"
}

# pluck_from_tarball TGZ MEMBER_REGEX DEST
pluck_from_tarball() {
  local tgz="$1" pat="$2" dest="$3" entry
  entry="$(tar -tzf "$tgz" 2>/dev/null | grep -E "$pat" | head -1)"
  [[ -z "$entry" ]] && { warn "no entry matching '$pat' in tarball"; return 1; }
  mkdir -p "$(dirname "$dest")"
  tar -xzOf "$tgz" "$entry" > "$dest" && ok "  -> $dest"
}

# rename_versioned PATTERN_GLOB NEW_NAME
# Removes existing files in $1's directory that match the glob (versioned
# filenames like rmg-5.1.0-jar-with-dependencies.jar) then renames a tmp file.
# Usage: download to $TMP_BASE/<thing>.tmp, find versioned URL from API, mv.

# ---------- registry ----------

# Active Directory ========================================================

begin "ActiveDirectory/ADCS/passthecert.py" && {
  raw_file "AlmondOffSec/PassTheCert" "main" "Python/passthecert.py" \
           "$ROOT/ActiveDirectory/ADCS/passthecert.py"
}

begin "ActiveDirectory/ADCS/Certify.zip" && {
  log "  (skipped — GhostPack/Certify v2 publishes no release assets; the .zip you have is a self-bundle)"
}

begin "ActiveDirectory/Bloodhound/SharpHound.{exe,ps1}" && {
  zip="$TMP_BASE/sharphound.zip"
  # SpecterOps SharpHound 2.x publishes a single AnyCPU/.NET (PE32) build as
  # SharpHound_v<ver>_windows_x86.zip; the +debug variant is intentionally skipped.
  if release_asset_match "SpecterOps/SharpHound" 'SharpHound_v[0-9.]+_windows_x86\.zip$' "$zip"; then
    d="$TMP_BASE/sharphound"; mkdir -p "$d"
    unzip -oq "$zip" -d "$d"
    [[ -f "$d/SharpHound.exe" ]] && cp -f "$d/SharpHound.exe" "$ROOT/ActiveDirectory/Bloodhound/SharpHound.exe" && ok "  -> SharpHound.exe"
    [[ -f "$d/SharpHound.ps1" ]] && cp -f "$d/SharpHound.ps1" "$ROOT/ActiveDirectory/Bloodhound/SharpHound.ps1" && ok "  -> SharpHound.ps1"
  fi
}

begin "ActiveDirectory/Whisker.exe" && {
  log "  (skipped — eladshamir/Whisker is source-only; rebuild from Whisker.sln if needed)"
}

begin "ActiveDirectory/Exploits/noPac" && {
  for f in noPac.py scanner.py README.md requirements.txt; do
    raw_file "Ridter/noPac" "main" "$f" "$ROOT/ActiveDirectory/Exploits/noPac/$f"
  done
  for f in S4U2self.py addcomputer.py helper.py __init__.py secretsdump.py smbexec.py; do
    raw_file "Ridter/noPac" "main" "utils/$f" "$ROOT/ActiveDirectory/Exploits/noPac/utils/$f"
  done
}

begin "ActiveDirectory/Exploits/PetitPotam" && {
  raw_file "topotam/PetitPotam" "main" "PetitPotam.py" \
           "$ROOT/ActiveDirectory/Exploits/PetitPotam/PetitPotam.py"
  # Invoke-Petitpotam.ps1 was dropped from topotam/PetitPotam and has no
  # canonical maintained mirror — keeping the local copy as-is.
  # PetitPotam.exe must be built from PetitPotam.sln.
}

begin "ActiveDirectory/Exploits/PrintNightmare" && {
  raw_file "cube0x0/CVE-2021-1675" "main" "CVE-2021-1675.py" \
           "$ROOT/ActiveDirectory/Exploits/PrintNightmare/CVE-2021-1675.py"
  # cube0x0/SharpPrintNightmare has been removed from GitHub. The local copy
  # is kept as a frozen reference; rebuild from any community mirror if needed.
  log "  (SharpPrintNightmare subdir skipped — cube0x0/SharpPrintNightmare repo was deleted)"
}

begin "ActiveDirectory/Exploits/RemotePotato0.exe" && {
  zip="$TMP_BASE/remotepotato0.zip"
  if release_asset "antonioCoco/RemotePotato0" "RemotePotato0.zip" "$zip"; then
    td="$TMP_BASE/rp0"; mkdir -p "$td"; unzip -oq "$zip" -d "$td"
    exe="$(find "$td" -name 'RemotePotato0.exe' | head -1)"
    [[ -n "$exe" ]] && cp -f "$exe" "$ROOT/ActiveDirectory/Exploits/RemotePotato0/RemotePotato0.exe" \
      && ok "  -> RemotePotato0.exe"
  fi
}

begin "ActiveDirectory/Ghostpack-CompiledBinaries" && {
  # r3motecontrol/Ghostpack-CompiledBinaries publishes pre-built binaries for
  # each .NET runtime in subfolders matching the local layout.
  git_export "r3motecontrol/Ghostpack-CompiledBinaries" "master" \
             "$ROOT/ActiveDirectory/Ghostpack-CompiledBinaries"
}

begin "ActiveDirectory/Inveigh/Inveigh.exe" && {
  zip="$TMP_BASE/inveigh.zip"
  if release_asset_match "Kevin-Robertson/Inveigh" 'win-x64.*\.zip$' "$zip"; then
    d="$TMP_BASE/inveigh"; mkdir -p "$d"
    unzip -oq "$zip" -d "$d"
    exe="$(find "$d" -maxdepth 4 -iname 'Inveigh.exe' | head -1)"
    [[ -n "$exe" ]] && cp -f "$exe" "$ROOT/ActiveDirectory/Inveigh/Inveigh.exe" && ok "  -> Inveigh.exe"
  fi
}

begin "ActiveDirectory/Inveigh/Inveigh.ps1" && {
  raw_file "Kevin-Robertson/Inveigh" "master" "Inveigh.ps1" \
           "$ROOT/ActiveDirectory/Inveigh/Inveigh.ps1"
}

begin "ActiveDirectory/Kerberos/kirbi2john.py" && {
  raw_file "Mag1cByt3s/kirbi2john" "main" "kirbi2john.py" \
           "$ROOT/ActiveDirectory/Kerberos/kirbi2john.py"
}

begin "ActiveDirectory/Kerberos/KrbRelayUp.exe" && {
  log "  (skipped — Dec0ne/KrbRelayUp has no releases; rebuild from source if needed)"
}

begin "ActiveDirectory/Kerberos/Rubeus.exe" && {
  # Use the v4.7.2 build from Ghostpack-CompiledBinaries as a canonical "latest".
  raw_file "r3motecontrol/Ghostpack-CompiledBinaries" "master" \
           "dotnet%20v4.7.2%20compiled%20binaries/Rubeus.exe" \
           "$ROOT/ActiveDirectory/Kerberos/Rubeus.exe"
}

begin "ActiveDirectory/Kerberos/KeyTabExtract" && {
  git_export "sosdave/KeyTabExtract" "master" \
             "$ROOT/ActiveDirectory/Kerberos/KeyTabExtract"
}

begin "ActiveDirectory/krbrelayx" && {
  git_export "dirkjanm/krbrelayx" "master" "$ROOT/ActiveDirectory/krbrelayx"
}

# ntlm_theft / pywhisker / Recon =========================================

begin "ActiveDirectory/ntlm_theft" && {
  git_export "Greenwolf/ntlm_theft" "master" "$ROOT/ActiveDirectory/ntlm_theft"
}

begin "ActiveDirectory/pywhisker" && {
  git_export "ShutdownRepo/pywhisker" "main" "$ROOT/ActiveDirectory/pywhisker"
}

begin "ActiveDirectory/Recon/Get-SpoolStatus.ps1" && {
  log "  (skipped — extracted from PingCastle source; no stable upstream URL)"
}

begin "ActiveDirectory/Recon/linWinPwn" && {
  git_export "lefayjey/linWinPwn" "main" "$ROOT/ActiveDirectory/Recon/linWinPwn"
}

begin "ActiveDirectory/Recon/windapsearch" && {
  git_export "ropnop/windapsearch" "master" "$ROOT/ActiveDirectory/Recon/windapsearch"
}

# Bruteforce =============================================================

begin "Bruteforce/su-bruteforce (your fork)" && {
  git_export "Mag1cByt3s/su-bruteforce" "master" "$ROOT/Bruteforce/su-bruteforce"
}

# ContainerBreakout ======================================================

begin "ContainerBreakout/deepce.sh" && {
  raw_file "stealthcopter/deepce" "main" "deepce.sh" \
           "$ROOT/ContainerBreakout/deepce.sh"
}

# CredentialDumping ======================================================

begin "CredentialDumping/Linux/LaZagne.tar.gz" && {
  # Latest AlessandroZ/LaZagne release only ships LaZagne.exe (Windows). Bundle
  # the upstream Linux source tree as a tarball instead.
  work="$(mktemp -d -p "$TMP_BASE" lazagne.XXXXXX)"
  if git clone --depth 1 --quiet https://github.com/AlessandroZ/LaZagne.git "$work"; then
    (cd "$work" && tar --exclude='.git' --exclude='.github' \
        -czf "$ROOT/CredentialDumping/Linux/LaZagne.tar.gz" Linux 2>/dev/null) \
      && ok "  -> LaZagne.tar.gz (Linux/ tree from upstream)"
  else
    warn "git clone failed: AlessandroZ/LaZagne"
  fi
}

begin "CredentialDumping/Linux/LinikatzV2" && {
  git_export "Orange-Cyberdefense/LinikatzV2" "main" "$ROOT/CredentialDumping/Linux/LinikatzV2"
}

begin "CredentialDumping/Linux/mimipenguin_2.0-release" && {
  tgz="$TMP_BASE/mimipenguin.tgz"
  if release_asset_match "huntergregal/mimipenguin" '2\.0.*\.tar\.gz$|tar\.gz$' "$tgz"; then
    td="$TMP_BASE/mp"; mkdir -p "$td"
    tar -xzf "$tgz" -C "$td"
    extracted="$(find "$td" -maxdepth 2 -type d -name 'mimipenguin*' | head -1)"
    [[ -n "$extracted" ]] && rsync -a --delete "$extracted/" "$ROOT/CredentialDumping/Linux/mimipenguin_2.0-release/" \
      && ok "  -> mimipenguin_2.0-release/"
  fi
}

begin "CredentialDumping/Windows/LaZagne.exe" && {
  release_asset_match "AlessandroZ/LaZagne" 'lazagne\.exe$|LaZagne\.exe$' \
                      "$ROOT/CredentialDumping/Windows/LaZagne.exe"
}

begin "CredentialDumping/Windows/mimikatz" && {
  zip="$TMP_BASE/mimikatz_trunk.zip"
  if release_asset_match "gentilkiwi/mimikatz" 'mimikatz_trunk\.zip$' "$zip"; then
    td="$TMP_BASE/mimikatz"; mkdir -p "$td"
    unzip -oq "$zip" -d "$td"
    rsync -a --delete "$td/" "$ROOT/CredentialDumping/Windows/mimikatz/" && ok "  -> mimikatz/"
  else
    log "  (latest mimikatz release uses .7z — install p7zip and re-run, or update manually)"
  fi
}

begin "CredentialDumping/Windows/mremoteng_decrypt.py" && {
  raw_file "haseebT/mRemoteNG-Decrypt" "master" "mremoteng_decrypt.py" \
           "$ROOT/CredentialDumping/Windows/mremoteng_decrypt.py" \
    || raw_file "kmahyyg/mremoteng_decrypt" "main" "mremoteng_decrypt.py" \
                "$ROOT/CredentialDumping/Windows/mremoteng_decrypt.py"
}

# Deserialization ========================================================

begin "Deserialization/ysoserial-all.jar" && {
  release_asset_match "frohoff/ysoserial" 'ysoserial-all\.jar$' \
                      "$ROOT/Deserialization/ysoserial-all.jar"
}

# Evasion ================================================================

begin "Evasion/Nimcrypt2" && {
  git_export "icyguider/Nimcrypt2" "main" "$ROOT/Evasion/Nimcrypt2"
}

# Exploits ===============================================================
# CVE PoCs are mostly frozen / locally compiled — see comments below.

begin "Exploits/Linux/PwnKit" && {
  git_export "ly4k/PwnKit" "main" "$ROOT/Exploits/Linux/PwnKit"
}

begin "Exploits/Linux/CVE-2022-0847-DirtyPipe-Exploits" && {
  git_export "AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits" "main" \
             "$ROOT/Exploits/Linux/CVE-2022-0847-DirtyPipe-Exploits"
}

begin "Exploits/Linux/* (frozen PoCs)" && {
  log "  (skipped — CVE-2017-16995, CVE-2021-22555, CVE-2021-3156, CVE-2022-25636, CVE-2023-32233, DirtyCow are frozen / locally compiled PoCs)"
}

begin "Exploits/Windows/Perfusion" && {
  log "  (skipped — itm4n/Perfusion has no release assets; keep local x32/x64 builds)"
}

begin "Exploits/Windows/* (frozen)" && {
  log "  (skipped — HiveNightmare.exe, CVE-2020-0668, PrintNightmare are local builds / source-only PoCs)"
}

# HTTP / Mail / XSS ======================================================

begin "HTTP/HTTP-POST-server.py, Mail/smtpd.py, XSS/XSS-cookie-stealer.py" && {
  log "  (skipped — small self-contained custom scripts)"
}

# JMX ====================================================================

begin "JMX/beanshooter-*.jar" && {
  url="$(_curl https://api.github.com/repos/qtc-de/beanshooter/releases/latest \
        | grep -oE '"browser_download_url":[[:space:]]*"[^"]+beanshooter-[^"]+-jar-with-dependencies\.jar"' \
        | sed -E 's/.*"([^"]+)"$/\1/' | head -1)"
  if [[ -n "$url" ]]; then
    fname="$(basename "$url")"
    if fetch_to "$url" "$ROOT/JMX/$fname"; then
      find "$ROOT/JMX" -maxdepth 1 -name 'beanshooter-*-jar-with-dependencies.jar' ! -name "$fname" -delete 2>/dev/null
      ok "  -> $ROOT/JMX/$fname"
    fi
  else
    warn "could not resolve beanshooter latest asset"
  fi
}

# JNDI ===================================================================

begin "JNDI/JNDI-Exploit-Kit (source — jar must be rebuilt)" && {
  work="$(mktemp -d -p "$TMP_BASE" jndi.XXXXXX)"
  if git clone --depth 1 --quiet https://github.com/pimps/JNDI-Exploit-Kit.git "$work"; then
    rsync -a --exclude='.git' --exclude='.github' --exclude='target' \
          "$work/" "$ROOT/JNDI/JNDI-Exploit-Kit/"
    ok "  -> JNDI-Exploit-Kit/ (source only — rebuild with: mvn clean package -DskipTests)"
  else
    warn "git clone failed: pimps/JNDI-Exploit-Kit"
  fi
}

# Kubernetes =============================================================

begin "Kubernetes/peirates-linux-amd64/peirates" && {
  txz="$TMP_BASE/peirates.tar.xz"
  if release_asset "inguardians/peirates" "peirates-linux-amd64.tar.xz" "$txz"; then
    td="$TMP_BASE/peir"; mkdir -p "$td"
    if tar -xJf "$txz" -C "$td"; then
      bin="$(find "$td" -maxdepth 3 -name peirates -type f | head -1)"
      [[ -n "$bin" ]] && cp -f "$bin" "$ROOT/Kubernetes/peirates-linux-amd64/peirates" \
        && chmod +x "$ROOT/Kubernetes/peirates-linux-amd64/peirates" \
        && ok "  -> peirates"
    else
      warn "tar -xJ failed (xz support required)"
    fi
  fi
}

# MitM ===================================================================

begin "MitM/ssh-mitm-x86_64.AppImage" && {
  release_asset_match "ssh-mitm/ssh-mitm" 'ssh-mitm-x86_64\.AppImage$' \
                      "$ROOT/MitM/ssh-mitm-x86_64.AppImage" \
    && chmod +x "$ROOT/MitM/ssh-mitm-x86_64.AppImage"
}

# Netcat / Socat =========================================================

begin "Netcat/* + Socat/* (static portable binaries)" && {
  log "  (skipped — no canonical upstream for the bundled static builds)"
}

# Payloads ===============================================================

begin "Payloads/phpggc" && {
  git_export "ambionics/phpggc" "master" "$ROOT/Payloads/phpggc"
}

# Phishing ===============================================================

begin "Phishing/PDF/Bad-Pdf" && {
  git_export "deepzec/Bad-Pdf" "master" "$ROOT/Phishing/PDF/Bad-Pdf"
}

# Pivoting ===============================================================

begin "Pivoting/chisel (linux + windows)" && {
  tag="$(_curl https://api.github.com/repos/jpillora/chisel/releases/latest \
        | grep -oE '"tag_name":[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"v?([^"]+)"$/\1/')"
  if [[ -n "$tag" ]]; then
    gz="$TMP_BASE/chisel_linux.gz"
    if release_asset "jpillora/chisel" "chisel_${tag}_linux_amd64.gz" "$gz"; then
      gunzip -fc "$gz" > "$ROOT/Pivoting/chisel" && chmod +x "$ROOT/Pivoting/chisel" && ok "  -> chisel"
    fi
    # Windows builds are shipped as zip on jpillora/chisel; extract chisel.exe.
    zip="$TMP_BASE/chisel_win.zip"
    if release_asset "jpillora/chisel" "chisel_${tag}_windows_amd64.zip" "$zip"; then
      td="$TMP_BASE/chisel_win"; mkdir -p "$td"; unzip -oq "$zip" -d "$td"
      exe="$(find "$td" -name 'chisel*.exe' | head -1)"
      [[ -n "$exe" ]] && cp -f "$exe" "$ROOT/Pivoting/chisel.exe" && ok "  -> chisel.exe"
    fi
  else
    warn "could not resolve chisel latest tag"
  fi
}

begin "Pivoting/dnscat2 (server source)" && {
  work="$(mktemp -d -p "$TMP_BASE" dnscat2.XXXXXX)"
  if git clone --depth 1 --quiet https://github.com/iagox86/dnscat2.git "$work"; then
    rsync -a --delete --exclude='.git' --exclude='.github' "$work/server/" "$ROOT/Pivoting/dnscat2/server/"
    ok "  -> dnscat2/server/"
  else
    warn "git clone failed: iagox86/dnscat2"
  fi
}

begin "Pivoting/dnscat2/client_windows/dnscat2.ps1" && {
  raw_file "lukebaggett/dnscat2-powershell" "master" "dnscat2.ps1" \
           "$ROOT/Pivoting/dnscat2/client_windows/dnscat2.ps1"
}

begin "Pivoting/dnscat2 (compiled clients)" && {
  log "  (skipped — dnscat2 has no canonical compiled client release; build from cloned server above)"
}

begin "Pivoting/ligolo-ng (agent+proxy, linux+windows)" && {
  v="$(_curl https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest \
       | grep -oE '"tag_name":[[:space:]]*"[^"]+"' | head -1 | sed -E 's/.*"v?([^"]+)"$/\1/')"
  if [[ -n "$v" ]]; then
    tgz="$TMP_BASE/lig_proxy.tgz"
    if release_asset "nicocha30/ligolo-ng" "ligolo-ng_proxy_${v}_linux_amd64.tar.gz" "$tgz"; then
      tar -xzf "$tgz" -C "$TMP_BASE" proxy 2>/dev/null \
        && mv "$TMP_BASE/proxy" "$ROOT/Pivoting/ligolo-ng/proxy" \
        && chmod +x "$ROOT/Pivoting/ligolo-ng/proxy" && ok "  -> proxy"
    fi
    tgz="$TMP_BASE/lig_agent.tgz"
    if release_asset "nicocha30/ligolo-ng" "ligolo-ng_agent_${v}_linux_amd64.tar.gz" "$tgz"; then
      tar -xzf "$tgz" -C "$TMP_BASE" agent 2>/dev/null \
        && mv "$TMP_BASE/agent" "$ROOT/Pivoting/ligolo-ng/agent" \
        && chmod +x "$ROOT/Pivoting/ligolo-ng/agent" && ok "  -> agent"
    fi
    zip="$TMP_BASE/lig_agent_win.zip"
    if release_asset "nicocha30/ligolo-ng" "ligolo-ng_agent_${v}_windows_amd64.zip" "$zip"; then
      td="$TMP_BASE/lig_win"; mkdir -p "$td"; unzip -oq "$zip" -d "$td"
      exe="$(find "$td" -name 'agent.exe' | head -1)"
      [[ -n "$exe" ]] && mv "$exe" "$ROOT/Pivoting/ligolo-ng/agent.exe" && ok "  -> agent.exe"
    fi
    printf 'Ligolo-ng v%s\nhttps://github.com/nicocha30/ligolo-ng/releases/tag/v%s\n' "$v" "$v" \
      > "$ROOT/Pivoting/ligolo-ng/VERSION"
    ok "  -> VERSION"
  else
    warn "could not resolve ligolo-ng latest tag"
  fi
}

begin "Pivoting/ptunnel-ng" && {
  log "  (skipped — utoni/ptunnel-ng's latest release has no binary assets; the local builds are static; rebuild from source if needed)"
}

begin "Pivoting/rpivot" && {
  work="$(mktemp -d -p "$TMP_BASE" rpivot.XXXXXX)"
  if git clone --depth 1 --quiet https://github.com/klsecservices/rpivot.git "$work"; then
    rsync -a --exclude='.git' --exclude='.github' \
          --exclude='client.exe' --exclude='rpivot.tar.gz' \
          "$work/" "$ROOT/Pivoting/rpivot/"
    (cd "$ROOT/Pivoting" && \
      tar --exclude='rpivot/rpivot.tar.gz' --exclude='rpivot/client.exe' \
          -czf rpivot/rpivot.tar.gz rpivot 2>/dev/null) \
      && ok "  -> rpivot/ (rpivot.tar.gz regenerated)"
  else
    warn "git clone failed: klsecservices/rpivot"
  fi
}

begin "Pivoting/SocksOverRDP (x64/x86/ARM64 zips)" && {
  for arch in x64 x86 ARM64; do
    release_asset "nccgroup/SocksOverRDP" "SocksOverRDP-${arch}.zip" \
                  "$ROOT/Pivoting/SocksOverRDP/SocksOverRDP-${arch}.zip"
  done
}

begin "Pivoting/Proxifier, plink.exe, rdp2tcp" && {
  log "  (skipped — proprietary / PuTTY / SourceForge upstream, no stable release URL)"
}

# Privesc / Linux ========================================================

begin "Privesc/Linux/LinEnum.sh" && {
  raw_file "rebootuser/LinEnum" "master" "LinEnum.sh" "$ROOT/Privesc/Linux/LinEnum.sh"
}

begin "Privesc/Linux/linpeas.sh" && {
  release_asset "peass-ng/PEASS-ng" "linpeas.sh" "$ROOT/Privesc/Linux/linpeas.sh" \
    && chmod +x "$ROOT/Privesc/Linux/linpeas.sh"
}

begin "Privesc/Linux/pspy64" && {
  release_asset "DominicBreuker/pspy" "pspy64" "$ROOT/Privesc/Linux/pspy64" \
    && chmod +x "$ROOT/Privesc/Linux/pspy64"
}

# Privesc / Windows ======================================================

begin "Privesc/Windows/winPEAS.{exe,bat,ps1}" && {
  # PEASS-ng publishes several winPEAS variants. winPEASany.exe is the standard
  # AnyCPU build with no obfuscation; the .bat ships as a release asset; the
  # .ps1 lives in the repo (no longer attached to releases).
  release_asset "peass-ng/PEASS-ng" "winPEASany.exe" "$ROOT/Privesc/Windows/winPEAS.exe"
  release_asset "peass-ng/PEASS-ng" "winPEAS.bat"    "$ROOT/Privesc/Windows/winPEAS.bat"
  raw_file "peass-ng/PEASS-ng" "master" "winPEAS/winPEASps1/winPEAS.ps1" \
           "$ROOT/Privesc/Windows/winPEAS.ps1"
}

begin "Privesc/Windows/PrivescCheck" && {
  git_export_replace "itm4n/PrivescCheck" "master" "$ROOT/Privesc/Windows/PrivescCheck"
}

begin "Privesc/Windows/Seatbelt.exe + SharpUp.exe (Ghostpack)" && {
  raw_file "r3motecontrol/Ghostpack-CompiledBinaries" "master" \
           "dotnet%20v4.7.2%20compiled%20binaries/Seatbelt.exe" \
           "$ROOT/Privesc/Windows/Seatbelt.exe"
  raw_file "r3motecontrol/Ghostpack-CompiledBinaries" "master" \
           "dotnet%20v4.7.2%20compiled%20binaries/SharpUp.exe" \
           "$ROOT/Privesc/Windows/SharpUp.exe"
}

begin "Privesc/Windows/SeBackupPrivilege/*.dll" && {
  raw_file "giuliano108/SeBackupPrivilege" "master" \
           "SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll" \
           "$ROOT/Privesc/Windows/SeBackupPrivilege/SeBackupPrivilegeCmdLets.dll"
  raw_file "giuliano108/SeBackupPrivilege" "master" \
           "SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll" \
           "$ROOT/Privesc/Windows/SeBackupPrivilege/SeBackupPrivilegeUtils.dll"
}

# Potatoes ---------------------------------------------------------------

# helper for potato exes that ship either as bare .exe or inside a same-named .zip
fetch_potato_exe() {
  local repo="$1" exe_name="$2" dest="$3" tmp base
  base="${exe_name%.exe}"
  tmp="$TMP_BASE/${exe_name}.dl"
  if release_asset_match "$repo" "(^|/)${base//./\\.}\.(exe|zip)\$" "$tmp"; then
    if file "$tmp" 2>/dev/null | grep -q 'Zip'; then
      local td="${tmp}.d"; mkdir -p "$td"; unzip -oq "$tmp" -d "$td"
      local exe; exe="$(find "$td" -iname "$exe_name" | head -1)"
      [[ -n "$exe" ]] && cp -f "$exe" "$dest" && ok "  -> $dest"
    else
      cp -f "$tmp" "$dest" && ok "  -> $dest"
    fi
  fi
}

begin "Privesc/Windows/SeImpersonatePrivilege/GodPotato-NET4.exe" && {
  release_asset "BeichenDream/GodPotato" "GodPotato-NET4.exe" \
                "$ROOT/Privesc/Windows/SeImpersonatePrivilege/GodPotato-NET4.exe"
}

begin "Privesc/Windows/SeImpersonatePrivilege/JuicyPotatoNG.exe" && {
  fetch_potato_exe "antonioCoco/JuicyPotatoNG" "JuicyPotatoNG.exe" \
                   "$ROOT/Privesc/Windows/SeImpersonatePrivilege/JuicyPotatoNG.exe"
}

begin "Privesc/Windows/SeImpersonatePrivilege/LocalPotato.exe" && {
  fetch_potato_exe "decoder-it/LocalPotato" "LocalPotato.exe" \
                   "$ROOT/Privesc/Windows/SeImpersonatePrivilege/LocalPotato.exe"
}

begin "Privesc/Windows/SeImpersonatePrivilege/PrintSpoofer64.exe" && {
  release_asset "itm4n/PrintSpoofer" "PrintSpoofer64.exe" \
                "$ROOT/Privesc/Windows/SeImpersonatePrivilege/PrintSpoofer64.exe"
}

begin "Privesc/Windows/SeImpersonatePrivilege/RoguePotato.exe" && {
  fetch_potato_exe "antonioCoco/RoguePotato" "RoguePotato.exe" \
                   "$ROOT/Privesc/Windows/SeImpersonatePrivilege/RoguePotato.exe"
}

begin "Privesc/Windows/SeImpersonatePrivilege/SigmaPotato.exe + Invoke-SigmaPotato.ps1" && {
  release_asset_match "tylerdotrar/SigmaPotato" 'SigmaPotato\.exe$' \
                      "$ROOT/Privesc/Windows/SeImpersonatePrivilege/SigmaPotato.exe"
  raw_file "tylerdotrar/SigmaPotato" "main" "Invoke-SigmaPotato.ps1" \
           "$ROOT/Privesc/Windows/SeImpersonatePrivilege/Invoke-SigmaPotato.ps1"
}

begin "Privesc/Windows/SeImpersonatePrivilege/SweetPotato.exe" && {
  # CCob/SweetPotato has no release assets; fall back to a build that ships
  # SweetPotato.exe in PowerSharpPack (S3cur3Th1sSh1t).
  log "  (skipped — CCob/SweetPotato has no release; rebuild from source if needed)"
}

begin "Privesc/Windows/SeImpersonatePrivilege/DeadPotato-NET4.exe" && {
  release_asset_match "lypd0/DeadPotato" 'DeadPotato.*NET4\.exe$' \
                      "$ROOT/Privesc/Windows/SeImpersonatePrivilege/DeadPotato-NET4.exe" \
    || log "  (no DeadPotato release asset — leaving local copy)"
}

begin "Privesc/Windows/SeImpersonatePrivilege/churrasco.exe" && {
  log "  (skipped — 2006-era exploit, no canonical upstream)"
}

begin "Privesc/Windows/SeLoadDriverPrivilege/*" && {
  log "  (skipped — frozen 2021 toolkit: Capcom.sys, EoPLoadDriver, etc.)"
}

begin "Privesc/Windows/SharpWSUS" && {
  git_export_replace "nettitude/SharpWSUS" "main" "$ROOT/Privesc/Windows/SharpWSUS"
}

begin "Privesc/Windows/Watson" && {
  log "  (skipped — rasta-mouse/Watson has no release; current copies are 2022 self-builds)"
}

begin "Privesc/Windows/accesschk.exe + pipelist.exe (Sysinternals)" && {
  fetch_to "https://live.sysinternals.com/accesschk.exe" \
           "$ROOT/Privesc/Windows/accesschk.exe" \
    && ok "  -> accesschk.exe" \
    || warn "Sysinternals accesschk download failed"
  fetch_to "https://live.sysinternals.com/pipelist.exe" \
           "$ROOT/Privesc/Windows/pipelist.exe" \
    && ok "  -> pipelist.exe" \
    || warn "Sysinternals pipelist download failed"
}

# Proxy ==================================================================

begin "Proxy/Squid/spose" && {
  git_export "aancw/spose" "master" "$ROOT/Proxy/Squid/spose"
}

# rcat ===================================================================

begin "rcat" && {
  log "  (skipped — xct/rcat has no releases; build from source)"
}

# Recon ==================================================================

begin "Recon/fscan" && {
  # fscan v2 ships three flavours: -lite, -nolocal, -web. We pick "nolocal"
  # because it keeps everything except the local vuln DB (smaller payload).
  release_asset_match "shadow1ng/fscan" 'fscan-nolocal_[0-9.]+_linux_x64$' \
                      "$ROOT/Recon/fscan/fscan" \
    && chmod +x "$ROOT/Recon/fscan/fscan"
  release_asset_match "shadow1ng/fscan" 'fscan-nolocal_[0-9.]+_windows_x64\.exe$' \
                      "$ROOT/Recon/fscan/fscan.exe"
  release_asset_match "shadow1ng/fscan" 'fscan-nolocal_[0-9.]+_windows_x32\.exe$' \
                      "$ROOT/Recon/fscan/fscan32.exe"
  release_asset_match "shadow1ng/fscan" 'fscan-nolocal_[0-9.]+_freebsd_x64$' \
                      "$ROOT/Recon/fscan/fscan_freebsd" \
    && chmod +x "$ROOT/Recon/fscan/fscan_freebsd"
}

begin "Recon/Nmap/nmap (static portable)" && {
  log "  (skipped — bundled static nmap has no canonical upstream URL)"
}

# RMI ====================================================================

begin "RMI/rmg-*.jar" && {
  url="$(_curl https://api.github.com/repos/qtc-de/remote-method-guesser/releases/latest \
        | grep -oE '"browser_download_url":[[:space:]]*"[^"]+rmg-[^"]+-jar-with-dependencies\.jar"' \
        | sed -E 's/.*"([^"]+)"$/\1/' | head -1)"
  if [[ -n "$url" ]]; then
    fname="$(basename "$url")"
    if fetch_to "$url" "$ROOT/RMI/$fname"; then
      find "$ROOT/RMI" -maxdepth 1 -name 'rmg-*-jar-with-dependencies.jar' ! -name "$fname" -delete 2>/dev/null
      ok "  -> $ROOT/RMI/$fname"
    fi
  else
    warn "could not resolve rmg latest asset"
  fi
}

# Shells =================================================================

begin "Shells/Linux/reverse-ssh + Shells/Windows/reverse-ssh*.exe" && {
  # Fahrj/reverse-ssh uses suffix-style names: reverse-sshx64, reverse-sshx64.exe,
  # upx_reverse-sshx64.exe. The user's local Linux binary is actually the x86
  # (statically linked, 32-bit) build, but we grab x64 since it's the standard.
  release_asset "Fahrj/reverse-ssh" "reverse-sshx64" "$ROOT/Shells/Linux/reverse-ssh" \
    && chmod +x "$ROOT/Shells/Linux/reverse-ssh"
  release_asset "Fahrj/reverse-ssh" "reverse-sshx64.exe"     "$ROOT/Shells/Windows/reverse-ssh.exe"
  release_asset "Fahrj/reverse-ssh" "upx_reverse-sshx64.exe" "$ROOT/Shells/Windows/upx_reverse-sshx64.exe"
}

begin "Shells/Windows/powercat" && {
  git_export "besimorhino/powercat" "master" "$ROOT/Shells/Windows/powercat"
}

# Steganography ==========================================================

begin "Steganography/stegsolve.jar" && {
  log "  (skipped — stegsolve.jar is on caesum.com; refresh manually if needed)"
}

# Windows / Powershell ===================================================

PD="$ROOT/Windows/Powershell"

begin "Powershell/DomainPasswordSpray.ps1"  && raw_file "dafthack/DomainPasswordSpray" "master" "DomainPasswordSpray.ps1" "$PD/DomainPasswordSpray.ps1"
begin "Powershell/MailSniper.ps1"           && raw_file "dafthack/MailSniper"           "master" "MailSniper.ps1"          "$PD/MailSniper.ps1"
begin "Powershell/PowerHuntShares.psm1"     && raw_file "NetSPI/PowerHuntShares"        "main"   "PowerHuntShares.psm1"    "$PD/PowerHuntShares.psm1"
begin "Powershell/PowerUpSQL.ps1"           && raw_file "NetSPI/PowerUpSQL"             "master" "PowerUpSQL.ps1"          "$PD/PowerUpSQL.ps1"
begin "Powershell/PsMapExec.ps1"            && raw_file "The-Viper-One/PsMapExec"       "main"   "PsMapExec.ps1"           "$PD/PsMapExec.ps1"
begin "Powershell/PSUpload.ps1"             && {
  # 14-line wrapper around uploadserver; not maintained in any canonical repo,
  # so we leave the local copy alone unless a fork of yours hosts it.
  log "  (skipped — local snippet wrapper around Densaugeo/uploadserver)"
}
begin "Powershell/SessionGopher.ps1"        && raw_file "Arvanaghi/SessionGopher"       "master" "SessionGopher.ps1"       "$PD/SessionGopher.ps1"

begin "Powershell/PowerUp.ps1 + PowerView.ps1 (PowerSploit dev branch)" && {
  raw_file "PowerShellMafia/PowerSploit" "dev" "Privesc/PowerUp.ps1" "$PD/PowerUp.ps1"
  raw_file "PowerShellMafia/PowerSploit" "dev" "Recon/PowerView.ps1" "$PD/PowerView.ps1"
}

begin "Powershell/PowerSploit-3.0.0" && {
  git_export_replace "PowerShellMafia/PowerSploit" "master" "$PD/PowerSploit-3.0.0"
}

begin "Powershell/Powermad"          && git_export "Kevin-Robertson/Powermad"        "master" "$PD/Powermad"
begin "Powershell/Invoke-TheHash"    && git_export "Kevin-Robertson/Invoke-TheHash"  "master" "$PD/Invoke-TheHash"
begin "Powershell/LAPSToolkit"       && git_export "leoloobeek/LAPSToolkit"          "master" "$PD/LAPSToolkit"
begin "Powershell/Invoke-DOSfuscation" && git_export "danielbohannon/Invoke-DOSfuscation" "master" "$PD/Invoke-DOSfuscation"

begin "Powershell/FullBypass" && {
  log "  (skipped — no canonical upstream confirmed; leaving existing local copy)"
}

begin "Powershell/PowerSharpBinaries (from S3cur3Th1sSh1t/PowerSharpPack)" && {
  git_export_replace "S3cur3Th1sSh1t/PowerSharpPack" "master" \
                     "$PD/PowerSharpBinaries" "PowerSharpBinaries"
}

begin "Powershell/Enable-Privilege.ps1, EnableAllTokenPrivs.ps1, Invoke-Clipboard.ps1, PsBypassCLM.exe" && {
  log "  (skipped — blog-snippet helpers; PsBypassCLM.exe is a frozen build)"
}

# Windows / other ========================================================

begin "Windows/RunAs/RunasCs.exe (+ net2)" && {
  # Latest RunasCs.zip bundles both .NET4 (RunasCs.exe) and .NET2 (RunasCs_net2.exe).
  zip="$TMP_BASE/runas.zip"
  if release_asset "antonioCoco/RunasCs" "RunasCs.zip" "$zip"; then
    td="$TMP_BASE/runas"; mkdir -p "$td"; unzip -oq "$zip" -d "$td"
    exe="$(find "$td" -name 'RunasCs.exe' | head -1)"
    [[ -n "$exe" ]] && cp -f "$exe" "$ROOT/Windows/RunAs/RunasCs.exe" && ok "  -> RunasCs.exe"
    net2="$(find "$td" -name 'RunasCs_net2.exe' | head -1)"
    [[ -n "$net2" ]] && cp -f "$net2" "$ROOT/Windows/RunAs/RunasCs_net2.exe" && ok "  -> RunasCs_net2.exe"
  fi
}

begin "Windows/SMB/Snaffler.exe" && {
  release_asset_match "SnaffCon/Snaffler" 'Snaffler\.exe$' \
                      "$ROOT/Windows/SMB/Snaffler.exe"
}

begin "Windows/Spraying/spraykatz" && {
  git_export "aas-n/spraykatz" "master" "$ROOT/Windows/Spraying/spraykatz"
}

# Wordlists ==============================================================

begin "Wordlists/username-anarchy" && {
  git_export "urbanadventurer/username-anarchy" "master" "$ROOT/Wordlists/username-anarchy"
}

# ---------- summary ----------

if [[ "$MODE" != "list" ]]; then
  echo
  log "Done. ${COUNT_OK} ok, ${COUNT_WARN} warning(s)."
  if (( ${#FAILED[@]} > 0 )); then
    printf '%sIssues:%s\n' "$C_WARN" "$C_RESET"
    printf '  %s\n' "${FAILED[@]}"
  fi
fi
