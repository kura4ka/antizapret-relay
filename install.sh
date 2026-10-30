#!/usr/bin/env bash
# This file is compiled into install.sh by tools/build.py.
set -Eeuo pipefail
umask 077
VERSION=0.3.2
STATE_DIR=/etc/antizapret-relay
APP=/usr/local/sbin/antizapret-relay
WG_IF=az-relay
WG_CONF=/etc/wireguard/az-relay.conf
AZ_DIR=/root/antizapret
log() { printf '[antizapret-relay] %s\n' "$*"; }
die() { printf '[antizapret-relay] ERROR: %s\n' "$*" >&2; exit 1; }
require_root() { [[ $EUID -eq 0 ]] || die 'Run as root (sudo bash install.sh ...).'; }
require_commands() {
    local command_name
    for command_name in "$@"; do
        command -v "$command_name" >/dev/null || die "Required command: $command_name";
    done
}
install_dependencies() {
    require_root
    [[ -d /run/systemd/system ]] || die 'A Linux host booted with systemd is required.'
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ ${ID:-} == debian || ${ID:-} == ubuntu ]] || die 'Supported: Debian and Ubuntu.'
    if ! command -v wg >/dev/null || ! command -v wg-quick >/dev/null || ! command -v ip >/dev/null || ! command -v iptables >/dev/null || ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools iptables iproute2 python3 curl
    fi
    require_commands wg wg-quick ip iptables python3 curl systemctl flock
}
validate_ipv4() {
    python3 - "$1" <<'PY'
import ipaddress, sys
try:
    ipaddress.IPv4Address(sys.argv[1])
except ValueError:
    sys.exit('A numeric IPv4 address is required.')
PY
}
validate_public_ipv4() {
    python3 - "$1" <<'PY'
import ipaddress, sys
try:
    address = ipaddress.IPv4Address(sys.argv[1])
    if not address.is_global or address.is_multicast:
        raise ValueError()
except ValueError:
    sys.exit('A public, numeric IPv4 address is required.')
PY
}
validate_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1024 && 10#$1 <= 65535 )); }
install_self() {
    [[ -f $SCRIPT_FILE ]] || die 'Download install.sh to a file before running it.'
    if [[ $(readlink -f "$SCRIPT_FILE") != "$APP" ]]; then
        install -m 0755 "$SCRIPT_FILE" "$APP"
    fi
    install -d -m 0700 "$STATE_DIR"
    # Older installations called firewall for both roles from each hook. Scope
    # those hooks before a second role is added, without restarting tunnels.
    config_tool scope-hooks "$STATE_DIR" "$WG_CONF" "$APP" /etc/systemd/system/antizapret.service.d
    systemctl daemon-reload
}
ipt_add() {
    local table=$1 chain=$2; shift 2
    iptables -w -t "$table" -C "$chain" "$@" 2>/dev/null || iptables -w -t "$table" -I "$chain" 1 "$@"
}
ipt_del() {
    local table=$1 chain=$2; shift 2
    while iptables -w -t "$table" -C "$chain" "$@" 2>/dev/null; do
        iptables -w -t "$table" -D "$chain" "$@"
    done
}


# Embedded configuration validator; no files are downloaded at runtime.
config_tool() {
    python3 - "$@" <<'AZ_RELAY_CONFIG_PY'
"""Validated data/configuration operations embedded into the relay installer."""
import base64
import ipaddress
import json
import os
import re
import shlex
import stat
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(ValueError):
    pass


FIELDS = (
    "endpoint", "server_public_key", "antizapret_private_key",
    "antizapret_address", "vpn_private_key", "vpn_address",
)
MANAGED = {"WARP_PROTECTION", "WARP_MTU"}
for _prefix in ("ANTIZAPRET", "VPN"):
    MANAGED.update({_prefix + "_WARP"})
    MANAGED.update(_prefix + "_WARP_" + suffix for suffix in (
        "PRIVATE_KEY", "PUBLIC_KEY", "ENDPOINT", "ADDRESS"))
ASSIGNMENT = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("Duplicate JSON field.")
        result[key] = value
    return result


def read_json(path):
    try:
        if Path(path).stat().st_size > 1024 * 1024:
            raise ConfigError("JSON input is too large.")
        return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_json_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError("Cannot read valid JSON input.") from exc


def key_value(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", value):
        raise ConfigError("Invalid WireGuard key.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ConfigError("Invalid WireGuard key.") from exc
    if len(decoded) != 32 or not any(decoded) or base64.b64encode(decoded).decode("ascii") != value:
        raise ConfigError("Invalid WireGuard key.")
    return value


def _private_scalar(value):
    # X25519 clamps these bits; different encodings can represent the same key.
    scalar = bytearray(base64.b64decode(value, validate=True))
    scalar[0] &= 248
    scalar[31] = (scalar[31] & 127) | 64
    return bytes(scalar)


def endpoint_value(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9.]+:[0-9]{1,5}", value):
        raise ConfigError("Endpoint must be a public numeric IPv4 address and UDP port.")
    address, port = value.rsplit(":", 1)
    try:
        parsed = ipaddress.IPv4Address(address)
    except ValueError as exc:
        raise ConfigError("Invalid endpoint IPv4 address.") from exc
    if not parsed.is_global or parsed.is_multicast or not 1 <= int(port) <= 65535:
        raise ConfigError("Endpoint must be a public numeric IPv4 address and UDP port.")
    return str(parsed) + ":" + str(int(port))


def address_value(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9.]+/32", value):
        raise ConfigError("Tunnel address must be an RFC1918 IPv4 /32.")
    try:
        interface = ipaddress.IPv4Interface(value)
    except ValueError as exc:
        raise ConfigError("Invalid tunnel address.") from exc
    if not any(interface.ip in network for network in PRIVATE_NETWORKS):
        raise ConfigError("Tunnel address must be an RFC1918 IPv4 /32.")
    if interface.ip in ipaddress.ip_network("10.28.0.0/14") or interface.ip in ipaddress.ip_network("172.28.0.0/14"):
        raise ConfigError("Tunnel address overlaps the AntiZapret client or fake address range.")
    if int(interface.ip) & 255 in (0, 255):
        raise ConfigError("Tunnel address must be a host address within its transit /24.")
    return str(interface)


def validate_bundle(path):
    bundle = read_json(path)
    if not isinstance(bundle, dict) or set(bundle) != {"version", *FIELDS}:
        raise ConfigError("Unexpected client bundle fields.")
    if type(bundle["version"]) is not int or bundle["version"] != 1:
        raise ConfigError("Unsupported client bundle version.")
    if endpoint_value(bundle["endpoint"]) != bundle["endpoint"]:
        raise ConfigError("Endpoint must use canonical numeric notation.")
    for field in ("server_public_key", "antizapret_private_key", "vpn_private_key"):
        key_value(bundle[field])
    for field in ("antizapret_address", "vpn_address"):
        address_value(bundle[field])
    if _private_scalar(bundle["antizapret_private_key"]) == _private_scalar(bundle["vpn_private_key"]):
        raise ConfigError("The two client interfaces require different WireGuard keys.")
    first = ipaddress.ip_interface(bundle["antizapret_address"])
    second = ipaddress.ip_interface(bundle["vpn_address"])
    if first.ip == second.ip or ipaddress.ip_network(str(first.ip) + "/24", strict=False) != ipaddress.ip_network(str(second.ip) + "/24", strict=False):
        raise ConfigError("Client tunnel addresses must be distinct hosts of one transit /24.")
    return [bundle[field] for field in FIELDS]


def check_routes(bundle_path, routes_path):
    validated = validate_bundle(bundle_path)
    candidate = ipaddress.ip_network(validated[3].split("/")[0] + "/24", strict=False)
    routes = read_json(routes_path)
    if not isinstance(routes, list):
        raise ConfigError("Invalid IPv4 route inventory.")
    for route in routes:
        if not isinstance(route, dict):
            raise ConfigError("Invalid IPv4 route inventory.")
        destination = route.get("dst", "default")
        if destination == "default":
            continue
        try:
            existing = ipaddress.IPv4Network(destination, strict=False)
        except (ValueError, TypeError) as exc:
            raise ConfigError("Invalid destination in IPv4 route inventory.") from exc
        if candidate.overlaps(existing):
            raise ConfigError("Transit subnet overlaps an existing IPv4 route; generate a bundle with a different server --subnet.")


def normalize_domain(value):
    if not isinstance(value, str):
        raise ConfigError("Invalid domain.")
    if any(character in value for character in ("\r", "\n", "\x00")):
        raise ConfigError("Domain must occupy one line.")
    value = value.strip()
    if "://" in value:
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in ("http", "https") or parsed.username or parsed.password or parsed.port is not None or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
                raise ConfigError("Use a domain or an HTTP(S) origin without a path, port or credentials.")
            value = parsed.hostname or ""
        except ValueError as exc:
            raise ConfigError("Invalid domain URL.") from exc
    value = value.rstrip(".").lower()
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise ConfigError("Invalid international domain.") from exc
    labels = ascii_value.split(".")
    if len(labels) < 2 or len(ascii_value) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
    ) or labels[-1].isdigit():
        raise ConfigError("Use a complete domain with at least two valid labels; wildcards are not accepted.")
    try:
        ipaddress.ip_address(ascii_value)
    except ValueError:
        return ascii_value
    raise ConfigError("Use a domain rather than an IP address.")


def _read_lines(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConfigError("Cannot read configuration file.") from exc
    if "\x00" in text:
        raise ConfigError("Invalid configuration file.")
    return text.splitlines(keepends=True)


def atomic_write(path, content, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise ConfigError("Refusing to replace a symbolic link.")
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
        with os.fdopen(descriptor, "wb") as handle:
            os.chmod(temporary, mode)
            handle.write(content.encode("utf-8") if isinstance(content, str) else content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise ConfigError("Cannot update configuration file atomically.") from exc
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _require_root_owned_regular(path):
    try:
        metadata = Path(path).lstat()
    except OSError as exc:
        raise ConfigError("Cannot inspect local role configuration.") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ConfigError("Refusing to migrate a symbolic link.")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise ConfigError("Role configuration must be a root-owned regular file.")
    return metadata


def scope_hooks(state_dir, wg_conf, app, dropin_dir):
    """Migrate only exact installer-owned legacy hooks, without restarting services."""
    if not app.startswith("/") or any(character in app for character in ("\r", "\n", "\x00")):
        raise ConfigError("Invalid installed application path.")
    state_dir, dropin_dir = Path(state_dir), Path(dropin_dir)
    candidates = []
    if (state_dir / "server.conf").exists() or (state_dir / "server.conf").is_symlink():
        _require_root_owned_regular(state_dir / "server.conf")
        candidates.extend((
            (Path(wg_conf), {
                f"PostUp = {app} firewall up": f"PostUp = {app} firewall up server",
                f"PostDown = {app} firewall down": f"PostDown = {app} firewall down server",
            }),
            (dropin_dir / "90-antizapret-relay-server.conf", {
                f"ExecStartPost=-{app} firewall up": f"ExecStartPost=-{app} firewall up server",
                f"ExecStartPost={app} firewall up": f"ExecStartPost={app} firewall up server",
            }),
        ))
    if (state_dir / "client.conf").exists() or (state_dir / "client.conf").is_symlink():
        _require_root_owned_regular(state_dir / "client.conf")
        candidates.append((dropin_dir / "90-antizapret-relay-client.conf", {
            f"ExecStartPost={app} firewall up": f"ExecStartPost={app} firewall up client",
        }))
    updates = []
    for path, substitutions in candidates:
        if not path.exists() and not path.is_symlink():
            continue
        metadata = _require_root_owned_regular(path)
        try:
            original = path.read_bytes()
        except OSError as exc:
            raise ConfigError("Cannot read local role configuration.") from exc
        replacements = {old.encode("utf-8"): new.encode("utf-8") for old, new in substitutions.items()}
        lines = []
        for line in original.splitlines(keepends=True):
            body = line.rstrip(b"\r\n")
            lines.append(replacements.get(body, body) + line[len(body):])
        migrated = b"".join(lines)
        if migrated != original:
            updates.append((path, migrated, stat.S_IMODE(metadata.st_mode)))
    # Validate every target before the first write, especially symlink targets.
    for path, content, mode in updates:
        atomic_write(path, content, mode=mode)


def _assignments(lines, names):
    result = {}
    for number, line in enumerate(lines):
        match = ASSIGNMENT.fullmatch(line.rstrip("\r\n"))
        if match and match.group(1) in names:
            key = match.group(1)
            if key in result:
                raise ConfigError("Duplicate managed variable in setup.")
            result[key] = (number, line)
    return result


def _validate_changes(changes):
    if not isinstance(changes, dict) or not changes or not set(changes).issubset(MANAGED):
        raise ConfigError("Unexpected managed setup variables.")
    for name, value in changes.items():
        if not isinstance(value, str):
            raise ConfigError("Managed setup values must be strings.")
        if name.endswith(("PRIVATE_KEY", "PUBLIC_KEY")):
            key_value(value)
        elif name.endswith("ENDPOINT"):
            if endpoint_value(value) != value:
                raise ConfigError("Endpoint must use canonical numeric notation.")
        elif name.endswith("ADDRESS"):
            address_value(value)
        elif name == "ANTIZAPRET_WARP" and value != "4":
            raise ConfigError("AntiZapret relay requires custom domain mode 4.")
        elif name == "VPN_WARP" and value != "3":
            raise ConfigError("Full VPN relay requires custom domain mode 3.")
        elif name == "WARP_PROTECTION" and value != "y":
            raise ConfigError("Relay requires WARP protection.")
        elif name == "WARP_MTU" and (not value.isdecimal() or not 1280 <= int(value) <= 1420):
            raise ConfigError("Invalid WARP MTU.")


def apply_setup(setup_path, backup_path, changes_path):
    if Path(backup_path).exists():
        raise ConfigError("Setup backup already exists; restore it before applying again.")
    changes = read_json(changes_path)
    _validate_changes(changes)
    lines = _read_lines(setup_path)
    assignments = _assignments(lines, changes)
    original = {key: assignments[key][1] if key in assignments else None for key in changes}
    backup = {"version": 1, "original": original, "applied": changes}
    updated = list(lines)
    for key, value in changes.items():
        replacement = key + "=" + shlex.quote(value) + "\n"
        if key in assignments:
            updated[assignments[key][0]] = replacement
        else:
            if updated and not updated[-1].endswith("\n"):
                updated[-1] += "\n"
            updated.append(replacement)
    atomic_write(backup_path, json.dumps(backup, ensure_ascii=True, indent=2) + "\n")
    try:
        atomic_write(setup_path, "".join(updated))
    except Exception:
        Path(backup_path).unlink()
        raise


def restore_setup(setup_path, backup_path, check_only=False):
    backup = read_json(backup_path)
    if not isinstance(backup, dict) or set(backup) != {"version", "original", "applied"} or type(backup["version"]) is not int or backup["version"] != 1:
        raise ConfigError("Invalid setup backup.")
    changes = backup["applied"]
    _validate_changes(changes)
    original = backup["original"]
    if not isinstance(original, dict) or set(original) != set(changes):
        raise ConfigError("Invalid setup backup variables.")
    for key, line in original.items():
        if line is not None and (not isinstance(line, str) or len(line.splitlines()) != 1 or not ASSIGNMENT.fullmatch(line.rstrip("\r\n")) or ASSIGNMENT.fullmatch(line.rstrip("\r\n")).group(1) != key):
            raise ConfigError("Invalid original setup value.")
    lines = _read_lines(setup_path)
    assignments = _assignments(lines, changes)
    for key, value in changes.items():
        current = assignments.get(key)
        applied_line = key + "=" + shlex.quote(value)
        original_line = original[key].rstrip("\r\n") if original[key] is not None else None
        current_line = current[1].rstrip("\r\n") if current else None
        if current_line not in (applied_line, original_line):
            raise ConfigError("Managed setup values changed after installation; restore requires resolving those changes first.")
    updated = []
    def append_line(line):
        if updated and not updated[-1].endswith("\n"):
            updated[-1] += "\n"
        updated.append(line)
    for line in lines:
        match = ASSIGNMENT.fullmatch(line.rstrip("\r\n"))
        key = match.group(1) if match else None
        if key in original:
            if original[key] is not None:
                append_line(original[key])
        else:
            append_line(line)
    for key, line in original.items():
        if key not in assignments and line is not None:
            append_line(line)
    if not check_only:
        atomic_write(setup_path, "".join(updated))


def domains(operation, path, value=None):
    target = Path(path)
    lines = _read_lines(path) if target.exists() else []
    known = []
    for line in lines:
        entry = line.strip()
        if entry and not entry.startswith("#"):
            known.append(normalize_domain(entry))
    if operation == "domain-list":
        return sorted(set(known))
    domain = normalize_domain(value)
    if operation == "domain-add":
        if domain not in known:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(domain + "\n")
    elif operation == "domain-drop":
        lines = [line for line in lines if not line.strip() or line.lstrip().startswith("#") or normalize_domain(line.strip()) != domain]
    else:
        raise ConfigError("Unknown domain operation.")
    atomic_write(path, "".join(lines))
    return []


EXCLUSIONS_BEGIN = '# BEGIN ANTIZAPRET RELAY DEFAULT WARP EXCLUSIONS'
EXCLUSIONS_END = '# END ANTIZAPRET RELAY DEFAULT WARP EXCLUSIONS'
_NATIVE_DOMAIN_CUT = set("]_~:/?#[@!$&'()*+,;=")


def _native_warp_entries(text, strict=True):
    """Read the host-list syntax used by upstream parse.sh, without evaluating it."""
    result = set()
    for line in text.splitlines():
        value = re.sub(r'[\r \t\v\f]+', '', line)
        if value == '.':
            if strict:
                raise ConfigError('A bundled catch-all WARP rule cannot be excluded by the native exclude parser.')
            continue
        if not value or not value[0].isalnum():
            continue
        value = value[:next((i for i, char in enumerate(value) if char in _NATIVE_DOMAIN_CUT), len(value))].lower()
        if value.endswith('.'):
            value = value[:-1]
        labels = value.split('.')
        if not value or len(value) > 253 or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
            for label in labels
        ) or labels[-1].isdigit():
            if strict:
                raise ConfigError('Invalid domain in the bundled WARP defaults.')
            continue
        result.add(value)
    return result


def _exclusion_file(path):
    path = Path(path)
    if path.is_symlink():
        raise ConfigError('Refusing to change an exclusion-list symbolic link.')
    if not path.exists():
        return False, '', 0o600
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            raise ConfigError('Exclusion input must be a regular file smaller than 1 MiB.')
        text = path.read_bytes().decode('utf-8')
    except (OSError, UnicodeError) as exc:
        raise ConfigError('Cannot read the native exclusion list.') from exc
    if '\x00' in text:
        raise ConfigError('Invalid exclusion list.')
    return True, text, stat.S_IMODE(metadata.st_mode)


def _render_default_exclusions(original, added):
    if not added:
        return original
    separator = '' if not original or original.endswith('\n') else '\n'
    return original + separator + EXCLUSIONS_BEGIN + '\n' + ''.join(domain + '\n' for domain in added) + EXCLUSIONS_END + '\n'


def prepare_default_exclusions(download_dir, target_path, output_path, metadata_path):
    """Stage the exclusion change and an exact snapshot before altering a live file."""
    paths = [Path(path) for path in (target_path, output_path, metadata_path)]
    if len({str(path.resolve()) for path in paths}) != len(paths):
        raise ConfigError('Exclusion target, staged output and backup must be distinct files.')
    for path in paths:
        if path.is_symlink():
            raise ConfigError('Refusing exclusion staging through a symbolic link.')
    if any(path.exists() for path in paths[1:]):
        raise ConfigError('Exclusion staging output or backup already exists.')
    default_files = sorted(Path(download_dir).glob('*include-warp-hosts.txt'))
    if not default_files:
        raise ConfigError('Bundled WARP include files are missing; exclusions were not changed.')
    if {str(path.resolve()) for path in default_files}.intersection(str(path.resolve()) for path in paths):
        raise ConfigError('Bundled input files cannot be used as exclusion staging targets.')
    defaults = set()
    for path in default_files:
        exists, text, _ = _exclusion_file(path)
        if not exists:
            raise ConfigError('A bundled WARP include file disappeared.')
        defaults.update(_native_warp_entries(text))
    exists, original, mode = _exclusion_file(target_path)
    if mode > 0o777:
        raise ConfigError('Exclusion lists with special permission bits require manual review.')
    if EXCLUSIONS_BEGIN in original or EXCLUSIONS_END in original:
        raise ConfigError('A relay default-exclusion block already exists; preserve it before applying again.')
    added = sorted(defaults - _native_warp_entries(original, strict=False))
    metadata = {'version': 1, 'target': str(Path(target_path).resolve()),
                'existed': exists, 'original': original, 'mode': mode, 'added': added}
    serialized = json.dumps(metadata, ensure_ascii=True, indent=2) + '\n'
    if len(serialized.encode('utf-8')) > 1024 * 1024:
        raise ConfigError('Exclusion backup is too large.')
    atomic_write(metadata_path, serialized)
    try:
        atomic_write(output_path, _render_default_exclusions(original, added), mode=mode)
    except Exception:
        Path(metadata_path).unlink()
        raise


def _default_exclusion_metadata(target_path, metadata_path):
    if Path(metadata_path).is_symlink():
        raise ConfigError('Refusing a symbolic-link exclusion backup.')
    metadata = read_json(metadata_path)
    fields = {'version', 'target', 'existed', 'original', 'mode', 'added'}
    if not isinstance(metadata, dict) or set(metadata) != fields or type(metadata['version']) is not int or metadata['version'] != 1:
        raise ConfigError('Invalid default-exclusion backup.')
    if metadata['target'] != str(Path(target_path).resolve()) or type(metadata['existed']) is not bool:
        raise ConfigError('Exclusion backup belongs to another target.')
    original, mode, added = metadata['original'], metadata['mode'], metadata['added']
    if not isinstance(original, str) or '\x00' in original or EXCLUSIONS_BEGIN in original or EXCLUSIONS_END in original:
        raise ConfigError('Invalid original exclusion list in backup.')
    if type(mode) is not int or not 0 <= mode <= 0o777:
        raise ConfigError('Invalid original exclusion-list mode.')
    if not metadata['existed'] and (original or mode != 0o600):
        raise ConfigError('Invalid snapshot of a missing exclusion file.')
    if not isinstance(added, list) or any(not isinstance(domain, str) for domain in added):
        raise ConfigError('Invalid automatically excluded domains.')
    if added != sorted(set(added)) or any(_native_warp_entries(domain) != {domain} for domain in added):
        raise ConfigError('Invalid automatically excluded domains.')
    if set(added).intersection(_native_warp_entries(original, strict=False)):
        raise ConfigError('Default-exclusion backup claims pre-existing user entries.')
    return metadata


def apply_default_exclusions(target_path, metadata_path):
    metadata = _default_exclusion_metadata(target_path, metadata_path)
    exists, current, mode = _exclusion_file(target_path)
    proposed = _render_default_exclusions(metadata['original'], metadata['added'])
    expected_exists = metadata['existed'] or bool(metadata['added'])
    if exists == expected_exists and current == proposed and (not exists or mode == metadata['mode']):
        return
    if exists != metadata['existed'] or current != metadata['original'] or exists and mode != metadata['mode']:
        raise ConfigError('The native exclusion list changed after staging; preserve those changes and retry.')
    if metadata['added']:
        atomic_write(target_path, proposed, mode=metadata['mode'])


def restore_default_exclusions(target_path, metadata_path, rollback=False, check_only=False):
    metadata = _default_exclusion_metadata(target_path, metadata_path)
    exists, current, mode = _exclusion_file(target_path)
    original = metadata['original']
    proposed = _render_default_exclusions(original, metadata['added'])
    exact = current == proposed or current == original
    if rollback and not exact:
        raise ConfigError('Exclusion list changed during installation; retain the backup for recovery.')
    if exact:
        updated = original
        delete = not metadata['existed']
        mode = metadata['mode']
    else:
        lines = current.splitlines(keepends=True)
        begins = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == EXCLUSIONS_BEGIN]
        ends = [i for i, line in enumerate(lines) if line.rstrip('\r\n') == EXCLUSIONS_END]
        if not begins and not ends:
            return  # The user already removed the managed block.
        if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
            raise ConfigError('Default-exclusion block markers changed; retain the backup and repair the block first.')
        start, end = begins[0], ends[0]
        owned = set(metadata['added'])
        retained = [line for line in lines[start + 1:end] if line.rstrip('\r\n') not in owned]
        updated = ''.join(lines[:start] + retained + lines[end + 1:])
        delete = not metadata['existed'] and not updated
    if check_only:
        return
    if delete:
        if exists:
            Path(target_path).unlink()
    elif not exists or updated != current:
        atomic_write(target_path, updated, mode=mode)


GEMINI_DOMAINS = ('gemini.google.com', 'generativelanguage.googleapis.com')


def _render_gemini(original, added):
    if not added:
        return original
    newline = '\r\n' if '\r\n' in original and '\n' not in original.replace('\r\n', '') else '\n'
    separator = '' if not original or original.endswith('\n') else newline
    return original + separator + ''.join(domain + newline for domain in added)


def prepare_gemini(target_path, metadata_path):
    """Stage an optional Gemini append without changing the native include list."""
    target, backup = Path(target_path), Path(metadata_path)
    if target.resolve() == backup.resolve():
        raise ConfigError('Gemini include target and transaction backup must be distinct files.')
    if target.is_symlink() or backup.is_symlink():
        raise ConfigError('Refusing a symbolic-link Gemini include target or backup.')
    if backup.exists():
        raise ConfigError('Gemini transaction backup already exists; preserve it before retrying.')
    existed, original, mode = _exclusion_file(target)
    if mode > 0o777:
        raise ConfigError('Native include lists with special permission bits require manual review.')
    known = _native_warp_entries(original, strict=False)
    added = [domain for domain in GEMINI_DOMAINS if domain not in known]
    metadata = {'version': 1, 'target': str(target.resolve()), 'existed': existed,
                'original': original, 'mode': mode, 'added': added}
    serialized = json.dumps(metadata, ensure_ascii=True, indent=2) + '\n'
    if len(serialized.encode('utf-8')) > 1024 * 1024:
        raise ConfigError('Gemini transaction backup is too large.')
    atomic_write(backup, serialized)
    return len(added)


def _gemini_metadata(target_path, metadata_path):
    target, backup = Path(target_path), Path(metadata_path)
    if target.resolve() == backup.resolve() or backup.is_symlink():
        raise ConfigError('Invalid Gemini transaction backup path.')
    metadata = read_json(backup)
    fields = {'version', 'target', 'existed', 'original', 'mode', 'added'}
    if not isinstance(metadata, dict) or set(metadata) != fields or type(metadata['version']) is not int or metadata['version'] != 1:
        raise ConfigError('Invalid Gemini transaction backup.')
    if metadata['target'] != str(target.resolve()) or type(metadata['existed']) is not bool:
        raise ConfigError('Gemini transaction backup belongs to another target.')
    original, mode, added = metadata['original'], metadata['mode'], metadata['added']
    if not isinstance(original, str) or '\x00' in original:
        raise ConfigError('Invalid original native include list in Gemini backup.')
    if type(mode) is not int or not 0 <= mode <= 0o777:
        raise ConfigError('Invalid original native include-list mode.')
    if not metadata['existed'] and (original or mode != 0o600):
        raise ConfigError('Invalid snapshot of a missing native include list.')
    expected = [domain for domain in GEMINI_DOMAINS if domain not in _native_warp_entries(original, strict=False)]
    if added != expected:
        raise ConfigError('Gemini transaction backup contains unexpected domain changes.')
    return metadata


def apply_gemini(target_path, metadata_path):
    metadata = _gemini_metadata(target_path, metadata_path)
    existed, current, mode = _exclusion_file(target_path)
    proposed = _render_gemini(metadata['original'], metadata['added'])
    expected_exists = metadata['existed'] or bool(metadata['added'])
    mode_matches = os.name == 'nt' or mode == metadata['mode']
    if existed == expected_exists and current == proposed and (not existed or mode_matches):
        return
    if existed != metadata['existed'] or current != metadata['original'] or existed and not mode_matches:
        raise ConfigError('Native include list changed after staging Gemini; preserve those changes and retry.')
    if metadata['added']:
        atomic_write(target_path, proposed, mode=metadata['mode'])


def rollback_gemini(target_path, metadata_path):
    metadata = _gemini_metadata(target_path, metadata_path)
    existed, current, mode = _exclusion_file(target_path)
    original = metadata['original']
    proposed = _render_gemini(original, metadata['added'])
    if current not in (original, proposed) or existed and os.name != 'nt' and mode != metadata['mode']:
        raise ConfigError('Native include list changed during Gemini setup; retain the transaction backup for recovery.')
    if not metadata['existed']:
        if existed:
            Path(target_path).unlink()
    elif not existed or current != original:
        atomic_write(target_path, original, mode=metadata['mode'])


def main(argv):
    try:
        if not argv:
            raise ConfigError("Missing configuration operation.")
        operation, *args = argv
        if operation == "validate-bundle" and len(args) == 1:
            print("\n".join(validate_bundle(args[0])))
        elif operation == "check-routes" and len(args) == 2:
            check_routes(*args)
        elif operation == "scope-hooks" and len(args) == 4:
            scope_hooks(*args)
        elif operation == 'prepare-default-exclusions' and len(args) == 4:
            prepare_default_exclusions(*args)
        elif operation == 'apply-default-exclusions' and len(args) == 2:
            apply_default_exclusions(*args)
        elif operation == 'restore-default-exclusions' and len(args) == 2:
            restore_default_exclusions(*args)
        elif operation == 'rollback-default-exclusions' and len(args) == 2:
            restore_default_exclusions(*args, rollback=True)
        elif operation == 'check-default-exclusions' and len(args) == 2:
            restore_default_exclusions(*args, check_only=True)
        elif operation == 'prepare-gemini' and len(args) == 2:
            print(prepare_gemini(*args))
        elif operation == 'gemini-domains' and not args:
            print('\n'.join(GEMINI_DOMAINS))
        elif operation == 'apply-gemini' and len(args) == 2:
            apply_gemini(*args)
        elif operation == 'rollback-gemini' and len(args) == 2:
            rollback_gemini(*args)
        elif operation == "normalize-domain" and len(args) == 1:
            print(normalize_domain(args[0]))
        elif operation == "apply" and len(args) == 3:
            apply_setup(*args)
        elif operation == "restore" and len(args) == 2:
            restore_setup(*args)
        elif operation == "check-restore" and len(args) == 2:
            restore_setup(*args, check_only=True)
        elif operation in ("domain-add", "domain-drop") and len(args) == 2:
            domains(operation, *args)
        elif operation == "domain-list" and len(args) == 1:
            for domain in domains(operation, *args):
                print(domain)
        else:
            raise ConfigError("Invalid configuration operation or arguments.")
    except ConfigError as exc:
        print("Configuration error: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
AZ_RELAY_CONFIG_PY
}


# Optional domain presets use the normal user-owned AntiZapret include list.
CLIENT_INCLUDES=/root/antizapret/config/include-warp-hosts.txt

gemini_domains() {
    config_tool gemini-domains
}

gemini_enable() (
    [[ -f $STATE_DIR/client.conf ]] || die 'Install the client role before enabling a domain preset.'
    client_compatibility
    local preset_stage added
    preset_stage=$(mktemp -d)
    trap 'rm -rf -- "$preset_stage"' EXIT
    added=$(config_tool prepare-gemini "$CLIENT_INCLUDES" "$preset_stage/gemini.before.json")
    [[ $added =~ ^[0-9]+$ ]] || die 'Could not prepare the Gemini domain list.'
    if [[ $added == 0 ]]; then
        log 'Gemini website and API domains are already in the native include list. Existing exclusions still apply.'
        return 0
    fi
    trap 'gemini_enable_rollback "$preset_stage"' ERR
    config_tool apply-gemini "$CLIENT_INCLUDES" "$preset_stage/gemini.before.json"
    (trap - ERR; cd "$AZ_DIR" && ./parse.sh)
    trap - ERR
    log 'Added Gemini website and API domains to /root/antizapret/config/include-warp-hosts.txt and applied the lists.'
    log 'Existing exclusions are kept. Remove any matching Gemini exclusions if you want these domains to use the donor.'
)

gemini_enable_rollback() {
    local preset_stage=$1
    trap - ERR
    if config_tool rollback-gemini "$CLIENT_INCLUDES" "$preset_stage/gemini.before.json"; then
        (cd "$AZ_DIR" && ./parse.sh) || log 'Could not reload the restored list; rerun /root/antizapret/parse.sh after resolving the error.'
    else
        # Do not discard the only recovery snapshot when the user edited the list.
        trap - EXIT
        log "Gemini recovery snapshot is kept at $preset_stage/gemini.before.json."
    fi
    die 'Could not apply the Gemini preset. Existing donor settings and keys are kept.'
}

preset_command() {
    [[ $# -eq 1 && $1 == gemini ]] || die 'Usage: antizapret-relay preset gemini'
    gemini_enable
}

# Exit VPS (Server 2). This file is concatenated into install.sh by build.py.
SERVER_BUNDLE=/root/antizapret-relay-donor.json

server_load_state() {
    [[ -f "$STATE_DIR/server.conf" && ! -L "$STATE_DIR/server.conf" ]] || die 'Exit server is not installed.'
    [[ $(stat -c %u "$STATE_DIR/server.conf") == 0 ]] || die 'Server state must be owned by root.'
    # This is a root-owned file generated with printf %q, never a downloaded bundle.
    # shellcheck disable=SC1091
    source "$STATE_DIR/server.conf"
    [[ ${RELAY_UPLINK:-} =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]] || die 'Invalid uplink in server state.'
    validate_port "${RELAY_PORT:-}"
    validate_ipv4 "${RELAY_SERVER_IP:-}"
    validate_ipv4 "${RELAY_ANTIZAPRET_IP:-}"
    validate_ipv4 "${RELAY_VPN_IP:-}"
}

server_iptables_remove() {
    local table=$1 chain=$2
    shift 2
    while iptables -w -t "$table" -C "$chain" "$@" 2>/dev/null; do
        iptables -w -t "$table" -D "$chain" "$@"
    done
}

server_firewall() {
    require_root
    local action=${1:-}
    [[ $action == up || $action == down ]] || die 'Usage: firewall up|down'
    [[ -f "$STATE_DIR/server.conf" ]] || return 0
    server_load_state

    # Keep tunnel traffic closed while rebuilding our chains. If any command
    # fails, these guards stay in place until a successful retry or uninstall.
    local guard_chain guard_direction guard_comment
    for guard_chain in INPUT FORWARD; do
        guard_direction=-i
        guard_comment="az-relay-rebuild-$guard_chain-in"
        if [[ $action == up ]] && ! iptables -w -C "$guard_chain" "$guard_direction" "$WG_IF" -m comment --comment "$guard_comment" -j DROP 2>/dev/null; then
            iptables -w -I "$guard_chain" 1 "$guard_direction" "$WG_IF" -m comment --comment "$guard_comment" -j DROP
        fi
    done
    if [[ $action == up ]] && ! iptables -w -C FORWARD -o "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-out -j DROP 2>/dev/null; then
        iptables -w -I FORWARD 1 -o "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-out -j DROP
    fi

    # Reinsert our hooks when AntiZapret has prepended its own rules on restart.
    server_iptables_remove filter INPUT -i "$RELAY_UPLINK" -p udp --dport "$RELAY_PORT" -m comment --comment az-relay-listen -j ACCEPT
    server_iptables_remove filter INPUT -i "$WG_IF" -m comment --comment az-relay-input -j AZRELAY-INPUT
    server_iptables_remove filter FORWARD -i "$WG_IF" -m comment --comment az-relay-forward -j AZRELAY-FWD
    server_iptables_remove filter FORWARD -o "$WG_IF" -m comment --comment az-relay-return -j AZRELAY-RETURN
    server_iptables_remove nat POSTROUTING -o "$RELAY_UPLINK" -m comment --comment az-relay-nat -j AZRELAY-NAT
    server_iptables_remove mangle FORWARD -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -m comment --comment az-relay-mss -j TCPMSS --clamp-mss-to-pmtu

    local chain
    for chain in AZRELAY-INPUT AZRELAY-FWD AZRELAY-RETURN; do
        if iptables -w -t filter -S "$chain" >/dev/null 2>&1; then
            iptables -w -t filter -F "$chain"
            if [[ $action == down ]]; then iptables -w -t filter -X "$chain"; fi
        elif [[ $action == up ]]; then
            iptables -w -t filter -N "$chain"
        fi
    done
    if iptables -w -t nat -S AZRELAY-NAT >/dev/null 2>&1; then
        iptables -w -t nat -F AZRELAY-NAT
        if [[ $action == down ]]; then iptables -w -t nat -X AZRELAY-NAT; fi
    elif [[ $action == up ]]; then
        iptables -w -t nat -N AZRELAY-NAT
    fi
    if [[ $action == down ]]; then
        server_iptables_remove filter INPUT -i "$WG_IF" -m comment --comment az-relay-rebuild-INPUT-in -j DROP
        server_iptables_remove filter FORWARD -i "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-in -j DROP
        server_iptables_remove filter FORWARD -o "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-out -j DROP
        return 0
    fi
    # A stopped tunnel must never leave a new public forwarding path behind.
    ip link show dev "$WG_IF" >/dev/null 2>&1 || return 0

    iptables -w -A AZRELAY-INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -w -A AZRELAY-FWD -m conntrack --ctstate INVALID -j DROP
    iptables -w -A AZRELAY-RETURN -m conntrack --ctstate INVALID -j DROP

    local peer destination
    # The relay is an Internet exit, not a route into the destination VPS network.
    # This also prevents forwarding to the other WireGuard peers or metadata IPs.
    for destination in \
        0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
        172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 \
        198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
        iptables -w -A AZRELAY-FWD -d "$destination" -j REJECT --reject-with icmp-admin-prohibited
    done
    for peer in "$RELAY_ANTIZAPRET_IP" "$RELAY_VPN_IP"; do
        iptables -w -A AZRELAY-INPUT -s "$peer/32" -d "$RELAY_SERVER_IP/32" -p icmp --icmp-type echo-request -j ACCEPT
        iptables -w -A AZRELAY-FWD -s "$peer/32" -o "$RELAY_UPLINK" -j ACCEPT
        iptables -w -A AZRELAY-RETURN -i "$RELAY_UPLINK" -d "$peer/32" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -w -t nat -A AZRELAY-NAT -s "$peer/32" -j MASQUERADE
    done
    iptables -w -A AZRELAY-INPUT -j DROP
    iptables -w -A AZRELAY-FWD -j DROP
    iptables -w -A AZRELAY-RETURN -j DROP
    # POSTROUTING cannot match -i: peer /32 sources are authenticated by WireGuard
    # AllowedIPs, checked in FORWARD, and cannot overlap any pre-existing route.
    iptables -w -I INPUT 1 -i "$RELAY_UPLINK" -p udp --dport "$RELAY_PORT" -m comment --comment az-relay-listen -j ACCEPT
    iptables -w -I INPUT 1 -i "$WG_IF" -m comment --comment az-relay-input -j AZRELAY-INPUT
    iptables -w -I FORWARD 1 -i "$WG_IF" -m comment --comment az-relay-forward -j AZRELAY-FWD
    iptables -w -I FORWARD 1 -o "$WG_IF" -m comment --comment az-relay-return -j AZRELAY-RETURN
    iptables -w -t nat -I POSTROUTING 1 -o "$RELAY_UPLINK" -m comment --comment az-relay-nat -j AZRELAY-NAT
    iptables -w -t mangle -I FORWARD 1 -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -m comment --comment az-relay-mss -j TCPMSS --clamp-mss-to-pmtu
    server_iptables_remove filter INPUT -i "$WG_IF" -m comment --comment az-relay-rebuild-INPUT-in -j DROP
    server_iptables_remove filter FORWARD -i "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-in -j DROP
    server_iptables_remove filter FORWARD -o "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-out -j DROP
}

server_validate_subnet() {
    python3 - "$1" <<'PY'
import ipaddress
import sys
try:
    subnet = ipaddress.IPv4Network(sys.argv[1], strict=True)
    private = [ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if subnet.prefixlen != 24 or not any(subnet.subnet_of(n) for n in private):
        raise ValueError('Transit subnet must be an RFC1918 IPv4 /24.')
    for reserved in ('10.28.0.0/14', '172.28.0.0/14'):
        if subnet.overlaps(ipaddress.IPv4Network(reserved)):
            raise ValueError('Transit subnet overlaps an AntiZapret client or fake address range.')
except ValueError as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
print(subnet.network_address)
print(subnet.network_address + 1)
print(subnet.network_address + 2)
print(subnet.network_address + 3)
PY
}

server_choose_subnet() {
    python3 - "$1" "$2" "$3" <<'PY'
import hashlib
import ipaddress
import json
import sys

try:
    endpoint = ipaddress.IPv4Address(sys.argv[1])
    port = int(sys.argv[2], 10)
    if not endpoint.is_global or endpoint.is_multicast or not 1024 <= port <= 65535:
        raise ValueError()
    inventory = json.loads(sys.argv[3])
    if not isinstance(inventory, list):
        raise ValueError()
    occupied = []
    for route in inventory:
        if not isinstance(route, dict):
            raise ValueError()
        destination = route.get('dst', 'default')
        if destination == 'default':
            continue
        network = ipaddress.IPv4Network(destination, strict=False)
        # A default route is the Internet uplink, not an occupied private range.
        if network.prefixlen:
            occupied.append(network)
except (ValueError, TypeError):
    sys.exit('Cannot choose a transit subnet from the local routing inventory.')

pool = ipaddress.IPv4Network('10.64.0.0/10')
count = 1 << (24 - pool.prefixlen)
seed = hashlib.sha256((str(endpoint) + ':' + str(port)).encode('ascii')).digest()
first = int.from_bytes(seed, 'big') % count
base = int(pool.network_address)
for offset in range(count):
    candidate = ipaddress.IPv4Network((base + (((first + offset) % count) << 8), 24))
    if not any(candidate.overlaps(network) for network in occupied):
        print(candidate)
        break
else:
    sys.exit('No free transit subnet is available; resolve local route conflicts before installation.')
PY
}

server_install() (
    set -Eeuo pipefail
    require_root
    local endpoint='' port=51888 uplink='' subnet=''
    while (($#)); do
        case $1 in
            --endpoint) (($# >= 2)) || die '--endpoint requires an IPv4 address'; endpoint=$2; shift 2 ;;
            --port) (($# >= 2)) || die '--port requires a number'; port=$2; shift 2 ;;
            --uplink) (($# >= 2)) || die '--uplink requires an interface'; uplink=$2; shift 2 ;;
            --subnet) (($# >= 2)) || die '--subnet requires an RFC1918 /24'; subnet=$2; shift 2 ;;
            *) die "Unknown server option: $1" ;;
        esac
    done
    if [[ -z $endpoint ]]; then
        [[ -t 0 ]] || die 'Specify --endpoint with the exit VPS (Server 2) public IPv4 address.'
        read -r -p 'Exit VPS (Server 2) public IPv4 address: ' endpoint
    fi
    # A host may be both an entry client and an exit server. Their state,
    # interfaces and firewall rules are independent; only transit routes overlap.
    [[ ! -e "$STATE_DIR/server.conf" && ! -e "$WG_CONF" ]] || die 'Exit server already installed, or az-relay.conf exists. Use status; existing keys are kept.'
    [[ ! -e "$SERVER_BUNDLE" ]] || die "$SERVER_BUNDLE already exists; preserve or move it before installation."
    [[ ! -e /etc/sysctl.d/98-antizapret-relay.conf ]] || die 'Relay sysctl file already exists.'
    [[ ! -e /etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf ]] || die 'Relay systemd override already exists.'
    install_dependencies
    require_commands ip iptables wg wg-quick python3 systemctl sysctl ss stat
    validate_public_ipv4 "$endpoint" || die 'A public IPv4 endpoint is required.'
    validate_port "$port" || die 'UDP port must be an integer between 1024 and 65535.'
    [[ ! -e "/sys/class/net/$WG_IF" ]] || die "Interface $WG_IF already exists."
    local check_chain
    for check_chain in AZRELAY-INPUT AZRELAY-FWD AZRELAY-RETURN; do
        if iptables -w -t filter -S "$check_chain" >/dev/null 2>&1; then
            die "Firewall chain already exists: $check_chain"
        fi
    done
    if iptables -w -t nat -S AZRELAY-NAT >/dev/null 2>&1; then
        die 'Firewall chain already exists: AZRELAY-NAT'
    fi
    [[ -z $(ss -H -lun "sport = :$port") ]] || die "UDP port $port is already in use."
    if [[ -z $uplink ]]; then
        uplink=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
    fi
    [[ $uplink =~ ^[a-zA-Z0-9_.:-]{1,15}$ && $uplink != lo && $uplink != "$WG_IF" && $uplink != warp-* ]] || die 'Could not select a physical Internet uplink; use --uplink.'
    ip link show dev "$uplink" >/dev/null 2>&1 || die "Uplink does not exist: $uplink"
    local routes
    routes=$(ip -j -4 route show table all)
    if [[ -z $subnet ]]; then
        subnet=$(server_choose_subnet "$endpoint" "$port" "$routes") || die 'Automatic transit subnet selection failed; no server configuration was changed.'
    fi
    local subnet_values
    subnet_values=$(server_validate_subnet "$subnet") || die 'Invalid transit subnet.'
    local server_ip antizapret_ip vpn_ip
    { read -r _; read -r server_ip; read -r antizapret_ip; read -r vpn_ip; } <<<"$subnet_values"
    [[ $endpoint != "$server_ip" && $endpoint != "$antizapret_ip" && $endpoint != "$vpn_ip" ]] || die 'Endpoint must not be in the transit subnet.'
    python3 - "$subnet" "$routes" <<'PY' || die 'Transit subnet overlaps an existing route; choose another --subnet.'
import ipaddress
import json
import sys
subnet = ipaddress.ip_network(sys.argv[1])
for route in json.loads(sys.argv[2]):
    destination = route.get('dst', 'default')
    if destination == 'default':
        continue
    try:
        existing = ipaddress.ip_network(destination, strict=False)
    except ValueError:
        continue
    if existing.prefixlen == 0:
        continue
    if existing.overlaps(subnet):
        print('Conflicting route: ' + destination, file=sys.stderr)
        sys.exit(1)
PY
    local transaction
    transaction=$(mktemp -d /tmp/antizapret-relay.XXXXXXXX)
    chmod 700 "$transaction"
    local installed=0 success=0 forward_before
    forward_before=$(sysctl -n net.ipv4.ip_forward)
    server_install_cleanup() {
        local result=$?
        if (( ! success && installed )); then
            systemctl disable --now "wg-quick@$WG_IF" >/dev/null 2>&1 || true
            server_firewall down >/dev/null 2>&1 || true
            rm -f -- "$WG_CONF" "$STATE_DIR/server.conf" "$SERVER_BUNDLE" \
                /etc/sysctl.d/98-antizapret-relay.conf \
                /etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf
            systemctl daemon-reload >/dev/null 2>&1 || true
            sysctl -q -w "net.ipv4.ip_forward=$forward_before" >/dev/null 2>&1 || true
        fi
        rm -rf -- "$transaction"
        exit "$result"
    }
    trap server_install_cleanup EXIT
    local server_private server_public antizapret_private antizapret_public vpn_private vpn_public
    server_private=$(wg genkey)
    server_public=$(printf '%s\n' "$server_private" | wg pubkey)
    antizapret_private=$(wg genkey)
    antizapret_public=$(printf '%s\n' "$antizapret_private" | wg pubkey)
    vpn_private=$(wg genkey)
    vpn_public=$(printf '%s\n' "$vpn_private" | wg pubkey)
    cat >"$transaction/az-relay.conf" <<EOF
[Interface]
Address = $server_ip/24
PrivateKey = $server_private
ListenPort = $port
MTU = 1280
Table = off
PostUp = $APP firewall up server
PostDown = $APP firewall down server

[Peer]
# Entry VPS (Server 1): AntiZapret clients
PublicKey = $antizapret_public
AllowedIPs = $antizapret_ip/32

[Peer]
# Entry VPS (Server 1): full VPN clients (distinct key required)
PublicKey = $vpn_public
AllowedIPs = $vpn_ip/32
EOF
    {
        printf 'RELAY_ENDPOINT=%q\n' "$endpoint:$port"
        printf 'RELAY_UPLINK=%q\n' "$uplink"
        printf 'RELAY_PORT=%q\n' "$port"
        printf 'RELAY_SUBNET=%q\n' "$subnet"
        printf 'RELAY_SERVER_IP=%q\n' "$server_ip"
        printf 'RELAY_ANTIZAPRET_IP=%q\n' "$antizapret_ip"
        printf 'RELAY_VPN_IP=%q\n' "$vpn_ip"
        printf 'RELAY_IP_FORWARD_BEFORE=%q\n' "$forward_before"
    } >"$transaction/server.conf"
    # Private keys go through stdin, never through process arguments or log output.
    printf '%s\n' "$endpoint:$port" "$server_public" "$antizapret_private" "$antizapret_ip/32" "$vpn_private" "$vpn_ip/32" |
        python3 -c 'import json,sys; values=sys.stdin.read().splitlines(); json.dump(dict(zip(("version","endpoint","server_public_key","antizapret_private_key","antizapret_address","vpn_private_key","vpn_address"),(1,*values))),sys.stdout,indent=2); print()' >"$transaction/client.json"
    install_self
    install -d -m 700 "$STATE_DIR"
    install -d -m 700 /etc/wireguard
    install -d -m 755 /etc/systemd/system/antizapret.service.d
    installed=1
    install -m 600 "$transaction/server.conf" "$STATE_DIR/server.conf"
    install -m 600 "$transaction/az-relay.conf" "$WG_CONF"
    install -m 600 "$transaction/client.json" "$SERVER_BUNDLE"
    printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/98-antizapret-relay.conf
    chmod 644 /etc/sysctl.d/98-antizapret-relay.conf
    # Do not make a firewall-repair failure take the existing VPN service offline.
    printf '[Service]\nExecStartPost=-%s firewall up server\n' "$APP" >/etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf
    chmod 644 /etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf
    sysctl -q -w net.ipv4.ip_forward=1
    systemctl daemon-reload
    systemctl enable --now "wg-quick@$WG_IF"
    success=1
    log "Exit VPS (Server 2) is ready at $endpoint:$port (UDP)."
    log "Copy $SERVER_BUNDLE securely to the entry VPS (Server 1); it contains private keys."
    log 'Allow this UDP port in the VPS provider firewall, if the provider uses one.'
)

server_uninstall() {
    require_root
    server_load_state
    systemctl disable --now "wg-quick@$WG_IF"
    server_firewall down
    rm -f -- "$WG_CONF" /etc/sysctl.d/98-antizapret-relay.conf /etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf
    rm -f -- "$SERVER_BUNDLE" "$STATE_DIR/server.conf"
    systemctl daemon-reload
    log 'Exit server removed. Other VPN interfaces and firewall rules are kept.'
    log 'Runtime IPv4 forwarding is kept enabled because the existing AntiZapret may require it.'
}

# Replace the built-in Cloudflare peers, preserving the upstream DNS allocator.
CLIENT_DOMAINS=/root/antizapret/config/relay-include-warp-hosts.txt
CLIENT_EXCLUDES=/root/antizapret/config/exclude-warp-hosts.txt
CLIENT_DROPIN=/etc/systemd/system/antizapret.service.d/90-antizapret-relay-client.conf

client_firewall() {
    local action=${1:-up} prefix only
    [[ -f $STATE_DIR/client.conf ]] || return 0
    [[ ! -L $STATE_DIR/client.conf && $(stat -c %u "$STATE_DIR/client.conf") == 0 ]] || die 'Client state must be a root-owned regular file.'
    # Root-owned state generated by this installer, never an imported bundle.
    # shellcheck disable=SC1090
    source "$STATE_DIR/client.conf"
    [[ $prefix =~ ^(10|172)$ && $only =~ ^[yn]$ ]] || die 'Invalid client state.'
    local -a rules=(-s "$prefix.29.0.0/16" -m mark --mark 0x2 ! -o warp-antizapret -m comment --comment az-relay-client -j DROP)
    if [[ $action == up ]]; then ipt_add filter FORWARD "${rules[@]}"; else ipt_del filter FORWARD "${rules[@]}"; fi
    if [[ $only == n ]]; then
        rules=(-s "$prefix.28.0.0/16" -m mark --mark 0x2 ! -o warp-vpn -m comment --comment az-relay-client -j DROP)
        if [[ $action == up ]]; then ipt_add filter FORWARD "${rules[@]}"; else ipt_del filter FORWARD "${rules[@]}"; fi
    fi
}

client_compatibility() {
    [[ -f $AZ_DIR/setup && -f $AZ_DIR/up.sh && -x $AZ_DIR/parse.sh ]] || die 'An existing GubernievS/AntiZapret-VPN installation is required.'
    grep -q 'ANTIZAPRET_WARP_PRIVATE_KEY' "$AZ_DIR/up.sh" || die 'Unsupported AntiZapret up.sh: custom WARP keys are unavailable.'
    grep -q 'Table = 1000' "$AZ_DIR/up.sh" || die 'Unsupported AntiZapret routing layout.'
    grep -q 'include-warp-hosts.txt' "$AZ_DIR/parse.sh" || die 'Unsupported AntiZapret domain parser.'
    systemctl is-active --quiet antizapret.service || die 'Start and repair antizapret.service before installing the relay.'
}

client_install() {
    local bundle='' only=n gemini=n argument domain stage prefix
    local -a domains=()
    while (($#)); do
        argument=$1; shift
        case "$argument" in
            --bundle) (($#)) || die '--bundle needs a path'; bundle=$1; shift ;;
            --domain) (($#)) || die '--domain needs a domain'; domains+=("$1"); shift ;;
            --antizapret-only) only=y ;;
            --gemini) gemini=y ;;
            *) die "Unknown client option: $argument" ;;
        esac
    done
    [[ -n $bundle && -f $bundle ]] || die 'Usage: client --bundle /root/antizapret-relay-import.json [--domain example.com] [--gemini]'
    install_dependencies
    client_compatibility
    [[ ! -e $STATE_DIR/client.conf ]] || die 'Client role already installed. Use status or uninstall --role client before reconfiguring.'
    [[ ! -e $STATE_DIR/setup.before.json && ! -e $STATE_DIR/setup.snapshot && ! -e $STATE_DIR/client-values.json && ! -e $STATE_DIR/default-exclusions.json && ! -L $STATE_DIR/default-exclusions.json && ! -e $STATE_DIR/gemini.before.json && ! -L $STATE_DIR/gemini.before.json ]] || die 'Previous installation metadata exists. Preserve and resolve it before installing.'
    [[ ! -e $CLIENT_DOMAINS && ! -e $CLIENT_DROPIN ]] || die 'Reserved relay domain file or systemd drop-in already exists.'
    stage=$(mktemp -d)
    # Validate all imported data before touching the running installation.
    if ! config_tool validate-bundle "$bundle" > "$stage/validated"; then rm -rf -- "$stage"; return 1; fi
    ip -j -4 route show table all > "$stage/routes.json"
    # A local donor may coexist, but its transit /24 must differ from this donor's.
    if ! config_tool check-routes "$bundle" "$stage/routes.json"; then rm -rf -- "$stage"; return 1; fi
    : > "$stage/domains"
    for domain in "${domains[@]}"; do
        if ! config_tool domain-add "$stage/domains" "$domain"; then rm -rf -- "$stage"; return 1; fi
    done
    # Exclude the installed upstream defaults without editing downloaded lists or
    # overwriting existing user exclusions. Prepare before any live changes.
    if ! config_tool prepare-default-exclusions "$AZ_DIR/download" "$CLIENT_EXCLUDES" "$stage/exclusions" "$stage/default-exclusions.json"; then
        rm -rf -- "$stage"
        return 1
    fi
    if [[ $gemini == y ]]; then
        if ! config_tool prepare-gemini "$CLIENT_INCLUDES" "$stage/gemini.before.json" >/dev/null; then
            rm -rf -- "$stage"
            return 1
        fi
    fi
    python3 - "$bundle" "$stage/changes.json" "$only" <<'PY'
import json, sys
from pathlib import Path
b = json.loads(Path(sys.argv[1]).read_text())
c = {'ANTIZAPRET_WARP': '4', 'WARP_PROTECTION': 'y', 'WARP_MTU': '1280'}
roles = [('ANTIZAPRET', 'antizapret')]
if sys.argv[3] == 'n':
    c['VPN_WARP'] = '3'
    roles.append(('VPN', 'vpn'))
for upper, lower in roles:
    c[upper + '_WARP_PRIVATE_KEY'] = b[lower + '_private_key']
    c[upper + '_WARP_PUBLIC_KEY'] = b['server_public_key']
    c[upper + '_WARP_ENDPOINT'] = b['endpoint']
    c[upper + '_WARP_ADDRESS'] = b[lower + '_address']
Path(sys.argv[2]).write_text(json.dumps(c))
PY
    # The setup file is already root-owned executable configuration in AntiZapret.
    prefix=$(bash -c 'source "$1"; if [[ ${ALTERNATIVE_CLIENT_IP:-n} == y ]]; then printf "%s" "${CLIENT_IP:-172}"; else printf 10; fi' _ "$AZ_DIR/setup")
    [[ $prefix =~ ^(10|172)$ ]] || die 'Unsupported custom client IP prefix.'
    install -m 0600 "$AZ_DIR/setup" "$stage/setup"
    if ! config_tool apply "$stage/setup" "$stage/setup.before.json" "$stage/changes.json"; then rm -rf -- "$stage"; return 1; fi
    install_self
    trap 'client_install_rollback "$stage"' ERR
    install -m 0600 "$stage/changes.json" "$STATE_DIR/client-values.json"
    printf 'prefix=%q\nonly=%q\n' "$prefix" "$only" > "$STATE_DIR/client.conf"
    install -m 0600 "$AZ_DIR/setup" "$STATE_DIR/setup.snapshot"
    install -m 0600 "$stage/default-exclusions.json" "$STATE_DIR/default-exclusions.json"
    if [[ $gemini == y ]]; then
        install -m 0600 "$stage/gemini.before.json" "$STATE_DIR/gemini.before.json"
    fi
    log 'Stopping AntiZapret briefly to remove the old WireGuard routes cleanly.'
    systemctl stop antizapret.service
    # Any failure after this point restores the previous managed settings.
    config_tool apply "$AZ_DIR/setup" "$STATE_DIR/setup.before.json" "$STATE_DIR/client-values.json"
    config_tool apply-default-exclusions "$CLIENT_EXCLUDES" "$STATE_DIR/default-exclusions.json"
    if [[ $gemini == y ]]; then
        config_tool apply-gemini "$CLIENT_INCLUDES" "$STATE_DIR/gemini.before.json"
    fi
    install -m 0600 "$stage/domains" "$CLIENT_DOMAINS"
    install -d -m 0755 "$(dirname "$CLIENT_DROPIN")"
    printf '[Service]\nExecStartPost=%s firewall up client\n' "$APP" > "$CLIENT_DROPIN"
    chmod 0644 "$CLIENT_DROPIN"
    systemctl daemon-reload
    client_firewall up
    systemctl start antizapret.service
    (trap - ERR; cd "$AZ_DIR" && ./parse.sh)
    trap - ERR
    rm -f -- "$STATE_DIR/gemini.before.json"
    rm -rf -- "$stage"
    log 'Installed. Native WARP domain lists now use your exit VPS.'
    log 'Bundled WARP defaults were added to the marked block in /root/antizapret/config/exclude-warp-hosts.txt.'
    log 'Run: antizapret-relay status'
    log 'Send domains through the donor: /root/antizapret/config/include-warp-hosts.txt'
    log 'Exclude domains from the donor: /root/antizapret/config/exclude-warp-hosts.txt'
    log 'To choose a bundled domain later, remove its matching exclusions before applying the lists.'
    log 'After editing the native lists, run: /root/antizapret/parse.sh'
    if [[ $gemini == y ]]; then
        log 'Gemini website and API domains were added to the native include list. Existing exclusions still apply.'
    fi
    log 'Keep donor exports private. A manually copied import file may be deleted after a secure backup.'
}

client_install_rollback() {
    local stage=$1
    trap - ERR
    log 'Installation failed; restoring previous AntiZapret settings.'
    systemctl stop antizapret.service || true
    client_firewall down || true
    if [[ -f $STATE_DIR/setup.before.json ]]; then
        config_tool restore "$AZ_DIR/setup" "$STATE_DIR/setup.before.json" || true
    elif [[ -f $STATE_DIR/setup.snapshot ]]; then
        install -m 0600 "$STATE_DIR/setup.snapshot" "$AZ_DIR/setup"
    fi
    if [[ -f $STATE_DIR/gemini.before.json ]]; then
        if config_tool rollback-gemini "$CLIENT_INCLUDES" "$STATE_DIR/gemini.before.json"; then
            rm -f -- "$STATE_DIR/gemini.before.json"
        else
            log 'Could not restore Gemini includes; recovery metadata is kept in /etc/antizapret-relay/gemini.before.json.'
        fi
    fi
    if [[ -f $STATE_DIR/default-exclusions.json ]]; then
        if config_tool rollback-default-exclusions "$CLIENT_EXCLUDES" "$STATE_DIR/default-exclusions.json"; then
            rm -f -- "$STATE_DIR/default-exclusions.json"
        else
            log 'Could not restore domain exclusions; recovery metadata is kept in /etc/antizapret-relay/default-exclusions.json.'
        fi
    fi
    rm -f -- "$CLIENT_DROPIN" "$CLIENT_DOMAINS"
    systemctl daemon-reload || true
    systemctl start antizapret.service || true
    rm -f -- "$STATE_DIR/client.conf" "$STATE_DIR/client-values.json" "$STATE_DIR/setup.before.json" "$STATE_DIR/setup.snapshot"
    rm -rf -- "$stage"
    die 'Client installation rolled back. Inspect journalctl -u antizapret.service.'
}

client_uninstall() {
    [[ -f $STATE_DIR/client.conf ]] || return 0
    [[ -f $AZ_DIR/setup && -f $STATE_DIR/setup.before.json ]] || die 'Restore metadata or AntiZapret setup is missing; refusing to discard the backup.'
    config_tool check-restore "$AZ_DIR/setup" "$STATE_DIR/setup.before.json"
    if [[ -e $STATE_DIR/default-exclusions.json || -L $STATE_DIR/default-exclusions.json ]]; then
        config_tool check-default-exclusions "$CLIENT_EXCLUDES" "$STATE_DIR/default-exclusions.json"
    fi
    trap 'trap - ERR; log "Uninstall interrupted; restart AntiZapret and retain the backup for recovery."; systemctl start antizapret.service || true; exit 1' ERR
    systemctl stop antizapret.service
    config_tool restore "$AZ_DIR/setup" "$STATE_DIR/setup.before.json"
    if [[ -f $STATE_DIR/default-exclusions.json ]]; then
        config_tool restore-default-exclusions "$CLIENT_EXCLUDES" "$STATE_DIR/default-exclusions.json"
    fi
    rm -f -- "$CLIENT_DROPIN" "$CLIENT_DOMAINS"
    client_firewall down
    systemctl daemon-reload
    systemctl start antizapret.service
    (cd "$AZ_DIR" && ./parse.sh)
    rm -f -- "$STATE_DIR/client.conf" "$STATE_DIR/client-values.json" "$STATE_DIR/setup.before.json" "$STATE_DIR/setup.snapshot" "$STATE_DIR/default-exclusions.json"
    trap - ERR
    log 'Previous WARP settings restored; unrelated AntiZapret setup values preserved.'
}

client_upgrade_exclusions() (
    # One-time migration. Later upgrades retain deliberate edits to exclusions.
    [[ -f $STATE_DIR/client.conf ]] || return 0
    if [[ -e $STATE_DIR/default-exclusions.json || -L $STATE_DIR/default-exclusions.json ]]; then
        return 0
    fi
    client_compatibility
    local stage
    stage=$(mktemp -d)
    trap 'rm -rf -- "$stage"' EXIT
    config_tool prepare-default-exclusions "$AZ_DIR/download" "$CLIENT_EXCLUDES" "$stage/exclusions" "$stage/default-exclusions.json"
    trap 'client_upgrade_exclusions_rollback' ERR
    install -m 0600 "$stage/default-exclusions.json" "$STATE_DIR/default-exclusions.json"
    config_tool apply-default-exclusions "$CLIENT_EXCLUDES" "$STATE_DIR/default-exclusions.json"
    # Native parser reloads domain policies and briefly reconnects WARP peers.
    (cd "$AZ_DIR" && ./parse.sh)
    trap - ERR
    log 'Bundled WARP defaults are now excluded in /root/antizapret/config/exclude-warp-hosts.txt.'
    log 'Later upgrades keep your edits to these exclusions. Keys and tunnel addresses are unchanged.'
)

client_upgrade_exclusions_rollback() {
    trap - ERR
    if [[ -f $STATE_DIR/default-exclusions.json ]]; then
        if config_tool rollback-default-exclusions "$CLIENT_EXCLUDES" "$STATE_DIR/default-exclusions.json"; then
            rm -f -- "$STATE_DIR/default-exclusions.json"
            (cd "$AZ_DIR" && ./parse.sh) || log 'Could not reload the restored lists; rerun /root/antizapret/parse.sh after resolving the error.'
        else
            log 'Domain recovery metadata is kept in /etc/antizapret-relay/default-exclusions.json.'
        fi
    fi
    die 'Default-exclusion migration failed. Existing roles and keys are kept; resolve the error and run upgrade again.'
}

domain_command() {
    [[ -f $STATE_DIR/client.conf ]] || die 'Install the client role first.'
    local operation=${1:-list}; shift || true
    case "$operation" in
        list) config_tool domain-list "$CLIENT_DOMAINS" ;;
        add|remove)
            [[ $# -eq 1 ]] || die 'Usage: domain add|remove DOMAIN'
            local verb='domain-add'
            [[ $operation == remove ]] && verb='domain-drop'
            config_tool "$verb" "$CLIENT_DOMAINS" "$1"
            (cd "$AZ_DIR" && ./parse.sh)
            log 'Domain lists applied. Clear DNS cache or reconnect your VPN client.'
            ;;
        *) die 'Usage: domain list|add|remove [DOMAIN]' ;;
    esac
}

# Interactive setup; the explicit client/server commands remain available.
WIZARD_IMPORT=${WIZARD_IMPORT:-/root/antizapret-relay-import.json}

wizard_read() {
    local target=$1 prompt=$2 default=${3:-} reply
    printf '%s' "$prompt" >&2
    if ! read -r reply; then
        printf '\n' >&2
        die 'Input ended. Run bash install.sh again from an interactive SSH terminal.'
    fi
    printf -v "$target" '%s' "${reply:-$default}"
}

wizard_server() {
    if [[ -f $STATE_DIR/server.conf ]]; then
        log 'Server / donor role is already installed; keeping its keys and settings.'
        return 0
    fi
    local endpoint port
    log 'Set up THIS VPS as a server / donor for another VPS.'
    while true; do
        wizard_read endpoint 'Public IPv4 of THIS donor VPS: '
        if validate_public_ipv4 "$endpoint" 2>/dev/null; then break; fi
        log 'Enter a public IPv4 address, for example 1.2.3.4.'
    done
    while true; do
        wizard_read port 'WireGuard UDP port [51888]: ' 51888
        if validate_port "$port"; then break; fi
        log 'Enter a UDP port from 1024 to 65535.'
    done
    port=$((10#$port))
    # Keep these calls outside conditionals: backends depend on errexit/ERR traps.
    server_install --endpoint "$endpoint" --port "$port"
}

gemini_install_prompt() {
    local target=$1 answer
    while true; do
        wizard_read answer 'Route Gemini through the donor? [y/N]: ' n
        case "${answer,,}" in
            y|yes) printf -v "$target" '%s' y; return ;;
            n|no) printf -v "$target" '%s' n; return ;;
        esac
        log 'Enter y or n.'
    done
}

wizard_client() (
    local gemini=n
    if [[ -f $STATE_DIR/client.conf ]]; then
        log 'Client role is already installed; keeping its donor and settings.'
        gemini_install_prompt gemini
        if [[ $gemini == y ]]; then gemini_enable; fi
        return 0
    fi
    local allow_defer=${1:-n} bundle='' donor_ip='' ssh_port='' wizard_stage='' own_bundle=''
    trap 'if [[ -n $wizard_stage ]]; then rm -f -- "$wizard_stage/donor.json"; rmdir -- "$wizard_stage"; fi' EXIT
    if [[ -f $WIZARD_IMPORT ]]; then
        bundle=$WIZARD_IMPORT
        log "Using the existing imported connection file: $bundle"
    else
        log 'Connect THIS AntiZapret VPS to ANOTHER server / donor.'
        if [[ $allow_defer == y ]]; then
            log 'If the other donor is not ready, press Enter to connect the client later.'
        fi
        while true; do
            wizard_read donor_ip 'Public IPv4 of the OTHER donor VPS: '
            if [[ -z $donor_ip && $allow_defer == y ]]; then
                log 'Client setup deferred. Run bash install.sh again and choose 1 when the other donor is ready.'
                return 0
            fi
            if validate_public_ipv4 "$donor_ip" 2>/dev/null; then break; fi
            log 'Enter the public IPv4 of the donor, not this client VPS.'
        done
        while true; do
            wizard_read ssh_port 'SSH port on the donor [22]: ' 22
            if [[ $ssh_port =~ ^[0-9]{1,5}$ ]] && ((10#$ssh_port >= 1 && 10#$ssh_port <= 65535)); then break; fi
            log 'Enter an SSH port from 1 to 65535.'
        done
        ssh_port=$((10#$ssh_port))
        if ! command -v scp >/dev/null; then
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-client
        fi
        require_commands scp
        wizard_stage=$(mktemp -d)
        chmod 0700 "$wizard_stage"
        bundle=$wizard_stage/donor.json
        log 'Downloading connection keys over SSH as root on the donor.'
        log 'Verify the SSH host fingerprint if asked. A password prompt is for the DONOR VPS.'
        if ! scp -P "$ssh_port" -o ConnectTimeout=15 -o StrictHostKeyChecking=ask -- \
            "root@$donor_ip:/root/antizapret-relay-donor.json" "$bundle"; then
            die 'Could not fetch donor keys. Set up the donor first and check root SSH access, or copy the bundle manually and use client --bundle FILE.'
        fi
    fi
    # validate-bundle prints private keys; never let its output reach the terminal.
    config_tool validate-bundle "$bundle" >/dev/null
    if [[ -f $STATE_DIR/server.conf && -f $SERVER_BUNDLE ]]; then own_bundle=$SERVER_BUNDLE; fi
    python3 - "$bundle" "$donor_ip" "$own_bundle" <<'PY'
import json
import sys
from pathlib import Path

bundle = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
if sys.argv[2] and bundle['endpoint'].split(':')[0] != sys.argv[2]:
    sys.exit('Donor endpoint differs from the entered IP. Check the donor configuration, or transfer the correct bundle manually.')
if sys.argv[3]:
    try:
        own = json.loads(Path(sys.argv[3]).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        sys.exit('Cannot read the local donor export. Repair it before connecting another donor.')
    if not isinstance(own, dict) or 'server_public_key' not in own:
        sys.exit('Local donor export is invalid. Repair it before connecting another donor.')
    if own.get('server_public_key') == bundle['server_public_key']:
        sys.exit('This is the local donor bundle. Enter the IP or import the keys of ANOTHER donor VPS.')
PY
    gemini_install_prompt gemini
    local -a client_options=(--bundle "$bundle")
    if [[ $gemini == y ]]; then client_options+=(--gemini); fi
    log 'Connecting the client to the donor. AntiZapret will restart briefly.'
    client_install "${client_options[@]}"
)

wizard_done() {
    printf '\n'
    if [[ -f $STATE_DIR/server.conf ]]; then
        log 'SERVER / DONOR: installed. Open its chosen WireGuard UDP port in the hosting provider firewall.'
        log 'On the other VPS, run bash install.sh and choose 1 to connect to this donor.'
    fi
    if [[ -f $STATE_DIR/client.conf ]]; then
        log 'CLIENT: installed. Manage domains ON THIS CLIENT VPS:'
        if [[ -f $STATE_DIR/default-exclusions.json ]]; then
            log 'Bundled WARP defaults are excluded in the marked block of exclude-warp-hosts.txt.'
        fi
    else
        log 'CLIENT: not installed here. Manage domains ON THE CLIENT VPS after connecting it:'
    fi
    log 'Send through donor: /root/antizapret/config/include-warp-hosts.txt'
    log 'Exceptions:         /root/antizapret/config/exclude-warp-hosts.txt'
    log 'Use one domain per line, without https:// or paths. Domain entries include subdomains.'
    log 'After editing either file, apply ON THE CLIENT: /root/antizapret/parse.sh'
    log 'Check installed roles: antizapret-relay status'
}

interactive_install() (
    [[ -t 0 ]] || die 'Interactive setup needs a terminal. Download install.sh, then run bash install.sh over SSH; use --help for unattended commands.'
    local choice
    trap 'if [[ $? != 0 ]]; then log "Setup stopped. Already installed roles are kept; fix the error and run bash install.sh again."; fi' EXIT
    printf '\nAntiZapret Relay setup\n'
    printf '  1) Client - selected domains use another donor VPS\n'
    printf '  2) Server / donor - let another VPS use this public IP\n'
    printf '  3) Both - install server / donor and client on this VPS\n\n'
    while true; do
        wizard_read choice 'Choose a role [1/2/3]: '
        case "$choice" in 1|2|3) break ;; esac
        log 'Choose 1, 2 or 3.'
    done
    install_dependencies
    if [[ ( $choice == 1 || $choice == 3 ) && ! -f $STATE_DIR/client.conf ]]; then
        client_compatibility
    fi
    case "$choice" in
        1) wizard_client n ;;
        2) wizard_server ;;
        3) wizard_server; wizard_client y ;;
    esac
    wizard_done
)

usage() {
    cat <<'HELP'
AntiZapret Relay: use your own WireGuard VPS instead of Cloudflare WARP.

Client VPS (Server 1): users connect to its AntiZapret.
Donor VPS (Server 2): selected domains use its public IP.
One VPS can run BOTH roles. Tunnel subnets and keys are selected automatically.
Easy setup (run in an interactive SSH terminal):
  bash install.sh
Choose 1) Client, 2) Server / donor, or 3) Both, then follow the IP prompts.
Client fetches donor keys over SSH as root; existing imported bundles also work.
Client setup also asks whether to add the Gemini website and API domains.

Download install.sh to both servers, then run as root:
  # On Server 2:
  bash install.sh server --endpoint SERVER2_PUBLIC_IPV4 [--port 51888] [--uplink eth0]
  # On Server 1, after copying the bundle from Server 2:
  bash install.sh client --bundle /root/antizapret-relay-import.json
  # Add --gemini to include Gemini website and API domains during client setup.

Donor creates /root/antizapret-relay-donor.json (SECRET). Copy it privately to
the client as /root/antizapret-relay-import.json. Never publish private keys.
Client replaces WARP peers for both AntiZapret and full VPN custom-domain mode.
Use --antizapret-only to leave the full VPN WARP peer unchanged. DNS WARP stays
unchanged. Existing shared WARP include/exclude lists continue to apply.
Installation adds the bundled WARP domains to a marked block in the native
exclude-warp-hosts.txt. To opt one back in, remove its matching exclusions,
add it to include-warp-hosts.txt, then run parse.sh.

Manage domains ON THE CLIENT VPS using the native AntiZapret files:
  /root/antizapret/config/include-warp-hosts.txt  # send through donor
  /root/antizapret/config/exclude-warp-hosts.txt  # exclude from donor route
One domain per line, without https://, paths or *. Subdomains are included.
After editing either file, apply changes on the client:
  /root/antizapret/parse.sh

After installation:
  antizapret-relay preset gemini
  antizapret-relay status
  antizapret-relay uninstall
  antizapret-relay uninstall --role client
  antizapret-relay uninstall --role server
  antizapret-relay uninstall --role all

Optional domain helpers manage config/relay-include-warp-hosts.txt only.
Native exclusions also apply; list shows only this additional file:
  antizapret-relay domain add example.com
  antizapret-relay domain remove example.com
  antizapret-relay domain list

Upgrade an existing installation (first default-exclusion migration briefly
reconnects WARP; keys and addresses are preserved):
  bash install.sh upgrade
HELP
}

relay_status() {
    local found=n
    if [[ -f $STATE_DIR/server.conf ]]; then
        found=y
        log 'Role: DONOR (server): other VPS use this host as their exit.'
        systemctl --no-pager status wg-quick@az-relay.service || true
        wg show az-relay || true
    fi
    if [[ -f $STATE_DIR/client.conf ]]; then
        found=y
        log 'Role: CLIENT: selected domains from this AntiZapret use another donor.'
        systemctl --no-pager status antizapret.service || true
        wg show warp-antizapret || true
        wg show warp-vpn || true
        log 'Relay domain file (also see native WARP include/exclude lists):'
        config_tool domain-list "$CLIENT_DOMAINS"
        log 'Handshake age and RX bytes confirm connectivity; an interface alone does not.'
    fi
    [[ $found == y ]] || die 'Relay is not installed on this host.'
}

firewall_command() {
    local action=${1:-} role=${2:-all}
    [[ $# -le 2 && ( $action == up || $action == down ) ]] || die 'Usage: firewall up|down [client|server|all]'
    case "$role" in
        server) server_firewall "$action" ;;
        client) client_firewall "$action" ;;
        all) server_firewall "$action"; client_firewall "$action" ;;
        *) die 'Firewall role must be client, server or all.' ;;
    esac
}

uninstall_command() {
    local role=''
    if (($#)); then
        [[ $# -eq 2 && $1 == --role ]] || die 'Usage: uninstall [--role client|server|all]'
        role=$2
    elif [[ -f $STATE_DIR/client.conf && -f $STATE_DIR/server.conf ]]; then
        die 'Both roles are installed. Choose uninstall --role client, --role server or --role all.'
    elif [[ -f $STATE_DIR/client.conf ]]; then role=client
    elif [[ -f $STATE_DIR/server.conf ]]; then role=server
    else die 'Relay is not installed.'
    fi
    case "$role" in
        client) [[ -f $STATE_DIR/client.conf ]] || die 'Client role is not installed.'; client_uninstall ;;
        server) [[ -f $STATE_DIR/server.conf ]] || die 'Donor role is not installed.'; server_uninstall ;;
        all)
            [[ -f $STATE_DIR/client.conf || -f $STATE_DIR/server.conf ]] || die 'Relay is not installed.'
            if [[ -f $STATE_DIR/client.conf ]]; then client_uninstall; fi
            if [[ -f $STATE_DIR/server.conf ]]; then server_uninstall; fi
            ;;
        *) die 'Uninstall role must be client, server or all.' ;;
    esac
    log "Removed role: $role. The installer remains available."
}

relay_main() {
    local command_name=${1:-install}
    shift || true
    case "$command_name" in
        help|-h|--help) usage; return ;;
        --version|version) printf '%s\n' "$VERSION"; return ;;
    esac
    require_root
    require_commands flock
    exec 9>/run/lock/antizapret-relay.lock
    # Firewall is also called synchronously by systemd while install holds fd 9.
    if [[ $command_name != firewall ]]; then flock -n 9 || die 'Another relay operation is running.'; fi
    case "$command_name" in
        install) [[ $# -eq 0 ]] || die 'Usage: bash install.sh [install]'; interactive_install ;;
        server) server_install "$@" ;;
        client) client_install "$@" ;;
        firewall) firewall_command "$@" ;;
        domain) domain_command "$@" ;;
        preset) preset_command "$@" ;;
        status) relay_status ;;
        uninstall) uninstall_command "$@" ;;
        upgrade)
            [[ $# -eq 0 ]] || die 'Usage: upgrade'
            [[ -f $STATE_DIR/client.conf || -f $STATE_DIR/server.conf ]] || die 'Install a role first.'
            install_dependencies
            install_self
            client_upgrade_exclusions
            log 'Installer and firewall hooks upgraded. Existing keys and tunnel addresses are kept.'
            ;;
        *) usage >&2; die "Unknown command: $command_name" ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    SCRIPT_FILE=$(readlink -f "${BASH_SOURCE[0]}")
    relay_main "$@"
fi
