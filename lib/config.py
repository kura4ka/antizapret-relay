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
