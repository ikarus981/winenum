"""Kerberos ccache auto-discovery for operator convenience."""

import glob
import os
import re
import subprocess


def _get_uid():
    try:
        return os.getuid()
    except AttributeError:
        pass
    try:
        import pwd  # noqa: F401
    except ImportError:
        pass
    for var in ("UID", "USER_ID"):
        val = os.environ.get(var)
        if val and val.isdigit():
            return int(val)
    try:
        out = subprocess.run(
            ["id", "-u"], capture_output=True, text=True, timeout=2
        )
        if out.returncode == 0 and out.stdout.strip().isdigit():
            return int(out.stdout.strip())
    except Exception:
        pass
    return None


def _strip_prefix(path):
    if not path:
        return path
    path = path.strip().strip('"').strip("'")
    if path.startswith("FILE:"):
        return path[5:]
    return path


def _is_keyring_or_kcm(path):
    if not path:
        return False
    upper = path.upper()
    return upper.startswith("KEYRING:") or upper.startswith("KCM:")


def _validate_file(path):
    try:
        if not os.path.isfile(path):
            return False
        size = os.path.getsize(path)
        return size > 64
    except Exception:
        return False


def _validate_dir(path):
    raw = path
    if raw.startswith("DIR::"):
        raw = raw[5:]
    try:
        if os.path.isdir(raw):
            try:
                return len(os.listdir(raw)) > 0
            except Exception:
                return True
        return False
    except Exception:
        return False


def _validate_ccache(path):
    if not path:
        return False
    if _is_keyring_or_kcm(path):
        return False
    if path.startswith("DIR::"):
        return _validate_dir(path)
    stripped = _strip_prefix(path)
    if stripped.startswith("DIR::"):
        return _validate_dir(stripped)
    if os.path.isdir(stripped):
        return _validate_dir(stripped)
    if _validate_file(stripped):
        if _try_klist_validate(stripped):
            return True
        return True
    return False


def _try_klist_validate(path):
    try:
        proc = subprocess.run(
            ["klist", "-c", path],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if proc.returncode == 0:
            return "Ticket cache:" in proc.stdout or "Default principal" in proc.stdout
        if "No such file" in (proc.stderr or ""):
            return False
        return proc.returncode == 0
    except FileNotFoundError:
        return True
    except Exception:
        return True


def _parse_klist_output(text):
    caches = []
    for line in text.splitlines():
        m = re.search(r"Ticket cache:\s*(.+)", line)
        if m:
            raw = m.group(1).strip()
            caches.append(raw)
    return caches


def _get_klist_caches():
    caches = []
    for args in ([], ["-A"]):
        try:
            proc = subprocess.run(
                ["klist"] + args,
                capture_output=True,
                text=True,
                timeout=3,
            )
            if proc.returncode == 0 and proc.stdout:
                caches.extend(_parse_klist_output(proc.stdout))
        except FileNotFoundError:
            break
        except Exception:
            continue
    seen = set()
    uniq = []
    for c in caches:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def candidate_ccaches():
    candidates = []
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        candidates.append(os.path.join(xdg, "krb5cc"))
    uid = _get_uid()
    if uid is not None:
        candidates.append(f"/tmp/krb5cc_{uid}")
        candidates.extend(glob.glob(f"/tmp/krb5cc_{uid}_*"))
        candidates.append(f"/run/user/{uid}/krb5cc")
        candidates.extend(glob.glob(f"/run/user/{uid}/krb5cc*"))
    candidates.append("/tmp/krb5cc")
    candidates.extend(glob.glob("/tmp/krb5cc_*"))
    seen = set()
    uniq = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def resolve_ccache(console=None):
    env = os.environ.get("KRB5CCNAME")
    if env:
        env = env.strip()
        if _is_keyring_or_kcm(env):
            return None
        stripped = _strip_prefix(env)
        if stripped.startswith("DIR::"):
            if _validate_ccache(env):
                return env
            return None
        if _validate_ccache(env) or _validate_ccache(stripped):
            return env if env.startswith("FILE:") or env.startswith("DIR::") else stripped
        if os.path.exists(stripped) or os.path.isdir(stripped):
            return env if env.startswith("FILE:") or env.startswith("DIR::") else stripped

    klist_caches = _get_klist_caches()
    for raw in klist_caches:
        raw = raw.strip()
        if _is_keyring_or_kcm(raw):
            continue
        candidate = raw
        if raw.startswith("FILE:"):
            candidate = raw[5:]
        elif raw.startswith("DIR::"):
            candidate = raw
        if _validate_ccache(candidate) or _validate_ccache(raw):
            if raw.startswith("FILE:"):
                return raw[5:]
            return raw

    candidates = candidate_ccaches()
    valid = []
    for path in candidates:
        if _validate_ccache(path):
            try:
                mtime = os.path.getmtime(path if not path.startswith("DIR::") else path[5:])
            except Exception:
                try:
                    mtime = os.path.getmtime(_strip_prefix(path))
                except Exception:
                    mtime = 0
            valid.append((mtime, path))
    if valid:
        valid.sort(key=lambda x: x[0], reverse=True)
        best = valid[0][1]
        if best.startswith("FILE:"):
            return best[5:]
        return best
    return None
