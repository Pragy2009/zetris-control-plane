#!/usr/bin/env python3
"""Provision connector mTLS and its server-owned tenant grant; requires OpenSSL.

Private CA material stays on Node 1. Existing key material is never overwritten.
"""
import argparse
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


def load_grants(path):
    grants = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if not isinstance(grants, dict):
        raise RuntimeError("Connector grants must be a fingerprint map")
    owners = {}
    for fingerprint, grant in grants.items():
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or not isinstance(grant, dict):
            raise RuntimeError("Invalid certificate grant")
        connector, tenants = grant.get("id"), grant.get("tenants")
        if (not isinstance(connector, str) or not IDENTIFIER.fullmatch(connector)
                or not isinstance(tenants, list) or len(tenants) != 1
                or not isinstance(tenants[0], str) or not IDENTIFIER.fullmatch(tenants[0])):
            raise RuntimeError("Each connector grant must have exactly one valid tenant")
        if connector in owners and owners[connector] != tenants[0]:
            raise RuntimeError("Connector ID has conflicting tenant ownership")
        owners[connector] = tenants[0]
    return grants


@contextmanager
def grant_lock(path):
    # Serialize issuance and read/modify/write. An interrupted process leaves
    # a lock for operator inspection rather than silently losing another grant.
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(".lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise RuntimeError("Connector provisioning is locked; inspect before retrying") from None
    os.close(descriptor)
    try:
        yield
    finally:
        lock.unlink()


def issue_connector(ca, root, out, connector, tenant):
    path = root / "config" / "connector-access.json"
    with grant_lock(path):
        grants = load_grants(path)
        for grant in grants.values():
            if grant["id"] == connector and grant["tenants"] != [tenant]:
                raise RuntimeError("Refusing to reassign an existing connector to another tenant")
        cert = certificate(ca, out, "client", f"/CN={connector}",
                           "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature")
        fingerprint = hashlib.sha256(openssl("x509", "-in", cert, "-outform", "DER")).hexdigest()
        grants = {k: v for k, v in grants.items() if v["id"] != connector}
        grants[fingerprint] = {"id": connector, "tenants": [tenant]}
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(grants, stream, indent=2)
                stream.write("\n")
            temporary.replace(path)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

def openssl(*args):
    return subprocess.check_output(["openssl", *map(str, args)], stderr=subprocess.PIPE)

def certificate(ca, out, name, subject, extensions):
    key, csr, cert, ext = (out / (name + s) for s in (".key", ".csr", ".crt", ".ext"))
    if key.exists() or cert.exists():
        raise SystemExit(f"Refusing to replace existing certificate/key: {out / name}")
    out.mkdir(parents=True, exist_ok=True)
    ext.write_text(extensions + "\n", encoding="utf-8")
    openssl("req", "-newkey", "rsa:3072", "-nodes", "-keyout", key, "-out", csr, "-subj", subject)
    key.chmod(0o600)
    openssl("x509", "-req", "-in", csr, "-CA", ca / "ca.crt", "-CAkey", ca / "ca.key",
            "-CAcreateserial", "-out", cert, "-days", "365", "-sha256", "-extfile", ext)
    csr.unlink(); ext.unlink()
    shutil.copyfile(ca / "ca.crt", out / "ca.crt")
    return cert

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--ca-dir", type=Path)
    sub = parser.add_subparsers(dest="action", required=True)
    init = sub.add_parser("init")
    init.add_argument("--mesh-ip", required=True)
    issue = sub.add_parser("issue")
    issue.add_argument("--connector", required=True)
    issue.add_argument("--tenant", required=True)
    issue.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    ca = args.ca_dir or args.root / ".connector-ca"
    if args.action == "init":
        ipaddress.ip_address(args.mesh_ip)
        server_dir = args.root / "score-service" / "dev" / "certs"
        if (server_dir / "server.key").exists() or (server_dir / "server.crt").exists():
            raise SystemExit("Existing server credentials found. Preserve their CA; do not reinitialize a live deployment.")
        ca.mkdir(parents=True, exist_ok=True)
        if (ca / "ca.key").exists() != (ca / "ca.crt").exists():
            raise RuntimeError("Incomplete connector CA material; inspect before retrying")
        if not (ca / "ca.key").exists() and not (ca / "ca.crt").exists():
            openssl("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "3650",
                    "-keyout", ca / "ca.key", "-out", ca / "ca.crt", "-subj", "/CN=Zetris Connector CA",
                    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            (ca / "ca.key").chmod(0o600)
        certificate(ca, server_dir, "server", "/CN=TEcert.local",
                    "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
                    "keyUsage=critical,digitalSignature,keyEncipherment\n"
                    f"subjectAltName=DNS:TEcert.local,DNS:localhost,DNS:score-service,IP:127.0.0.1,IP:{args.mesh_ip}")
        print("Created connector CA and control-plane server certificate.")
    else:
        for value in (args.connector, args.tenant):
            if not IDENTIFIER.fullmatch(value):
                raise SystemExit("Invalid connector/tenant identifier")
        issue_connector(ca, args.root, args.out, args.connector, args.tenant)
        print(f"Issued {args.connector} for {args.tenant}")
        print("Copy only client.crt, client.key and ca.crt to that connector; recreate score-service to reload grants.")

if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from None
    except Exception as exc:
        raise SystemExit("Provisioning failed: " + type(exc).__name__ + " (details withheld)") from None
