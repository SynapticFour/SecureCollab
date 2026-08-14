# SPDX-License-Identifier: Apache-2.0
"""Click CLI. Also usable as argparse-compatible `python -m securecollab.cli`."""
from __future__ import annotations

import getpass
import sys

import click

from .audit import verify_audit_trail
from .crypto import _secret_key_path, generate_key_share
from .exceptions import CryptoError
from .ops import (
    analyze_local_schema,
    compute_decryption_share,
    encrypt_and_upload,
    generate_study_report,
    negotiate_schema,
    run_dry_run,
    verify_study_public_key,
)
from .audit import write_local_audit


@click.group()
@click.option("--api-url", default="http://localhost:8000", envvar="SECURECOLLAB_API_URL", help="API base URL")
@click.pass_context
def cli(ctx, api_url):
    """SecureCollab SDK — local encryption and multi-party study workflow."""
    ctx.ensure_object(dict)
    ctx.obj["api_url"] = api_url


@cli.command("generate-key")
@click.option("--email", required=True, help="E-Mail der Institution")
def generate_key(email):
    """Generate a local CKKS key pair; secret is Fernet-wrapped on disk."""
    password = getpass.getpass("Passwort zum Schutz des Secret Keys (wird nicht gespeichert): ")
    if not password:
        click.echo("Passwort darf nicht leer sein.", err=True)
        sys.exit(1)
    try:
        r = generate_key_share(email, password)
    except CryptoError as e:
        click.echo(str(e), err=True)
        sys.exit(1)
    write_local_audit(email, "key_share_generated", {
        "key_fingerprint": r.get("key_fingerprint"),
        "secret_key_file": r.get("secret_key_file"),
    })
    click.echo("Public Key Share (base64) und Fingerprint wurden erzeugt.")
    click.echo(f"Key-Fingerprint: {r.get('key_fingerprint', '')}")
    click.echo(f"Secret Key gespeichert in: {_secret_key_path(email)}")
    click.echo(r["public_key_share"])


@cli.command("verify-study")
@click.option("--study-id", required=True)
@click.option("--url", "api_base_url", required=False)
@click.option("--email", default="")
@click.pass_context
def verify_study(ctx, study_id, api_base_url, email):
    """Verify the study public-key fingerprint locally."""
    url = api_base_url or ctx.obj["api_url"]
    r = verify_study_public_key(study_id, url, email=email)
    click.echo(f"Verifiziert: {r.get('verified')}")
    click.echo(f"Fingerprint: {r.get('fingerprint', '')}")
    if r.get("key_model"):
        click.echo(f"Key-Modell: {r['key_model']}")
    if r.get("error"):
        click.echo(f"Hinweis: {r['error']}")


@cli.command("upload")
@click.option("--csv", "csv_path", required=True, type=click.Path(exists=True))
@click.option("--study-id", required=True)
@click.option("--email", "institution_email", required=True)
@click.option("--url", "api_base_url", required=False)
@click.pass_context
def upload(ctx, csv_path, study_id, institution_email, api_base_url):
    """Encrypt a CSV under the study public key and upload the JSON bundle."""
    url = api_base_url or ctx.obj["api_url"]
    r = encrypt_and_upload(csv_path, study_id, institution_email, url)
    click.echo(f"Commitment-Hash: {r.get('commitment_hash', '')}")
    click.echo(f"Vom Server verifiziert: {r.get('verified')}")
    click.echo(f"Verschlüsselte Spalten: {r.get('columns_encrypted', [])}")
    if r.get("error"):
        click.echo(f"Fehler: {r['error']}", err=True)
        sys.exit(1)


@cli.command("decrypt-share")
@click.option("--study-id", required=True)
@click.option("--job-id", required=True)
@click.option("--email", "institution_email", required=True)
@click.option("--url", "api_base_url", required=False)
@click.pass_context
def decrypt_share(ctx, study_id, job_id, institution_email, api_base_url):
    """Authorize release of the encrypted result blob."""
    url = api_base_url or ctx.obj["api_url"]
    r = compute_decryption_share(study_id, job_id, institution_email, url)
    click.echo(f"Share eingereicht: {r.get('share_submitted')}")
    click.echo(f"Job-ID: {r.get('job_id', '')}")
    if r.get("error"):
        click.echo(f"Fehler: {r['error']}", err=True)
        sys.exit(1)


@cli.command("verify-audit")
@click.option("--study-id", required=True)
@click.option("--url", "api_base_url", required=False)
@click.option("--email", default="", dest="institution_email")
@click.pass_context
def verify_audit(ctx, study_id, api_base_url, institution_email):
    """Verify the server audit chain locally."""
    url = api_base_url or ctx.obj["api_url"]
    r = verify_audit_trail(study_id, url, institution_email)
    click.echo(f"Kette gültig: {r.get('chain_valid')}")
    click.echo(f"Eigene Einträge verifiziert: {r.get('own_entries_verified')}")
    click.echo(f"Anzahl Einträge: {r.get('total_entries')}")
    for a in r.get("anomalies", []):
        click.echo(f"Anomalie: {a}")


@cli.command("generate-report")
@click.option("--study-id", required=True)
@click.option("--url", "api_base_url", required=False)
@click.option("--email", default="", dest="institution_email")
@click.pass_context
def generate_report(ctx, study_id, api_base_url, institution_email):
    url = api_base_url or ctx.obj["api_url"]
    path = generate_study_report(study_id, url, institution_email)
    click.echo(f"Bericht gespeichert: {path}")


@cli.command("analyze-schema")
@click.option("--csv", "csv_path", required=True, type=click.Path(exists=True))
def analyze_schema(csv_path):
    r = analyze_local_schema(csv_path)
    if r.get("error"):
        click.echo(f"Fehler: {r['error']}", err=True)
        sys.exit(1)
    click.echo("Gefundene Spalten (lokal, keine Übertragung):")
    for c in r.get("columns", []):
        rng = c.get("range")
        rng_s = f"{rng[0]}-{rng[1]}" if rng else "—"
        click.echo(f"  {c['name']} ({c['type']}, {rng_s}, {c.get('null_pct', 0)}% missing)")


@cli.command("negotiate-schema")
@click.option("--csv", "csv_path", required=True, type=click.Path(exists=True))
@click.option("--study-id", required=True)
@click.option("--email", "institution_email", required=True)
@click.option("--url", "api_base_url", required=False)
@click.pass_context
def negotiate(ctx, csv_path, study_id, institution_email, api_base_url):
    url = api_base_url or ctx.obj["api_url"]
    r = negotiate_schema(csv_path, study_id, institution_email, url)
    write_local_audit(
        institution_email,
        "schema_negotiated",
        {"study_id": study_id, "compatible": r.get("compatible"), "issue_count": len(r.get("issues", []))},
    )
    click.echo(f"Kompatibel: {r.get('compatible')}")
    click.echo(f"Approved Mappings: {r.get('approved_mappings', [])}")
    for i in r.get("issues", []):
        click.echo(f"  ✗ {i}")
    for w in r.get("warnings", []):
        click.echo(f"  ⚠ {w}")


@cli.command("dry-run")
@click.option("--csv", "csv_path", required=True, type=click.Path(exists=True))
@click.option("--study-id", required=True)
@click.option("--email", "institution_email", required=True)
@click.option("--url", "api_base_url", required=False)
@click.pass_context
def dry_run(ctx, csv_path, study_id, institution_email, api_base_url):
    url = api_base_url or ctx.obj["api_url"]
    r = run_dry_run(csv_path, study_id, institution_email, url)
    click.echo(f"Schema gültig: {r.get('schema_valid')}")
    for i in r.get("issues", []):
        click.echo(f"  {i}")


def main():
    """Entry point for console_scripts and `python -m`."""
    cli(obj={})
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
