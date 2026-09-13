"""
generate_token.py
-----------------
Run this LOCALLY (never deploy it, never expose it over HTTP) to
pre-issue a token for a teammate's service.

The token is signed using the same VPAP_AUTH_SECRET that the live
audit API uses for JWT validation.

Set the secret locally before running:

PowerShell:
    $env:VPAP_AUTH_SECRET = "<same value as set on Render>"

Usage:
    py generate_token.py --subject ingestion-service --tenant-id vpap-pilot
    py generate_token.py --subject policy-engine --tenant-id vpap-pilot
    py generate_token.py --subject enrichment-service --tenant-id vpap-pilot --scope "persistence:read"
"""

import argparse

from auth import issue_token


DEFAULT_SUBJECT = "enrichment-service"
DEFAULT_SCOPE = "persistence:*"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Issue a VPAP access token for a specific teammate/service."
    )

    parser.add_argument(
        "--subject",
        default=DEFAULT_SUBJECT,
        help=(
            "Who this token identifies, e.g. "
            "'ingestion-service', 'policy-engine' "
            f"(default: {DEFAULT_SUBJECT})"
        ),
    )

    parser.add_argument(
        "--tenant-id",
        required=True,
        help="Tenant this token is scoped to.",
    )

    parser.add_argument(
        "--scope",
        default=DEFAULT_SCOPE,
        help=f"Access scope (default: {DEFAULT_SCOPE})",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    result = issue_token(
        tenant_id=args.tenant_id,
        scope=args.scope,
        subject=args.subject,
    )

    print("Token issued for:")
    print(f"  subject   = {args.subject}")
    print(f"  tenant_id = {args.tenant_id}")
    print(f"  scope     = {args.scope}")
    print(
        f"  expires_in = {result['expires_in']} seconds "
        f"({result['expires_in'] / 3600:.0f} hours)"
    )

    print()
    print("access_token (share this securely, NOT in chat):")
    print(result["access_token"])