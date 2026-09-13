"""
generate_token.py
-----------------

Generate a VPAP access token for a specific service.

LOCAL USAGE:
    This script can be run locally by a trusted operator.

AUTOMATED USAGE:
    GitHub Actions can run this script with --quiet and capture the
    generated token without printing additional information.

The token is signed using the same VPAP_AUTH_SECRET that the live
audit API uses for JWT validation.

PowerShell:
    $env:VPAP_AUTH_SECRET = "<same value as set on Render>"

Normal usage:
    py generate_token.py --subject ingestion-service --tenant-id vpap-pilot
    py generate_token.py --subject policy-engine --tenant-id vpap-pilot
    py generate_token.py --subject enrichment-service --tenant-id vpap-pilot

Restricted scope:
    py generate_token.py `
        --subject enrichment-service `
        --tenant-id vpap-pilot `
        --scope "persistence:read"

GitHub Actions / automation:
    python generate_token.py `
        --subject ingestion-service `
        --tenant-id vpap-pilot `
        --quiet

IMPORTANT:
    Never commit generated tokens.
    Never print generated tokens into CI logs.
    Never expose VPAP_AUTH_SECRET.
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
            "'ingestion-service', 'policy-engine', "
            f"'enrichment-service' (default: {DEFAULT_SUBJECT})"
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

    parser.add_argument(
        "--quiet",
        action="store_true",
        help=(
            "Print only the generated access token. "
            "Use this mode for automated workflows such as GitHub Actions."
        ),
    )

    return parser.parse_args()


def main():
    args = parse_args()

    result = issue_token(
        tenant_id=args.tenant_id,
        scope=args.scope,
        subject=args.subject,
    )

    access_token = result["access_token"]

    # ---------------------------------------------------------
    # AUTOMATION MODE
    # ---------------------------------------------------------
    # GitHub Actions can capture stdout directly:
    #
    # TOKEN=$(python generate_token.py --quiet ...)
    #
    # No additional information is printed.
    # ---------------------------------------------------------
    if args.quiet:
        print(access_token)
        return

    # ---------------------------------------------------------
    # NORMAL LOCAL MODE
    # ---------------------------------------------------------
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
    print(access_token)


if __name__ == "__main__":
    main()