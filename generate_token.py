"""
generate_token.py
-----------------
CLI utility for trusted operators to generate signed VPAP JWT access tokens out-of-band.

Usage:
  py generate_token.py
  py generate_token.py --tenant vpap-pilot --scope audit:read
  py generate_token.py --tenant vpap-pilot --scope "audit:read audit:write" --subject security-admin
"""

import argparse
import sys
from auth import issue_token, TOKEN_LIFETIME_SECONDS, TOKEN_ISSUER, TOKEN_AUDIENCE


def main():
    parser = argparse.ArgumentParser(
        description="Generate signed VPAP JWT access tokens for API and UI authentication."
    )
    parser.add_argument(
        "--tenant",
        default="vpap-pilot",
        help="Target tenant ID (default: 'vpap-pilot')",
    )
    parser.add_argument(
        "--scope",
        default="audit:read",
        help="Access scope (default: 'audit:read', e.g., 'audit:read audit:write')",
    )
    parser.add_argument(
        "--subject",
        default="audit-ui-operator",
        help="Subject / actor identity (default: 'audit-ui-operator')",
    )

    parser.add_argument(
        "--services",
        action="store_true",
        help="Generate tokens for all 3 core VPAP services (Ingestion, Enrichment, Policy Engine)",
    )

    args = parser.parse_args()

    if args.services:
        services = [
            ("ingestion-service", "persistence:*"),
            ("enrichment-service", "persistence:*"),
            ("policy-engine", "persistence:*"),
            ("audit-ui-operator", "audit:read"),
        ]
        print("=" * 75)
        print(f"VPAP SERVICE TOKENS (Tenant: {args.tenant})")
        print("=" * 75)
        for subject, scope in services:
            t = issue_token(tenant_id=args.tenant, scope=scope, subject=subject)
            print(f"\n[*] Service: {subject}")
            print(f"    Scope  : {scope}")
            print(f"    Token  :\n{t['access_token']}\n")
        print("=" * 75)
        return

    token_data = issue_token(
        tenant_id=args.tenant,
        scope=args.scope,
        subject=args.subject,
    )

    print("=" * 70)
    print("VPAP ACCESS TOKEN GENERATED")
    print("=" * 70)
    print(f"Tenant ID  : {token_data['tenant_id']}")
    print(f"Subject    : {token_data['subject']}")
    print(f"Scope      : {token_data['scope']}")
    print(f"Issuer     : {TOKEN_ISSUER}")
    print(f"Audience   : {TOKEN_AUDIENCE}")
    print(f"Expires In : {token_data['expires_in']} seconds (8 hours)")
    print("-" * 70)
    print("ACCESS TOKEN:")
    print(token_data["access_token"])
    print("-" * 70)
    print("HTTP HEADER:")
    print(f"Authorization: Bearer {token_data['access_token']}")
    print("=" * 70)


if __name__ == "__main__":
    main()
