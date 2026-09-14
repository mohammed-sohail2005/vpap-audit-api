"""Small local smoke test for token_client.py."""

from token_client import VpapTokenClient, VpapTokenError


def main() -> None:
    client = VpapTokenClient()

    try:
        token = client.get_token()
    except VpapTokenError as exc:
        raise SystemExit(f"Token vending failed: {exc}") from exc

    print("Token vending: OK")
    print("JWT received and cached in memory.")
    print(f"API base: {client.base_url}")
    print("Token value intentionally not printed.")


if __name__ == "__main__":
    main()
