#!/usr/bin/env python3

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


INFISICAL_URL = os.environ["INFISICAL_URL"].rstrip("/")
CLIENT_ID = os.environ["INFISICAL_CLIENT_ID"]
CLIENT_SECRET = os.environ["INFISICAL_CLIENT_SECRET"]
PROJECT_ID = os.environ["INFISICAL_PROJECT_ID"]

ENVIRONMENT = os.getenv(
    "INFISICAL_ENVIRONMENT",
    "prod",
)

SECRET_PATH = os.getenv(
    "INFISICAL_SECRET_PATH",
    "/",
)


SECRET_MAPPING = {
    "UNIFI_API_KEY": os.getenv(
        "INFISICAL_UNIFI_SECRET_NAME",
        "UNIFI_API_KEY",
    ),
    "DNS01_TOKEN": os.getenv(
        "INFISICAL_DNS01_SECRET_NAME",
        "DNS01_TOKEN",
    ),
    "DNS02_TOKEN": os.getenv(
        "INFISICAL_DNS02_SECRET_NAME",
        "DNS02_TOKEN",
    ),
}


if urllib.parse.urlparse(INFISICAL_URL).scheme != "https":
    raise RuntimeError("INFISICAL_URL must use HTTPS")

SSL_CONTEXT = ssl.create_default_context()


def request_json(
    url,
    method="GET",
    headers=None,
    data=None,
):
    req = urllib.request.Request(
        url,
        data=data,
        headers=headers or {},
        method=method,
    )

    try:
        with urllib.request.urlopen(
            req,
            timeout=20,
            context=SSL_CONTEXT,
        ) as response:

            body = response.read()

            return json.loads(
                body.decode("utf-8")
            )

    except urllib.error.HTTPError as exc:

        body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        raise RuntimeError(
            f"HTTP {exc.code}"
        ) from exc


def authenticate():
    print(
        "Authenticating against Infisical...",
        flush=True,
    )

    payload = json.dumps(
        {
            "clientId": CLIENT_ID,
            "clientSecret": CLIENT_SECRET,
        }
    ).encode("utf-8")

    result = request_json(
        f"{INFISICAL_URL}/api/v1/auth/universal-auth/login",
        method="POST",
        headers={
            "Content-Type": "application/json",
        },
        data=payload,
    )

    token = result.get("accessToken")

    if not token:
        raise RuntimeError(
            "Infisical authentication returned no accessToken"
        )

    print(
        "Infisical authentication successful.",
        flush=True,
    )

    return token


def load_secret(
    access_token,
    secret_name,
):
    encoded_name = urllib.parse.quote(
        secret_name,
        safe="",
    )

    query = urllib.parse.urlencode(
        {
            "projectId": PROJECT_ID,
            "environment": ENVIRONMENT,
            "secretPath": SECRET_PATH,
            "expandSecretReferences": "true",
        }
    )

    url = (
        f"{INFISICAL_URL}"
        f"/api/v4/secrets/{encoded_name}"
        f"?{query}"
    )

    result = request_json(
        url,
        headers={
            "Authorization":
                f"Bearer {access_token}",
            "Accept": "application/json",
        },
    )

    secret = result.get("secret")

    if isinstance(secret, dict):
        value = secret.get("secretValue")
    else:
        value = result.get("secretValue")

    if not value:
        raise RuntimeError(
            f"Secret '{secret_name}' has no secretValue"
        )

    return value


def main():
    try:
        access_token = authenticate()

        for env_name, secret_name in SECRET_MAPPING.items():

            value = load_secret(
                access_token,
                secret_name,
            )

            os.environ[env_name] = value

            print(
                f"Loaded {env_name} from Infisical "
                f"secret '{secret_name}'.",
                flush=True,
            )

        print(
            "Starting UniFi DNS Sync...",
            flush=True,
        )

        os.execv(
            sys.executable,
            [
                sys.executable,
                os.path.join(os.path.dirname(__file__), "sync.py"),
            ],
        )

    except Exception as exc:

        print(
            f"Bootstrap failed: {exc}",
            file=sys.stderr,
            flush=True,
        )

        sys.exit(1)


if __name__ == "__main__":
    main()
