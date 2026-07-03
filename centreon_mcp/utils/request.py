import json
import os
import ssl
from copy import deepcopy

import httpx
from fastmcp.server.dependencies import get_http_headers
from httpx import AsyncClient

from centreon_mcp import CREDENTIALS
from centreon_mcp.utils import logger


def _as_bool(value: str | bool) -> bool:
    """
    Convert environment-style boolean strings to bool.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _build_tls_verify() -> bool | str | ssl.SSLContext:
    """
    Build HTTPX TLS verify setting from environment credentials.
    """
    if _as_bool(CREDENTIALS.get("CENTREON_TLS_INSECURE", "false")):
        logger.warning(
            "CENTREON_TLS_INSECURE is enabled: TLS certificate verification is disabled."
        )
        return False

    ca_bundle = str(CREDENTIALS.get("CENTREON_CA_BUNDLE", "")).strip()
    if ca_bundle:
        if os.path.isfile(ca_bundle):
            return ca_bundle
        logger.warning(
            f"Ignoring CENTREON_CA_BUNDLE='{ca_bundle}': file does not exist. "
            "Falling back to system/default CA trust."
        )

    if _as_bool(CREDENTIALS.get("CENTREON_USE_SYSTEM_CA_STORE", "true")):
        try:
            import truststore  # type: ignore[import-untyped]

            return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except ImportError:
            logger.warning(
                "CENTREON_USE_SYSTEM_CA_STORE is enabled but truststore is not installed. "
                "Falling back to default CA bundle."
            )

    return True


def hide(headers: dict | None) -> dict | None:
    """
    Hide Centreon API token in headers for logging
    """
    if headers is None:
        return None

    hidden = deepcopy(headers)
    token = headers["X-AUTH-TOKEN"]
    size = 6
    hidden["X-AUTH-TOKEN"] = (len(token) - size) * "*" + token[-size:]
    return hidden


class CentreonAPIError(Exception):
    """
    Custom exception for Centreon API errors.
    """

    def __init__(self, status: int, url: str, method: str, content: dict) -> None:
        self.status = status
        self.url = url
        self.method = method
        self.content = content

    def __str__(self) -> str:
        """
        Return string representation of the error.
        """
        content = "\n".join(f"  {key}: {value}" for key, value in self.content.items())
        return (
            f"\nCentreon API Error [{self.status}]"
            f"\nMethod: {self.method}"
            f"\nURL: {self.url}"
            f"\nContent:\n{content}"
        )


async def request(
    method: str, endpoint: str, payload: dict | None = None, params: dict | None = None
) -> dict:
    """
    Make request to Centreon API.
    """
    # Build request arguments
    base = CREDENTIALS["CENTREON_BASE_URL"]
    token = get_http_headers().get("centreon-api-token") or CREDENTIALS.get("CENTREON_API_TOKEN")
    url = f"{base}/api/latest/{endpoint}"
    headers = {"X-AUTH-TOKEN": token} if token else None
    params = params or {}
    params = {name: value for name, value in params.items() if value is not None}

    # Make request and handle response
    logger.debug(
        f"Centreon API Request: {method} {url}\n"
        f"Headers: {json.dumps(hide(headers), indent=2)}\n"
        f"Params: {json.dumps(params, indent=2)}\n"
        f"Payload: {json.dumps(payload, indent=2)}"
    )
    try:
        verify: bool | str | ssl.SSLContext = _build_tls_verify()
        async with AsyncClient(verify=verify) as client:
            response = await client.request(
                method, url, headers=headers, json=payload, params=params
            )
            try:
                content = (
                    response.json() if (response.status_code != 204 and response.content) else {}
                )
            except json.JSONDecodeError:
                logger.warning(
                    f"Non-JSON response from {method} {url} (status {response.status_code}): {response.text[:500]}"
                )
                content = {"raw": response.text}

            logger.debug(
                f"Centreon API Response: {response.status_code}\n"
                f"Content: {json.dumps(content, indent=2)}"
            )
            response.raise_for_status()
            return content

    except httpx.HTTPStatusError as e:
        status = e.response.status_code
        url = str(e.request.url)
        error = CentreonAPIError(status, url, method, content)
        logger.error(error)
        raise error from e
