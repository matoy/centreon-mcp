from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import HTTPStatusError, Request, Response

from centreon_mcp import CREDENTIALS
from centreon_mcp.utils.request import CentreonAPIError, request

MODULE = "centreon_mcp.utils.request"


@patch(f"{MODULE}.AsyncClient", new_callable=MagicMock)
@patch(f"{MODULE}.get_http_headers", new_callable=MagicMock)
@patch(f"{MODULE}.logger", new_callable=MagicMock)
async def test_request(logger: MagicMock, get_http_headers: MagicMock, client_cls: MagicMock):

    # Setup args
    method = "GET"
    endpoint = "some/endpoint"
    params: dict = {}
    payload: dict = {}

    # Mock logger
    logger.debug.return_value = None

    # Mock get_http_hearders
    token = "token"
    get_http_headers.return_value = {"centreon-api-token": token}

    original = CREDENTIALS["CENTREON_USE_SYSTEM_CA_STORE"]
    CREDENTIALS["CENTREON_USE_SYSTEM_CA_STORE"] = "false"

    # Mock AsyncClient.request
    content: dict = {}
    client, response = AsyncMock(), MagicMock()
    response.json.return_value = content
    client.request.return_value = response
    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = client
    context_manager.__aexit__.return_value = None
    client_cls.return_value = context_manager

    try:
        # Call test function
        result = await request(method, endpoint, payload, params)

        # Assert logger was called
        assert logger.debug.call_count == 2

        # Assert request was called with good args
        base = CREDENTIALS["CENTREON_BASE_URL"]
        url = f"{base}/api/latest/{endpoint}"
        headers = {"X-AUTH-TOKEN": token}
        client_cls.assert_called_once_with(verify=True)
        client.request.assert_awaited_once_with(
            method, url, headers=headers, json=payload, params=params
        )

        # Assert request output
        assert result == content
    finally:
        CREDENTIALS["CENTREON_USE_SYSTEM_CA_STORE"] = original


@patch(f"{MODULE}.AsyncClient", new_callable=MagicMock)
@patch(f"{MODULE}.get_http_headers", new_callable=MagicMock)
@patch(f"{MODULE}.logger", new_callable=MagicMock)
async def test_request_with_env_token_fallback(
    logger: MagicMock, get_http_headers: MagicMock, client_cls: MagicMock
):

    method = "GET"
    endpoint = "some/endpoint"
    params: dict = {}
    payload: dict = {}

    logger.debug.return_value = None
    get_http_headers.return_value = {}

    original_token = CREDENTIALS.get("CENTREON_API_TOKEN", "")
    original_use_system = CREDENTIALS["CENTREON_USE_SYSTEM_CA_STORE"]
    CREDENTIALS["CENTREON_API_TOKEN"] = "env-token"
    CREDENTIALS["CENTREON_USE_SYSTEM_CA_STORE"] = "false"

    content: dict = {}
    client, response = AsyncMock(), MagicMock()
    response.json.return_value = content
    client.request.return_value = response
    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = client
    context_manager.__aexit__.return_value = None
    client_cls.return_value = context_manager

    try:
        result = await request(method, endpoint, payload, params)
        base = CREDENTIALS["CENTREON_BASE_URL"]
        url = f"{base}/api/latest/{endpoint}"
        headers = {"X-AUTH-TOKEN": "env-token"}
        client.request.assert_awaited_once_with(
            method, url, headers=headers, json=payload, params=params
        )
        assert result == content
    finally:
        CREDENTIALS["CENTREON_API_TOKEN"] = original_token
        CREDENTIALS["CENTREON_USE_SYSTEM_CA_STORE"] = original_use_system


@patch(f"{MODULE}.AsyncClient", new_callable=MagicMock)
@patch(f"{MODULE}.get_http_headers", new_callable=MagicMock)
@patch(f"{MODULE}.logger", new_callable=MagicMock)
async def test_request_centreon_api_error(
    logger: MagicMock, get_http_headers: MagicMock, client_cls: MagicMock
):

    # Setup args
    method = "GET"
    endpoint = "some/endpoint"
    params: dict = {}
    payload: dict = {}

    # Mock logger
    logger.debug.return_value = None

    # Mock get_http_hearders
    token = "token"
    get_http_headers.return_value = {"centreon-api-token": token}

    # Mock AsyncClient.request
    content: dict = {}
    client, response = AsyncMock(), MagicMock()
    response.json.return_value = content
    client.request.return_value = response
    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = client
    context_manager.__aexit__.return_value = None
    client_cls.return_value = context_manager

    # Mock response.raise_for_status to raise an error
    response.raise_for_status.side_effect = HTTPStatusError(
        message="Error",
        request=Request("GET", "http://localhost/api/latest/some/endpoint"),
        response=Response(500),
    )

    # Call test function
    with pytest.raises(CentreonAPIError):
        _ = await request(method, endpoint, payload, params)


@patch(f"{MODULE}.AsyncClient", new_callable=MagicMock)
@patch(f"{MODULE}.get_http_headers", new_callable=MagicMock)
@patch(f"{MODULE}.logger", new_callable=MagicMock)
async def test_request_with_custom_ca_bundle(
    logger: MagicMock, get_http_headers: MagicMock, client_cls: MagicMock
):

    method = "GET"
    endpoint = "some/endpoint"
    params: dict = {}
    payload: dict = {}
    token = "token"

    logger.debug.return_value = None
    get_http_headers.return_value = {"centreon-api-token": token}

    original = CREDENTIALS["CENTREON_CA_BUNDLE"]
    CREDENTIALS["CENTREON_CA_BUNDLE"] = "/tmp/ca.pem"

    client, response = AsyncMock(), MagicMock()
    response.json.return_value = {}
    client.request.return_value = response
    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = client
    context_manager.__aexit__.return_value = None
    client_cls.return_value = context_manager

    try:
        await request(method, endpoint, payload, params)
        client_cls.assert_called_once_with(verify="/tmp/ca.pem")
    finally:
        CREDENTIALS["CENTREON_CA_BUNDLE"] = original


@patch(f"{MODULE}.AsyncClient", new_callable=MagicMock)
@patch(f"{MODULE}.get_http_headers", new_callable=MagicMock)
@patch(f"{MODULE}.logger", new_callable=MagicMock)
async def test_request_with_insecure_tls(
    logger: MagicMock, get_http_headers: MagicMock, client_cls: MagicMock
):

    method = "GET"
    endpoint = "some/endpoint"
    params: dict = {}
    payload: dict = {}
    token = "token"

    logger.debug.return_value = None
    get_http_headers.return_value = {"centreon-api-token": token}

    original = CREDENTIALS["CENTREON_TLS_INSECURE"]
    CREDENTIALS["CENTREON_TLS_INSECURE"] = "true"

    client, response = AsyncMock(), MagicMock()
    response.json.return_value = {}
    client.request.return_value = response
    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = client
    context_manager.__aexit__.return_value = None
    client_cls.return_value = context_manager

    try:
        await request(method, endpoint, payload, params)
        client_cls.assert_called_once_with(verify=False)
    finally:
        CREDENTIALS["CENTREON_TLS_INSECURE"] = original


@patch(f"{MODULE}.AsyncClient", new_callable=MagicMock)
@patch(f"{MODULE}.get_http_headers", new_callable=MagicMock)
@patch(f"{MODULE}.logger", new_callable=MagicMock)
async def test_request_with_invalid_ca_bundle_falls_back_to_default_verify(
    logger: MagicMock, get_http_headers: MagicMock, client_cls: MagicMock
):
    method = "GET"
    endpoint = "some/endpoint"
    params: dict = {}
    payload: dict = {}
    token = "token"

    logger.debug.return_value = None
    get_http_headers.return_value = {"centreon-api-token": token}

    original_ca_bundle = CREDENTIALS["CENTREON_CA_BUNDLE"]
    original_use_system = CREDENTIALS["CENTREON_USE_SYSTEM_CA_STORE"]
    CREDENTIALS["CENTREON_CA_BUNDLE"] = "this-file-does-not-exist.pem"
    CREDENTIALS["CENTREON_USE_SYSTEM_CA_STORE"] = "false"

    client, response = AsyncMock(), MagicMock()
    response.json.return_value = {}
    client.request.return_value = response
    context_manager = AsyncMock()
    context_manager.__aenter__.return_value = client
    context_manager.__aexit__.return_value = None
    client_cls.return_value = context_manager

    try:
        await request(method, endpoint, payload, params)
        client_cls.assert_called_once_with(verify=True)
    finally:
        CREDENTIALS["CENTREON_CA_BUNDLE"] = original_ca_bundle
        CREDENTIALS["CENTREON_USE_SYSTEM_CA_STORE"] = original_use_system
