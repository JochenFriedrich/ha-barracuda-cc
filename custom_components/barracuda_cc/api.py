"""Barracuda CloudGen Firewall Control Center REST API client.

Base URL: https://<CC-IP>:8443/rest/cc/v1
Auth:     X-API-Token header (preferred) or HTTP Basic

Hierarchy: Ranges → Clusters → Boxes
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

# Box connection/management state as reported by CC Status Map
BOX_STATES = {
    "ok": "ok",
    "warning": "warning",
    "error": "error",
    "unreachable": "unreachable",
    "unknown": "unknown",
}


class BarracudaCCAuthError(Exception):
    """Raised on authentication failure (401/403)."""


class BarracudaCCConnectionError(Exception):
    """Raised on connection / HTTP failure."""


@dataclass
class CCBox:
    """A single managed CloudGen Firewall."""
    range_name: str
    cluster_name: str
    box_name: str
    ip: str
    firmware: str
    state: str          # connected / unreachable / etc.
    ha_role: str        # primary / secondary / standalone
    model: str
    raw: dict           # full JSON for future use

    @property
    def unique_id(self) -> str:
        return f"{self.range_name}__{self.cluster_name}__{self.box_name}"

    @property
    def display_name(self) -> str:
        return f"{self.range_name} / {self.cluster_name} / {self.box_name}"


class BarracudaCCClient:
    """Async REST client for Barracuda CloudGen Firewall Control Center."""

    def __init__(
        self,
        host: str,
        port: int,
        api_token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._api_token = api_token
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._owned_session = session is None
        self._session = session or aiohttp.ClientSession()

    @property
    def _base_url(self) -> str:
        return f"https://{self._host}:{self._port}/rest/cc/v1"

    @property
    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self._api_token:
            headers["X-API-Token"] = self._api_token
        return headers

    @property
    def _auth(self) -> aiohttp.BasicAuth | None:
        if self._api_token:
            return None
        if self._username and self._password:
            return aiohttp.BasicAuth(self._username, self._password)
        return None

    async def _get(self, path: str) -> Any:
        url = f"{self._base_url}{path}"
        try:
            async with self._session.get(
                url,
                headers=self._headers,
                auth=self._auth,
                ssl=self._verify_ssl,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status in (401, 403):
                    raise BarracudaCCAuthError(f"Authentication failed: HTTP {resp.status}")
                resp.raise_for_status()
                return await resp.json()
        except BarracudaCCAuthError:
            raise
        except aiohttp.ClientConnectorError as err:
            raise BarracudaCCConnectionError(f"Cannot connect to CC at {url}: {err}") from err
        except aiohttp.ClientError as err:
            raise BarracudaCCConnectionError(f"Request failed: {err}") from err

    async def test_connection(self) -> bool:
        """Verify connectivity and auth by listing ranges."""
        await self._get("/ranges")
        return True

    async def get_ranges(self) -> list[str]:
        """Return list of range names."""
        data = await self._get("/ranges")
        # Response is typically {"ranges": ["range1", ...]} or a list
        if isinstance(data, dict):
            return data.get("ranges", [])
        return data or []

    async def get_clusters(self, range_name: str) -> list[str]:
        """Return cluster names for a given range."""
        data = await self._get(f"/ranges/{range_name}/clusters")
        if isinstance(data, dict):
            return data.get("clusters", [])
        return data or []

    async def get_boxes(self, range_name: str, cluster_name: str) -> list[dict]:
        """Return raw box dicts for a range/cluster."""
        data = await self._get(f"/ranges/{range_name}/clusters/{cluster_name}/boxes")
        if isinstance(data, dict):
            return data.get("boxes", [])
        return data or []

    async def get_box_status(self, range_name: str, cluster_name: str, box_name: str) -> dict:
        """Return status fields for a specific box."""
        try:
            return await self._get(
                f"/ranges/{range_name}/clusters/{cluster_name}/boxes/{box_name}/status"
            )
        except BarracudaCCConnectionError:
            # Status endpoint may not exist on older CC firmware; return empty
            return {}

    async def get_all_boxes(self) -> list[CCBox]:
        """Walk the full hierarchy and return all managed boxes."""
        boxes: list[CCBox] = []
        ranges = await self.get_ranges()

        for range_name in ranges:
            try:
                clusters = await self.get_clusters(range_name)
            except BarracudaCCConnectionError as err:
                _LOGGER.warning("Could not fetch clusters for range %s: %s", range_name, err)
                continue

            for cluster_name in clusters:
                try:
                    raw_boxes = await self.get_boxes(range_name, cluster_name)
                except BarracudaCCConnectionError as err:
                    _LOGGER.warning(
                        "Could not fetch boxes for %s/%s: %s", range_name, cluster_name, err
                    )
                    continue

                for box in raw_boxes:
                    name = box.get("name", box.get("boxname", "unknown"))
                    boxes.append(
                        CCBox(
                            range_name=range_name,
                            cluster_name=cluster_name,
                            box_name=name,
                            ip=box.get("ip", box.get("management_ip", "")),
                            firmware=box.get("firmware", box.get("version", "unknown")),
                            state=box.get("state", box.get("connection_state", "unknown")),
                            ha_role=box.get("ha_role", box.get("ha_state", "standalone")),
                            model=box.get("model", box.get("hw_type", "CloudGen Firewall")),
                            raw=box,
                        )
                    )

        return boxes

    async def close(self) -> None:
        if self._owned_session:
            await self._session.close()
