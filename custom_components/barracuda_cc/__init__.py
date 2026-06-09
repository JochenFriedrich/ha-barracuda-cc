"""Barracuda CloudGen Firewall Control Center integration."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    BarracudaCCAuthError,
    BarracudaCCClient,
    BarracudaCCConnectionError,
    CCBox,
)
from .const import (
    AUTH_METHOD_TOKEN,
    CLIENT,
    CONF_API_TOKEN,
    CONF_AUTH_METHOD,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    COORDINATOR,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Barracuda CC from a config entry."""
    auth_method = entry.data.get(CONF_AUTH_METHOD, AUTH_METHOD_TOKEN)

    client = BarracudaCCClient(
        host=entry.data[CONF_HOST],
        port=entry.data[CONF_PORT],
        api_token=entry.data.get(CONF_API_TOKEN) if auth_method == AUTH_METHOD_TOKEN else None,
        username=entry.data.get(CONF_USERNAME),
        password=entry.data.get(CONF_PASSWORD),
        verify_ssl=entry.data.get(CONF_VERIFY_SSL, True),
    )

    try:
        await client.test_connection()
    except BarracudaCCAuthError as err:
        raise ConfigEntryAuthFailed from err
    except BarracudaCCConnectionError as err:
        raise ConfigEntryNotReady from err

    async def _async_update_data() -> list[CCBox]:
        try:
            return await client.get_all_boxes()
        except BarracudaCCAuthError as err:
            raise ConfigEntryAuthFailed from err
        except BarracudaCCConnectionError as err:
            raise UpdateFailed(f"Error communicating with Barracuda CC: {err}") from err

    coordinator: DataUpdateCoordinator[list[CCBox]] = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=DOMAIN,
        update_method=_async_update_data,
        update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
    )

    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        COORDINATOR: coordinator,
        CLIENT: client,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        entry_data = hass.data[DOMAIN].pop(entry.entry_id)
        await entry_data[CLIENT].close()
    return unload_ok
