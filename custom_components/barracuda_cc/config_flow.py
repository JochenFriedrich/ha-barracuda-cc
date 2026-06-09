"""Config flow for Barracuda CloudGen Firewall Control Center."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .api import BarracudaCCAuthError, BarracudaCCClient, BarracudaCCConnectionError
from .const import (
    AUTH_METHOD_BASIC,
    AUTH_METHOD_TOKEN,
    CONF_API_TOKEN,
    CONF_AUTH_METHOD,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_AUTH_METHOD, default=AUTH_METHOD_TOKEN): vol.In(
            [AUTH_METHOD_TOKEN, AUTH_METHOD_BASIC]
        ),
        vol.Optional(CONF_API_TOKEN): str,
        vol.Optional(CONF_USERNAME): str,
        vol.Optional(CONF_PASSWORD): str,
        vol.Optional(CONF_VERIFY_SSL, default=True): bool,
    }
)


class BarracudaCCConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Barracuda CC."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_HOST]
            port = user_input[CONF_PORT]
            auth_method = user_input[CONF_AUTH_METHOD]

            # Validate required auth fields
            if auth_method == AUTH_METHOD_TOKEN and not user_input.get(CONF_API_TOKEN):
                errors[CONF_API_TOKEN] = "api_token_required"
            elif auth_method == AUTH_METHOD_BASIC and (
                not user_input.get(CONF_USERNAME) or not user_input.get(CONF_PASSWORD)
            ):
                errors["base"] = "credentials_required"
            else:
                await self.async_set_unique_id(f"{host}:{port}")
                self._abort_if_unique_id_configured()

                client = BarracudaCCClient(
                    host=host,
                    port=port,
                    api_token=user_input.get(CONF_API_TOKEN),
                    username=user_input.get(CONF_USERNAME),
                    password=user_input.get(CONF_PASSWORD),
                    verify_ssl=user_input[CONF_VERIFY_SSL],
                )
                try:
                    await client.test_connection()
                    await client.close()
                except BarracudaCCAuthError:
                    errors["base"] = "invalid_auth"
                except BarracudaCCConnectionError:
                    errors["base"] = "cannot_connect"
                except Exception:  # noqa: BLE001
                    _LOGGER.exception("Unexpected error during Barracuda CC config flow")
                    errors["base"] = "unknown"
                else:
                    return self.async_create_entry(
                        title=f"Barracuda CC ({host})",
                        data=user_input,
                    )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_SCHEMA,
            errors=errors,
        )
