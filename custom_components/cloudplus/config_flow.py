"""Config flow for CloudPlus / Meari integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult

from .const import (
    CONF_EMAIL,
    CONF_PASSWORD,
    CONF_COUNTRY_CODE,
    CONF_PHONE_CODE,
    DOMAIN,
)
from .api import MeariApiClient

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_COUNTRY_CODE): str,
        vol.Required(CONF_PHONE_CODE): str,
    }
)


class CloudPlusConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for CloudPlus / Meari."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Single step: collect credentials, auto-add all snap cameras."""
        errors: dict[str, str] = {}

        if user_input is not None:
            email = user_input[CONF_EMAIL].strip()
            password = user_input[CONF_PASSWORD]
            country_code = user_input[CONF_COUNTRY_CODE]
            phone_code = user_input[CONF_PHONE_CODE]

            client = MeariApiClient(email=email, password=password, country_code=country_code, phone_code=phone_code)

            try:
                await self.hass.async_add_executor_job(client.login)
                snap_devices = client.get_snap_devices()
            except PermissionError as e:
                _LOGGER.error(e)
                errors["base"] = "invalid_auth"
            except (ConnectionError, OSError) as e:
                _LOGGER.error(e)
                errors["base"] = "cannot_connect"
            except Exception as e:
                _LOGGER.error(e)
                _LOGGER.exception("Unexpected exception during login")
                errors["base"] = "unknown"
            else:
                if not snap_devices:
                    errors["base"] = "no_devices"
                else:
                    # One config entry per account — prevent duplicates
                    await self.async_set_unique_id(email.lower())
                    self._abort_if_unique_id_configured()

                    return self.async_create_entry(
                        title=f"CloudPlus ({email})",
                        data={
                            CONF_EMAIL: email,
                            CONF_PASSWORD: password,
                            CONF_COUNTRY_CODE: country_code,
                            CONF_PHONE_CODE: phone_code,
                        },
                    )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )
