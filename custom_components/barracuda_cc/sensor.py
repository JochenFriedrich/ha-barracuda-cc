"""Sensor platform for Barracuda CloudGen Firewall Control Center.

One device per managed box, with sensors for state, firmware, HA role, IP, and model.
Device name follows the CC hierarchy: Range / Cluster / Box
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity, DataUpdateCoordinator

from .api import CCBox
from .const import COORDINATOR, DOMAIN

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CCBoxSensorDescription(SensorEntityDescription):
    """Extended description with a value extractor."""
    value_fn: Callable[[CCBox], str | None] = lambda b: None


SENSOR_DESCRIPTIONS: tuple[CCBoxSensorDescription, ...] = (
    CCBoxSensorDescription(
        key="state",
        name="Connection State",
        icon="mdi:connection",
        value_fn=lambda b: b.state,
    ),
    CCBoxSensorDescription(
        key="firmware",
        name="Firmware Version",
        icon="mdi:package-up",
        value_fn=lambda b: b.firmware,
    ),
    CCBoxSensorDescription(
        key="ha_role",
        name="HA Role",
        icon="mdi:server-network",
        value_fn=lambda b: b.ha_role,
    ),
    CCBoxSensorDescription(
        key="ip",
        name="IP Address",
        icon="mdi:ip-network",
        value_fn=lambda b: b.ip,
    ),
    CCBoxSensorDescription(
        key="model",
        name="Model",
        icon="mdi:chip",
        value_fn=lambda b: b.model,
    ),
    CCBoxSensorDescription(
        key="range",
        name="Range",
        icon="mdi:folder-network",
        value_fn=lambda b: b.range_name,
    ),
    CCBoxSensorDescription(
        key="cluster",
        name="Cluster",
        icon="mdi:folder",
        value_fn=lambda b: b.cluster_name,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Barracuda CC sensors."""
    coordinator: DataUpdateCoordinator[list[CCBox]] = hass.data[DOMAIN][entry.entry_id][COORDINATOR]
    known: set[str] = set()

    def _add_new_boxes() -> None:
        if not coordinator.data:
            return
        new_entities: list[CCBoxSensor] = []
        for box in coordinator.data:
            if box.unique_id in known:
                continue
            known.add(box.unique_id)
            for desc in SENSOR_DESCRIPTIONS:
                new_entities.append(CCBoxSensor(coordinator, box, desc))
            new_entities.append(CCBoxRawDiagnostic(coordinator, box))
        if new_entities:
            async_add_entities(new_entities)

    _add_new_boxes()
    entry.async_on_unload(coordinator.async_add_listener(_add_new_boxes))


class CCBoxSensor(CoordinatorEntity[DataUpdateCoordinator[list[CCBox]]], SensorEntity):
    """A single sensor for one attribute of a CC-managed box."""

    entity_description: CCBoxSensorDescription

    def __init__(
        self,
        coordinator: DataUpdateCoordinator[list[CCBox]],
        box: CCBox,
        description: CCBoxSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._box_uid = box.unique_id

        self._attr_unique_id = f"{box.unique_id}_{description.key}"
        self._attr_name = f"{box.display_name} {description.name}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, box.unique_id)},
            name=box.display_name,
            manufacturer="Barracuda Networks",
            model=box.model,
            sw_version=box.firmware,
            configuration_url=f"https://{box.ip}" if box.ip else None,
        )

    def _current_box(self) -> CCBox | None:
        if not self.coordinator.data:
            return None
        for box in self.coordinator.data:
            if box.unique_id == self._box_uid:
                return box
        return None

    @property
    def native_value(self) -> str | None:
        box = self._current_box()
        if box is None:
            return None
        return self.entity_description.value_fn(box)

    @property
    def available(self) -> bool:
        return self.coordinator.last_update_success and self._current_box() is not None


class CCBoxRawDiagnostic(CoordinatorEntity[DataUpdateCoordinator[list[CCBox]]], SensorEntity):
    """Diagnostic sensor exposing the full raw CC API response as state attributes.

    Find this entity in Developer Tools → States and inspect its attributes
    to see every field your CC firmware version returns. Once you know the
    real field names, map them in sensor.py and remove this entity if desired.
    """

    _attr_icon = "mdi:code-json"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: DataUpdateCoordinator[list[CCBox]],
        box: CCBox,
    ) -> None:
        super().__init__(coordinator)
        self._box_uid = box.unique_id
        self._attr_unique_id = f"{box.unique_id}_raw_diagnostic"
        self._attr_name = f"{box.display_name} Raw API Fields"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, box.unique_id)},
            name=box.display_name,
            manufacturer="Barracuda Networks",
        )

    def _current_box(self) -> CCBox | None:
        if not self.coordinator.data:
            return None
        for box in self.coordinator.data:
            if box.unique_id == self._box_uid:
                return box
        return None

    @property
    def native_value(self) -> int | None:
        """Number of raw fields returned by the CC API (0 = empty response)."""
        box = self._current_box()
        return len(box.raw) if box is not None else None

    @property
    def extra_state_attributes(self) -> dict:
        """Every raw field as a HA attribute. Nested dicts are dot-flattened."""
        box = self._current_box()
        if box is None:
            return {}
        attrs: dict = {}
        for key, value in box.raw.items():
            if isinstance(value, dict):
                for subkey, subvalue in value.items():
                    attrs[f"{key}.{subkey}"] = subvalue
            elif isinstance(value, list):
                # HA attribute values must be JSON-serialisable scalars or dicts;
                # convert lists to a string to avoid rendering issues.
                attrs[key] = ", ".join(str(v) for v in value)
            else:
                attrs[key] = value
        return attrs

    @property
    def available(self) -> bool:
        return self.coordinator.last_update_success and self._current_box() is not None
