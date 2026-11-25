"""Plugin registry.

Plugins are registered explicitly so the dependency graph is obvious and the
API can publish a full manifest (including capability availability) at startup.
"""

from __future__ import annotations

from .base import BasePlugin, ModuleSpec


class Registry:
    def __init__(self) -> None:
        self._plugins: dict[str, BasePlugin] = {}

    def register(self, plugin: BasePlugin) -> None:
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> BasePlugin | None:
        return self._plugins.get(name)

    def get_module(self, plugin_name: str, module_name: str) -> ModuleSpec | None:
        plugin = self.get(plugin_name)
        if not plugin:
            return None
        for spec in plugin.iter_modules():
            if spec.name == module_name:
                return spec
        return None

    def all(self) -> list[BasePlugin]:
        return list(self._plugins.values())

    def manifest(self) -> list[dict]:
        return [p.manifest() for p in self._plugins.values()]


registry = Registry()


def load_plugins() -> Registry:
    """Import and register every built-in plugin."""
    from .bluetooth.plugin import BluetoothPlugin
    from .firmware.plugin import FirmwarePlugin
    from .hardware.plugin import HardwarePlugin
    from .wifi.plugin import WifiPlugin

    for plugin_cls in (BluetoothPlugin, WifiPlugin, HardwarePlugin, FirmwarePlugin):
        registry.register(plugin_cls())
    return registry
