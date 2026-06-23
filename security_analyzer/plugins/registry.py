import importlib
import importlib.util
import os
import sys
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type


class BasePlugin(ABC):
    NAME: str = ""
    VERSION: str = "1.0.0"
    DESCRIPTION: str = ""

    @abstractmethod
    def rules(self) -> list:
        """Return a list of Rule instances contributed by this plugin."""

    def on_load(self) -> None:
        """Called once when the plugin is registered. Override for setup."""

    def on_events(self, events: list) -> list:
        """Called with the full event list. Return additional events or []."""
        return []

    def __repr__(self) -> str:
        return f"<Plugin {self.NAME} v{self.VERSION}>"


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: Dict[str, BasePlugin] = {}

    def register(self, plugin: BasePlugin) -> None:
        if not plugin.NAME:
            raise ValueError(f"Plugin {type(plugin).__name__} must define NAME.")
        if plugin.NAME in self._plugins:
            raise ValueError(f"Plugin '{plugin.NAME}' is already registered.")
        plugin.on_load()
        self._plugins[plugin.NAME] = plugin

    def unregister(self, name: str) -> None:
        self._plugins.pop(name, None)

    def get(self, name: str) -> Optional[BasePlugin]:
        return self._plugins.get(name)

    @property
    def plugins(self) -> List[BasePlugin]:
        return list(self._plugins.values())

    def all_rules(self) -> list:
        rules = []
        for plugin in self._plugins.values():
            rules.extend(plugin.rules())
        return rules

    def dispatch_events(self, events: list) -> list:
        extra: list = []
        for plugin in self._plugins.values():
            result = plugin.on_events(events)
            if result:
                extra.extend(result)
        return extra

    def discover(self, directory: str) -> int:
        """
        Scan *directory* for Python files that define a BasePlugin subclass.
        Each file must expose a module-level PLUGIN_CLASS variable pointing to the class,
        or contain exactly one non-abstract subclass of BasePlugin.
        Returns the number of plugins successfully loaded.
        """
        if not os.path.isdir(directory):
            return 0

        loaded = 0
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue
            filepath = os.path.join(directory, filename)
            module_name = f"_dyn_plugin_{filename[:-3]}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, filepath)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                plugin_class: Optional[Type[BasePlugin]] = getattr(module, "PLUGIN_CLASS", None)

                if plugin_class is None:
                    candidates = [
                        obj for obj in vars(module).values()
                        if isinstance(obj, type)
                        and issubclass(obj, BasePlugin)
                        and obj is not BasePlugin
                        and not getattr(obj, "__abstractmethods__", None)
                    ]
                    if len(candidates) == 1:
                        plugin_class = candidates[0]

                if plugin_class is not None:
                    instance = plugin_class()
                    self.register(instance)
                    loaded += 1

            except Exception:
                pass

        return loaded

    def summary(self) -> str:
        if not self._plugins:
            return "(no plugins loaded)"
        lines = [f"Loaded plugins ({len(self._plugins)}):"]
        for name, plugin in self._plugins.items():
            lines.append(f"  {name} v{plugin.VERSION} — {plugin.DESCRIPTION}")
        return "\n".join(lines)
