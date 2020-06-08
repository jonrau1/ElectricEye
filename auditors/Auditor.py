"""Auditor plugin manager

This module implements a plugin manager for ElectricEye auditors.  It consists of two parts:
    The base Auditor class that ever auditor check must inherit from
    The AuditorCollection that loads the plugins from the plugin directory

Example usage:
    Create a list of auditor checks by passing the relative package name where the plugins reside:
        auditors = AuditorCollection("auditors") 
    This will return a list of dictionaries:
        {
            "check": <class object>,
            "auditor": <module_name>
        }
"""

import inspect
import os
import pkgutil
import importlib


class Auditor(object):
    """Base class that each auditor must inherit from. 
        Every auditor must implement an execute method.
    """

    def __init__(self):
        self.description = "UNKNOWN"
        self.name = self.__class__.__name__

    def execute(self, *args, **kwargs):
        """The method that we expect all plugins to implement. This is the
        method that our framework will call
        """
        raise NotImplementedError


class AuditorCollection(object):
    """Upon creation, this class will read the plugins package for modules
    that contain a class definition that is inheriting from the Auditor class
    """

    def __init__(self, plugin_package):
        """Constructor that initiates the reading of all available plugins
        when an instance of the PluginCollection object is created
        """
        self.plugin_package = plugin_package
        self.reload_plugins()

    def reload_plugins(self):
        """Reset the list of all plugins and initiate the walk over the main
        provided plugin package to load all available plugins
        """
        self.plugins = []
        self.walk_package(self.plugin_package)

    def walk_package(self, package):
        """Load all modules in package to retrieve all plugins
        """
        imported_package = __import__(package)

        for _, pluginname, ispkg in pkgutil.iter_modules(
            imported_package.__path__, imported_package.__name__ + "."
        ):
            try:
                if not ispkg:
                    plugin_module = importlib.import_module(pluginname)
                    clsmembers = inspect.getmembers(plugin_module, inspect.isclass)
                    for (_, c) in clsmembers:
                        # Only add classes that are a sub class of Auditor, but NOT Auditor itself
                        if issubclass(c, Auditor) & (c is not Auditor):
                            self.plugins.append(
                                {"check": c(), "auditor": pluginname,}
                            )
            except Exception as e:
                print(f"failed to load {pluginname} with error {e}")
