"""
Web Vulnerability Scanner - Plugin Base Module

This module provides the base class for vulnerability check plugins and
a registration system for automatic plugin discovery and loading.
"""

import abc
import importlib
import inspect
import logging
import pkgutil
from typing import Dict, List, Type, Set, Any, Optional, ClassVar
import requests

from scanner.http_client import HttpClient
from scanner.reporter import Finding, Severity, Reporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('plugins.base')


class PluginMetaclass(abc.ABCMeta):
    """
    Metaclass for plugins that handles automatic registration.
    """
    
    _plugins: ClassVar[Dict[str, Type['Plugin']]] = {}
    
    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        
        # Don't register the base Plugin class
        if name != 'Plugin' and abc.ABC not in bases:
            plugin_name = getattr(cls, 'name', name.lower())
            mcs._plugins[plugin_name] = cls
            logger.debug(f"Registered plugin: {plugin_name}")
        
        return cls


class Plugin(abc.ABC, metaclass=PluginMetaclass):
    """
    Abstract base class for vulnerability scanner plugins.
    
    All plugins must inherit from this class and implement the required methods.
    Plugins are automatically registered when defined.
    """
    
    # Class attributes
    name: str = None  # Plugin name, defaults to lowercase class name
    description: str = ""  # Plugin description
    enabled: bool = True  # Whether the plugin is enabled by default
    requires_auth: bool = False  # Whether the plugin requires authentication
    
    def __init__(self, reporter: Reporter = None):
        """
        Initialize the plugin.
        
        Args:
            reporter: Reporter instance for recording findings
        """
        self.reporter = reporter or Reporter()
        self.logger = logging.getLogger(f'plugins.{self.name}')
    
    @abc.abstractmethod
    def scan(self, target_url: str, http_client: HttpClient) -> List[Finding]:
        """
        Run the vulnerability scan on a target URL.
        
        Args:
            target_url: The URL to scan
            http_client: HttpClient instance for making requests
            
        Returns:
            List[Finding]: List of vulnerability findings
        """
        pass
    
    def report_finding(self, finding: Finding) -> None:
        """
        Report a vulnerability finding.
        
        Args:
            finding: The finding to report
        """
        if self.reporter:
            self.reporter.add_finding(finding)
            self.logger.info(f"Reported finding: {finding.title} ({finding.severity.value}) at {finding.url}")
        else:
            self.logger.warning(f"No reporter configured, finding not recorded: {finding.title}")
    
    def can_scan(self, target_url: str, response: requests.Response) -> bool:
        """
        Check if this plugin can scan the given URL/response.
        Plugins can override this to add more specific conditions.
        
        Args:
            target_url: Target URL
            response: HTTP response from the URL
            
        Returns:
            bool: True if the plugin can scan this target
        """
        # Default implementation - plugin can scan all targets
        return True
    
    @classmethod
    def get_all_plugins(cls) -> Dict[str, Type['Plugin']]:
        """
        Get all registered plugin classes.
        
        Returns:
            Dict[str, Type[Plugin]]: Dictionary of plugin name to plugin class
        """
        return PluginMetaclass._plugins.copy()
    
    @classmethod
    def get_enabled_plugins(cls, config: Optional[Dict[str, Any]] = None) -> Dict[str, Type['Plugin']]:
        """
        Get all enabled plugin classes.
        
        Args:
            config: Optional configuration dictionary that can override defaults
            
        Returns:
            Dict[str, Type[Plugin]]: Dictionary of enabled plugin name to plugin class
        """
        enabled_plugins = {}
        
        for name, plugin_cls in PluginMetaclass._plugins.items():
            # Check if plugin is enabled in config
            enabled = plugin_cls.enabled
            if config and 'plugins' in config and name in config['plugins']:
                enabled = config['plugins'][name].get('enabled', enabled)
            
            if enabled:
                enabled_plugins[name] = plugin_cls
        
        return enabled_plugins
    
    @classmethod
    def instantiate_plugins(cls, reporter: Reporter, config: Optional[Dict[str, Any]] = None) -> Dict[str, 'Plugin']:
        """
        Create instances of all enabled plugins.
        
        Args:
            reporter: Reporter instance to use for findings
            config: Optional configuration dictionary
            
        Returns:
            Dict[str, Plugin]: Dictionary of plugin name to plugin instance
        """
        instances = {}
        enabled_plugins = cls.get_enabled_plugins(config)
        
        for name, plugin_cls in enabled_plugins.items():
            try:
                instances[name] = plugin_cls(reporter=reporter)
                logger.debug(f"Instantiated plugin: {name}")
            except Exception as e:
                logger.error(f"Failed to instantiate plugin {name}: {e}")
        
        return instances


def discover_plugins(package_name: str = 'plugins') -> None:
    """
    Discover and import all plugins in the given package.
    
    Args:
        package_name: Name of the package containing plugins
    """
    logger.debug(f"Discovering plugins in package: {package_name}")
    
    try:
        package = importlib.import_module(package_name)
    except ImportError:
        logger.error(f"Could not import plugin package: {package_name}")
        return
    
    # Track imported modules to avoid duplicates
    imported: Set[str] = set()
    
    # Import all modules in the package
    for _, module_name, is_pkg in pkgutil.iter_modules(package.__path__, package.__name__ + '.'):
        if module_name == f"{package_name}.base" or module_name in imported:
            continue
            
        try:
            importlib.import_module(module_name)
            imported.add(module_name)
            logger.debug(f"Imported plugin module: {module_name}")
        except ImportError as e:
            logger.error(f"Failed to import plugin module {module_name}: {e}")
    
    logger.info(f"Discovered {len(Plugin.get_all_plugins())} plugins: {', '.join(Plugin.get_all_plugins().keys())}")


# Utility function to check if a class is a valid plugin
def is_plugin_class(cls: Any) -> bool:
    """
    Check if a class is a valid plugin.
    
    Args:
        cls: Class to check
        
    Returns:
        bool: True if the class is a valid plugin
    """
    return (inspect.isclass(cls) and 
            issubclass(cls, Plugin) and 
            cls != Plugin)
