"""
Web Vulnerability Scanner - Plugin modules

This package contains modular vulnerability test plugins
that inherit from the base plugin class.
"""

__version__ = '0.1.0'

# Import all plugins to ensure they are registered with the metaclass
from . import sql_injection
from . import xss
from . import directory_traversal
from . import open_redirect
from . import security_headers
