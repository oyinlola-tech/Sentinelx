"""SentinelX - an explainable network intrusion detection and prevention platform.

The security core (``sentinelx.capture`` through ``sentinelx.response``) is a plain
Python library with no dependency on the web application.  ``sentinelx.api`` and
``sentinelx.cli`` are two front-ends over the same :mod:`sentinelx.pipeline`.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
