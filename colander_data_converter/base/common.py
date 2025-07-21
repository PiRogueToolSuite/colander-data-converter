import enum
from typing import Dict

from pydantic import UUID4


class TlpPapLevel(str, enum.Enum):
    """Traffic Light Protocol (TLP) and Permissible Actions Protocol (PAP) classification levels.

    The TLP is a set of designations used to ensure that sensitive information is shared
    with the appropriate audience. PAP complements TLP by providing guidance on what
    actions can be taken with the information.

    Note:
        See `FIRST TLP Standard <https://www.first.org/tlp/>`_ for complete specification.

    Example:
        >>> level = TlpPapLevel.RED
        >>> print(level)
        RED
        >>> str(level) == "RED"
        True
    """

    RED = "RED"
    """Highly sensitive information, restricted to specific recipients."""

    AMBER = "AMBER"
    """Sensitive information, limited to a defined group."""

    GREEN = "GREEN"
    """Information that can be shared within the community."""

    WHITE = "WHITE"
    """Information that can be shared publicly."""

    def __str__(self):
        """Return the string representation of the TLP level.

        Returns:
            str: The TLP level value as a string
        """
        return self.value


# ObjectReference is an alias for UUID4, representing a unique object identifier.
type ObjectReference = UUID4


class Singleton(type):
    """Metaclass implementation of the Singleton design pattern.

    This metaclass ensures that only one instance of a class can exist at any time.
    Subsequent instantiation attempts will return the existing instance rather than
    creating a new one.

    Note:
        The singleton instance is created lazily on first instantiation and persists
        for the lifetime of the Python process.

        Classes using this metaclass should be designed to handle reinitialization
        gracefully, as ``__init__`` may be called multiple times on the same instance.

    Example:
        >>> class Configuration(metaclass=Singleton):
        ...     def __init__(self, value=None):
        ...         if not hasattr(self, 'initialized'):
        ...             self.value = value
        ...             self.initialized = True
        ...
        >>> config1 = Configuration(value=42)
        >>> config2 = Configuration(value=99)
        >>> print(config1 is config2)  # Both variables point to the same instance
        True
        >>> print(config1.value)  # The value from first initialization
        42
    """

    _instances: Dict[type, type] = {}

    def __call__(cls, *args, **kwargs):
        """Control instance creation to ensure singleton behavior.

        Args:
            cls (type): The class being instantiated
            *args: Positional arguments for class initialization
            **kwargs: Keyword arguments for class initialization

        Returns:
            type: The singleton instance of the class

        Note:
            If an instance already exists, ``__init__`` will still be called with
            the provided arguments, but no new instance is created.
        """
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
