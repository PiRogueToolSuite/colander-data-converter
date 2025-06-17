import enum

from pydantic import UUID4


class TlpPapLevel(str, enum.Enum):
    """
    TlpPapLevel represents the Traffic Light Protocol (TLP) and Permissible Actions Protocol (PAP) levels.

    These levels are used to classify the sensitivity of information and its sharing restrictions.

    Example:
        >>> level = TlpPapLevel.RED
        >>> print(level)
        TlpPapLevel.RED
    """

    RED = "RED"
    """Highly sensitive information, restricted to specific recipients."""

    AMBER = "AMBER"
    """Sensitive information, limited to a defined group."""

    GREEN = "GREEN"
    """Information that can be shared within the community."""

    WHITE = "WHITE"
    """Information that can be shared publicly."""


type ObjectReference = UUID4


class Singleton(type):
    """
    Singleton is a metaclass that ensures a class has only one instance.

    Example:
        >>> class Configuration(metaclass=Singleton):
        ...     def __init__(self, value):
        ...         self.value = value
        ...
        >>> config1 = Configuration(value=42)
        >>> config2 = Configuration(value=99)
        >>> print(config1 is config2)  # Both variables point to the same instance
        True
        >>> print(config1.value)  # The value is shared across instances
        42
    """

    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
