import abc
import enum
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field, UUID4


class TlpPapLevel(str, enum.Enum):
    """
    TlpPapLevel represents the Traffic Light Protocol (TLP) and Permissible Actions Protocol (PAP) levels.

    These levels are used to classify the sensitivity of information and its sharing restrictions.

    Example:
        >>> level = TlpPapLevel.RED
        >>> print(level)
        RED
    """

    RED = "RED"
    """Highly sensitive information, restricted to specific recipients."""

    AMBER = "AMBER"
    """Sensitive information, limited to a defined group."""

    GREEN = "GREEN"
    """Information that can be shared within the community."""

    WHITE = "WHITE"
    """Information that can be shared publicly."""


class SuperType(BaseModel):
    short_name: str = Field(frozen=True, max_length=32)
    """A short name for the model type."""

    name: str = Field(frozen=True, max_length=512)
    """The name of the model type."""

    _class: type


class CommonModelType(BaseModel, abc.ABC):
    """
    CommonModelType is an abstract base class for defining shared attributes across various model types.

    This class provides fields for identifiers, names, descriptions, and other metadata.
    """
    short_name: str = Field(frozen=True, max_length=32)
    """A short name for the model type."""

    name: str = Field(frozen=True, max_length=512)
    """The name of the model type."""

    description: str | None = None
    """An optional description of the model type."""

    svg_icon: str | None = None
    """Optional SVG icon for the model type."""

    nf_icon: str | None = None
    """Optional NF icon for the model type."""

    stix2_type: str | None = None
    """Optional STIX 2.0 type for the model type."""

    stix2_value_field_name: str | None = None
    """Optional STIX 2.0 value field name."""

    stix2_pattern: str | None = None
    """Optional STIX 2.0 pattern."""

    stix2_pattern_type: str | None = None
    """Optional STIX 2.0 pattern type."""

    default_attributes: Optional[Dict[str, str]] = None
    """Optional dictionary of default attributes."""

    type_hints: Dict[Any, Any] | None = None
    """Optional dictionary of type hints."""


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
