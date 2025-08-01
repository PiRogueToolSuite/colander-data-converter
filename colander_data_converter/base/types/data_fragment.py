# Automatically generated by generate_types.py. Do not edit manually.
import enum

from pydantic import field_validator

from .base import CommonEntityType, load_entity_supported_types

__all__ = ["DataFragmentType", "DataFragmentTypes"]


class DataFragmentType(CommonEntityType):
    """
    DataFragmentType represents metadata for data fragments in Colander. Check :ref:`the list of supported
    types <data_fragment_types>`.

    Example:
        >>> data_fragment_type = DataFragmentTypes.CODE.value
        >>> print(data_fragment_type.name)
        Piece of code
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in load_entity_supported_types("data_fragment")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class DataFragmentTypes(enum.Enum):
    """
    DataFragmentTypes provides access to all supported data fragment types.

    This class loads data fragment type definitions from the data fragment types JSON file and exposes them as an enum.
    It also provides a method to look up a data fragment type by its short name.

    Example:
        >>> data_fragment_type = DataFragmentTypes.CODE.value
        >>> print(data_fragment_type.name)
        Piece of code
        >>> default_type = DataFragmentTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    CODE = DataFragmentType(
        **{
            "short_name": "CODE",
            "name": "Piece of code",
            "description": "A snippet or segment of source code from any programming language.",
            "svg_icon": "",
            "nf_icon": "nf-md-code_braces",
        }
    )
    """Piece of code - A snippet or segment of source code from any programming language."""

    GENERIC = DataFragmentType(
        **{
            "short_name": "GENERIC",
            "name": "Generic",
            "description": "A general or unspecified data fragment type that does not fit other categories.",
            "svg_icon": "",
            "nf_icon": "nf-oct-file_binary",
        }
    )
    """Generic - A general or unspecified data fragment type that does not fit other categories."""

    PATTERN = DataFragmentType(
        **{
            "short_name": "PATTERN",
            "name": "Pattern",
            "description": "A recognizable sequence or structure, such as a regular expression or YARA rule.",
            "svg_icon": "",
            "nf_icon": "nf-fa-puzzle_piece",
        }
    )
    """Pattern - A recognizable sequence or structure, such as a regular expression or YARA rule."""

    PAYLOAD = DataFragmentType(
        **{
            "short_name": "PAYLOAD",
            "name": "Raw payload",
            "description": "A block of raw binary or encoded data.",
            "svg_icon": "",
            "nf_icon": "nf-oct-file_binary",
        }
    )
    """Raw payload - A block of raw binary or encoded data."""

    TEXT = DataFragmentType(
        **{
            "short_name": "TEXT",
            "name": "Piece of text",
            "description": "A fragment of unstructured or plain text.",
            "svg_icon": "",
            "nf_icon": "nf-fa-file_text",
        }
    )
    """Piece of text - A fragment of unstructured or plain text."""

    default = GENERIC  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str):
        sn = short_name.replace(" ", "_").upper()
        if sn in cls._member_names_:
            return cls[sn].value
        return cls.default.value
