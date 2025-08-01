# Automatically generated by generate_types.py. Do not edit manually.
import enum

from pydantic import field_validator

from .base import CommonEntityType, load_entity_supported_types

__all__ = ["EventType", "EventTypes"]


class EventType(CommonEntityType):
    """
    EventType represents metadata for events in Colander. Check :ref:`the list of supported types <event_types>`.

    Example:
        >>> event_type = EventTypes.HIT.value
        >>> print(event_type.name)
        Hit
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in load_entity_supported_types("event")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class EventTypes(enum.Enum):
    """
    EventTypes provides access to all supported event types.

    This class loads event type definitions from the event types JSON file and exposes them as an enum.
    It also provides a method to look up an event type by its short name.

    Example:
        >>> event_type = EventTypes.HIT.value
        >>> print(event_type.name)
        Hit
        >>> default_type = EventTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    ALERT = EventType(
        **{
            "short_name": "ALERT",
            "name": "Alert",
            "description": "A notification or warning about a detected security event or anomaly.",
            "svg_icon": "",
            "nf_icon": "nf-oct-alert",
        }
    )
    """Alert - A notification or warning about a detected security event or anomaly."""

    ATTACK = EventType(
        **{
            "short_name": "ATTACK",
            "name": "Attack",
            "description": "An event indicating a deliberate attempt to breach, disrupt, or damage a system or network.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-bomb",
        }
    )
    """Attack - An event indicating a deliberate attempt to breach, disrupt, or damage a system or network."""

    AV_DETECTION = EventType(
        **{
            "short_name": "AV_DETECTION",
            "name": "AntiVirus detection",
            "description": "An event where antivirus software detects malicious or suspicious activity.",
            "svg_icon": "",
            "nf_icon": "nf-oct-alert",
        }
    )
    """AntiVirus detection - An event where antivirus software detects malicious or suspicious activity."""

    COMMUNICATION = EventType(
        **{
            "short_name": "COMMUNICATION",
            "name": "Communication",
            "description": "An event involving the exchange of information between entities, such as emails or messages.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-lan_connect",
        }
    )
    """Communication - An event involving the exchange of information between entities, such as emails or messages."""

    COMPROMISE = EventType(
        **{
            "short_name": "COMPROMISE",
            "name": "Compromise",
            "description": "An event indicating that a system, account, or data has been breached or compromised.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-disk_alert",
        }
    )
    """Compromise - An event indicating that a system, account, or data has been breached or compromised."""

    GENERIC = EventType(
        **{
            "short_name": "GENERIC",
            "name": "Generic",
            "description": "An event that does not fit into any of the predefined categories.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-white_balance_sunny",
        }
    )
    """Generic - An event that does not fit into any of the predefined categories."""

    HIT = EventType(
        **{
            "short_name": "HIT",
            "name": "Hit",
            "description": "An event indicating a match or detection by a rule, signature, or indicator.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-white_balance_sunny",
        }
    )
    """Hit - An event indicating a match or detection by a rule, signature, or indicator."""

    INFECTION = EventType(
        **{
            "short_name": "INFECTION",
            "name": "Infection",
            "description": "An event where a system or device is infected by malware or a similar threat.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-disk_alert",
        }
    )
    """Infection - An event where a system or device is infected by malware or a similar threat."""

    PASSIVE_DNS = EventType(
        **{
            "short_name": "PASSIVE_DNS",
            "name": "Passive DNS",
            "description": "An event recording historical DNS resolution data observed passively.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-white_balance_sunny",
        }
    )
    """Passive DNS - An event recording historical DNS resolution data observed passively."""

    RESOLVE = EventType(
        **{
            "short_name": "RESOLVE",
            "name": "Resolution",
            "description": "An event where a domain or hostname is resolved to an IP address.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-search_web",
        }
    )
    """Resolution - An event where a domain or hostname is resolved to an IP address."""

    TARGETED_ATTACK = EventType(
        **{
            "short_name": "TARGETED_ATTACK",
            "name": "Targeted Attack",
            "description": "An event representing a focused and intentional attack against a specific entity or asset.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-crosshairs",
        }
    )
    """Targeted Attack - An event representing a focused and intentional attack against a specific entity or asset."""

    default = GENERIC  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str):
        sn = short_name.replace(" ", "_").upper()
        if sn in cls._member_names_:
            return cls[sn].value
        return cls.default.value
