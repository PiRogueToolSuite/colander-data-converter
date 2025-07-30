import enum

from pydantic import field_validator

from .base import CommonEntityType, load_entity_supported_types

__all__ = ["ActorType", "ActorTypes"]


class ActorType(CommonEntityType):
    """
    ActorType represents metadata for actors in Colander. Check :ref:`the list of supported types <actor_types>`.

    Example:
        >>> actor_type = ActorTypes.INDIVIDUAL.value
        >>> print(actor_type.name)
        Individual
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in load_entity_supported_types("actor")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class ActorTypes(enum.Enum):
    """
    ActorTypes provides access to all supported actor types.

    This class loads actor type definitions from the actor types JSON file and exposes them as an enum.
    It also provides a method to look up an actor type by its short name.

    Example:
        >>> actor_type = ActorTypes.INDIVIDUAL.value
        >>> print(actor_type.name)
        Individual
        >>> default_type = ActorTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    NGO = ActorType(
        **{
            "short_name": "NGO",
            "name": "NGO",
            "description": "A non-governmental organization.",
            "svg_icon": "",
            "nf_icon": "nf-fae-cc_nc",
        }
    )

    COMPANY = ActorType(
        **{
            "short_name": "COMPANY",
            "name": "Private company",
            "description": "A privately owned business entity, often a target or participant in cyber activities.",
            "svg_icon": "",
            "nf_icon": "nf-fa-dollar",
        }
    )

    APT = ActorType(
        **{
            "short_name": "APT",
            "name": "APT",
            "description": "An advanced persistent threat group, typically well-resourced and highly skilled.",
            "svg_icon": "",
            "nf_icon": "nf-fae-virus",
        }
    )

    THREAT_ACTOR = ActorType(
        **{
            "short_name": "THREAT_ACTOR",
            "name": "Threat actor",
            "description": "An individual or group responsible for malicious cyber activities.",
            "svg_icon": "",
            "nf_icon": "nf-fae-virus",
        }
    )

    INDIVIDUAL = ActorType(
        **{
            "short_name": "INDIVIDUAL",
            "name": "Individual",
            "description": "A single person involved in threat activity or as a target.",
            "svg_icon": "",
            "nf_icon": "nf-cod-person",
        }
    )

    PUB_INST = ActorType(
        **{
            "short_name": "PUB_INST",
            "name": "Public institution",
            "description": "A government or public sector organization.",
            "svg_icon": "",
            "nf_icon": "nf-fa-bank",
        }
    )

    GENERIC = ActorType(
        **{
            "short_name": "GENERIC",
            "name": "Generic",
            "description": "A generic or unspecified actor type.",
            "svg_icon": "",
            "nf_icon": "nf-cod-person",
        }
    )

    HACKTIVIST = ActorType(
        **{
            "short_name": "HACKTIVIST",
            "name": "Hacktivist",
            "description": "An individual or group using hacking to promote political or social agendas.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-hammer_sickle",
        }
    )

    CYBER_CRIMINAL = ActorType(
        **{
            "short_name": "CYBER_CRIMINAL",
            "name": "Cyber criminal",
            "description": "An individual or group engaging in illegal activities for financial gain.",
            "svg_icon": "",
            "nf_icon": "nf-fa-user_secret",
        }
    )

    INSIDER = ActorType(
        **{
            "short_name": "INSIDER",
            "name": "Insider threat",
            "description": "An individual within an organization posing a security risk.",
            "svg_icon": "",
            "nf_icon": "nf-fa-user",
        }
    )

    NATION_STATE = ActorType(
        **{
            "short_name": "NATION_STATE",
            "name": "Nation-state actor",
            "description": "A government-sponsored group conducting cyber operations.",
            "svg_icon": "",
            "nf_icon": "nf-mdi-flag",
        }
    )

    default = GENERIC  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str):
        sn = short_name.replace(" ", "_").upper()
        if sn in cls._member_names_:
            return cls[sn].value
        return cls.default.value
