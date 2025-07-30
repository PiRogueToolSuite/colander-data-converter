import enum

from pydantic import field_validator

from .base import CommonEntityType, load_entity_supported_types

__all__ = ["ThreatType", "ThreatTypes"]


class ThreatType(CommonEntityType):
    """
    ThreatType represents metadata for threats in Colander. Check :ref:`the list of supported types <threat_types>`.

    Example:
        >>> threat_type = ThreatTypes.TROJAN.value
        >>> print(threat_type.name)
        Trojan
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in load_entity_supported_types("threat")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class ThreatTypes(enum.Enum):
    """
    ThreatTypes provides access to all supported threat types.

    This class loads threat type definitions from the threat types JSON file and exposes them as an enum.
    It also provides a method to look up a threat type by its short name.

    Example:
        >>> threat_type = ThreatTypes.TROJAN.value
        >>> print(threat_type.name)
        Trojan
        >>> default_type = ThreatTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    ADWARE = ThreatType(
        **{
            "short_name": "ADWARE",
            "name": "Adware",
            "description": "Software that automatically displays or downloads advertising material, often unwanted.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    APT = ThreatType(
        **{
            "short_name": "APT",
            "name": "APT",
            "description": "Advanced Persistent Threat; a prolonged and targeted cyberattack by a well-resourced adversary.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    BACKDOOR = ThreatType(
        **{
            "short_name": "BACKDOOR",
            "name": "Backdoor",
            "description": "Malware that allows unauthorized remote access to a compromised system.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    BOTNET = ThreatType(
        **{
            "short_name": "BOTNET",
            "name": "Botnet",
            "description": "A network of compromised computers controlled by an attacker to perform coordinated tasks.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    BROWSER_HIJACKER = ThreatType(
        **{
            "short_name": "BROWSER_HIJACKER",
            "name": "Browser Hijacker",
            "description": "Malware that alters browser settings, redirects traffic, or injects unwanted ads.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    CRYPTOJACKING = ThreatType(
        **{
            "short_name": "CRYPTOJACKING",
            "name": "Cryptojacking",
            "description": "Unauthorized use of a device to mine cryptocurrency.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    DROPPER = ThreatType(
        **{
            "short_name": "DROPPER",
            "name": "Dropper",
            "description": "A type of malware designed to deliver and install other malicious software.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    EXPLOIT_KIT = ThreatType(
        **{
            "short_name": "EXPLOIT_KIT",
            "name": "Exploit Kit",
            "description": "A toolkit used to exploit vulnerabilities in software to deliver malware.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    INFO_STEALER = ThreatType(
        **{
            "short_name": "INFO_STEALER",
            "name": "Information Stealer",
            "description": "Malware designed to steal sensitive information such as credentials or financial data.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    LOADER = ThreatType(
        **{
            "short_name": "LOADER",
            "name": "Loader",
            "description": "Malware that loads and executes other malicious payloads on a system.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    MALVERTISING = ThreatType(
        **{
            "short_name": "MALVERTISING",
            "name": "Malvertising",
            "description": "The use of online advertising to spread malware.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    MOBILE_MALWARE = ThreatType(
        **{
            "short_name": "MOBILE_MALWARE",
            "name": "Mobile Malware",
            "description": "A malware specifically targeting mobile devices to steal data or perform malicious actions.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    RANSOMWARE = ThreatType(
        **{
            "short_name": "RANSOMWARE",
            "name": "Ransomware",
            "description": "Malware that encrypts data and demands payment for decryption.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    PHISHING = ThreatType(
        **{
            "short_name": "PHISHING",
            "name": "Phishing",
            "description": "A technique to trick users into revealing sensitive information, often via fake emails or websites.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    STALKERWARE = ThreatType(
        **{
            "short_name": "STALKERWARE",
            "name": "Stalkerware",
            "description": "Software used to secretly monitor and track user activity, often for surveillance.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    MALWARE = ThreatType(
        **{
            "short_name": "MALWARE",
            "name": "Malware",
            "description": "A general term for any software intentionally designed to cause damage or unauthorized actions.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    RAT = ThreatType(
        **{
            "short_name": "RAT",
            "name": "Remote Access Trojan (RAT)",
            "description": "Malware that provides remote control over an infected system.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    ROOTKIT = ThreatType(
        **{
            "short_name": "ROOTKIT",
            "name": "Rootkit",
            "description": "Malware designed to hide its presence and provide privileged access to a system.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    SPAM = ThreatType(
        **{
            "short_name": "SPAM",
            "name": "Spam",
            "description": "Unsolicited or bulk messages, often used to deliver malware or phishing attempts.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    GENERIC = ThreatType(
        **{
            "short_name": "GENERIC",
            "name": "Generic",
            "description": "A general or unspecified threat type that does not fit other categories.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    SPYWARE = ThreatType(
        **{
            "short_name": "SPYWARE",
            "name": "Spyware",
            "description": "Malware that secretly gathers user information without consent.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    TROJAN = ThreatType(
        **{
            "short_name": "TROJAN",
            "name": "Trojan",
            "description": "Malware disguised as legitimate software to trick users into installing it.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    CYBERCRIME = ThreatType(
        **{
            "short_name": "CYBERCRIME",
            "name": "Cybercrime",
            "description": "Criminal activities carried out using computers or the internet, including fraud, theft, and unauthorized access.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    CYBER_ATTACK = ThreatType(
        **{
            "short_name": "CYBER_ATTACK",
            "name": "Cyber Attack",
            "description": "An attempt by hackers to damage, disrupt, or gain unauthorized access to computer systems, networks, or devices.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    PHYSICAL_ATTACK = ThreatType(
        **{
            "short_name": "PHYSICAL_ATTACK",
            "name": "Physical Attack",
            "description": "A threat involving physical actions intended to harm or compromise assets, infrastructure, or individuals.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    HARASSMENT = ThreatType(
        **{
            "short_name": "HARASSMENT",
            "name": "Harassment",
            "description": "Unwanted behavior intended to intimidate, threaten, or disturb an individual, often through digital means.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    DOXXING = ThreatType(
        **{
            "short_name": "DOXXING",
            "name": "Doxxing",
            "description": "The act of publicly revealing private or identifying information about an individual without their consent.",
            "svg_icon": "",
            "nf_icon": "nf nf-fa-bug",
        }
    )

    default = GENERIC  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str):
        sn = short_name.replace(" ", "_").upper()
        if sn in cls._member_names_:
            return cls[sn].value
        return cls.default.value
