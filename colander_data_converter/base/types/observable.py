import enum

from pydantic import field_validator

from .base import CommonEntityType, load_entity_supported_types

__all__ = ["ObservableType", "ObservableTypes"]


class ObservableType(CommonEntityType):
    """ObservableType represents metadata for observables in Colander.

    Check :ref:`the list of supported types <observable_types>`.

    Example:
        >>> observable_type = ObservableType(
        ...     short_name='IPV4',
        ...     name='IPv4',
        ...     description='An IPv4 address type'
        ... )
        >>> print(observable_type.name)
        IPv4
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in load_entity_supported_types("observable")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class ObservableTypes(enum.Enum):
    """ObservableTypes provides access to all supported observable types.

    This class loads observable type definitions from the observable types JSON file and exposes them as an enum.
    It also provides a method to look up an observable type by its short name.

    Example:
        >>> observable_type = ObservableTypes.IPV4.value
        >>> print(observable_type.name)
        IPv4
        >>> default_type = ObservableTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    IPV4 = ObservableType(
        **{
            "short_name": "IPV4",
            "name": "IPv4",
            "description": "An IPv4 address, a 32-bit numeric address used for identifying devices on a network.",
            "default_attributes": {"address_block": "", "subnet": "", "routable": "", "ASN": ""},
            "svg_icon": "",
            "nf_icon": "nf-mdi-ethernet",
        }
    )

    IPV6 = ObservableType(
        **{
            "short_name": "IPV6",
            "name": "IPv6",
            "description": "An IPv6 address, a 128-bit alphanumeric address for identifying devices on a network.",
            "default_attributes": {"address_block": "", "subnet": "", "routable": "", "ASN": ""},
            "svg_icon": "",
            "nf_icon": "nf-mdi-ethernet",
        }
    )

    MAC = ObservableType(
        **{
            "short_name": "MAC",
            "name": "MAC address",
            "description": "A unique hardware identifier assigned to a network interface card (NIC).",
            "default_attributes": {"manufacturer": ""},
            "svg_icon": "",
            "nf_icon": "nf-mdi-ethernet",
        }
    )

    DOMAIN = ObservableType(
        **{
            "short_name": "DOMAIN",
            "name": "Domain name",
            "description": "A human-readable address used to identify resources on the internet.",
            "default_attributes": {"root_domain": "", "registration_date": ""},
            "svg_icon": "",
            "nf_icon": "nf-mdi-web",
        }
    )

    DOMAIN_REGISTRAR = ObservableType(
        **{
            "short_name": "DOMAIN_REGISTRAR",
            "name": "Domain registrar",
            "description": "The organization or entity responsible for registering domain names.",
            "default_attributes": {
                "name": "",
                "organization": "",
                "street": "",
                "city": "",
                "state": "",
                "postal_code": "",
                "country": "",
                "phone": "",
                "fax": "",
                "email": "",
            },
            "svg_icon": "",
            "nf_icon": "nf-mdi-web",
        }
    )

    DOMAIN_REGISTRANT = ObservableType(
        **{
            "short_name": "DOMAIN_REGISTRANT",
            "name": "Domain registrant",
            "description": "The individual or organization that owns or controls a domain name.",
            "default_attributes": {
                "name": "",
                "organization": "",
                "street": "",
                "city": "",
                "state": "",
                "postal_code": "",
                "country": "",
                "phone": "",
                "fax": "",
                "email": "",
            },
            "svg_icon": "",
            "nf_icon": "nf-mdi-web",
        }
    )

    HOSTNAME = ObservableType(
        **{
            "short_name": "HOSTNAME",
            "name": "Hostname",
            "description": "A label assigned to a device on a network, used to identify it in various forms.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-mdi-web",
        }
    )

    EMAIL = ObservableType(
        **{
            "short_name": "EMAIL",
            "name": "Email address",
            "description": "An address used to send and receive electronic mail.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-mdi-email_outline",
        }
    )

    PHONE = ObservableType(
        **{
            "short_name": "PHONE",
            "name": "Phone number",
            "description": "A numeric identifier used to reach a telephone endpoint.",
            "default_attributes": {"prefix": "", "country_code": "", "country_name": ""},
            "svg_icon": "",
            "nf_icon": "nf-fa-phone",
        }
    )

    SOCIAL_ACCOUNT = ObservableType(
        **{
            "short_name": "SOCIAL_ACCOUNT",
            "name": "Social account identifier",
            "description": "A unique identifier for a user account on a social media platform.",
            "default_attributes": {"platform": ""},
            "svg_icon": "",
            "nf_icon": "nf-mdi-account_card_details",
        }
    )

    URL = ObservableType(
        **{
            "short_name": "URL",
            "name": "URL",
            "description": "A Uniform Resource Locator, specifying the address of a resource on the internet.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-mdi-web",
        }
    )

    URI = ObservableType(
        **{
            "short_name": "URI",
            "name": "URI",
            "description": "A Uniform Resource Identifier, a string used to identify a resource.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-mdi-web",
        }
    )

    MD5 = ObservableType(
        **{
            "short_name": "MD5",
            "name": "MD5",
            "description": "A 128-bit hash value, commonly used to verify file integrity.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-fa-hashtag",
        }
    )

    COMMUNITY_ID = ObservableType(
        **{
            "short_name": "COMMUNITY_ID",
            "name": "Community id",
            "description": "A hash value used to uniquely identify network flows across tools.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-fa-hashtag",
        }
    )

    SHA1 = ObservableType(
        **{
            "short_name": "SHA1",
            "name": "SHA1",
            "description": "A 160-bit hash value, used for data integrity and file identification.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-fa-hashtag",
        }
    )

    SHA256 = ObservableType(
        **{
            "short_name": "SHA256",
            "name": "SHA256",
            "description": "A 256-bit hash value, widely used for file and data integrity verification.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-fa-hashtag",
        }
    )

    PEHASH = ObservableType(
        **{
            "short_name": "PEHASH",
            "name": "PE hash",
            "description": "A hash value calculated from the structure of a Portable Executable (PE) file.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-fa-hashtag",
        }
    )

    IMPHASH = ObservableType(
        **{
            "short_name": "IMPHASH",
            "name": "Import hash",
            "description": "A hash of the import table of a PE file, used to identify similar binaries.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-fa-hashtag",
        }
    )

    DEXOFUZZY = ObservableType(
        **{
            "short_name": "DEXOFUZZY",
            "name": "Dexofuzzy hash",
            "description": "A fuzzy hash value used to compare Android DEX files for similarity.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-fa-hashtag",
        }
    )

    CIDR = ObservableType(
        **{
            "short_name": "CIDR",
            "name": "CIDR",
            "description": "A Classless Inter-Domain Routing block, representing a range of IP addresses.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-mdi-ethernet",
        }
    )

    PATH = ObservableType(
        **{
            "short_name": "PATH",
            "name": "File path",
            "description": "A string specifying the location of a file or directory in a filesystem.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-mdi-file_tree",
        }
    )

    MUTEX = ObservableType(
        **{
            "short_name": "MUTEX",
            "name": "Mutex",
            "description": "A mutual exclusion object used for process synchronization.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-mdi-pencil_lock",
        }
    )

    CVE = ObservableType(
        **{
            "short_name": "CVE",
            "name": "CVE",
            "description": "A Common Vulnerabilities and Exposures identifier for publicly known security flaws.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-cod-debug_console",
        }
    )

    OS_QUERY = ObservableType(
        **{
            "short_name": "OS_QUERY",
            "name": "Os query",
            "description": "A query or result from an operating system instrumentation framework.",
            "default_attributes": {},
            "svg_icon": "",
            "nf_icon": "nf-cod-inspect",
        }
    )

    SSL_CERT_F = ObservableType(
        **{
            "short_name": "SSL_CERT_F",
            "name": "SSL certificate fingerprint",
            "description": "A hash value uniquely identifying an SSL/TLS certificate.",
            "default_attributes": {
                "subject": "",
                "md5": "",
                "sha1": "",
                "sha256": "",
                "issuer": "",
                "organization": "",
                "not_before": "",
                "not_after": "",
            },
            "svg_icon": "",
            "nf_icon": "nf-mdi-certificate",
        }
    )

    DNS_RECORD = ObservableType(
        **{
            "short_name": "DNS_RECORD",
            "name": "DNS record",
            "description": "A record containing information about a domain name in the DNS system.",
            "default_attributes": {"resolver": ""},
            "svg_icon": "",
            "nf_icon": "nf-mdi-web",
        }
    )

    ASN = ObservableType(
        **{
            "short_name": "ASN",
            "name": "Autonomous system number",
            "description": "A unique number assigned to a group of IP networks operated by one or more network operators.",
            "default_attributes": {"organization": ""},
            "svg_icon": "",
            "nf_icon": "nf-mdi-web",
        }
    )

    PROCESS = ObservableType(
        **{
            "short_name": "PROCESS",
            "name": "Process name",
            "description": "The name of a running process on a computer system.",
            "default_attributes": {"executable": "", "path": ""},
            "svg_icon": "",
            "nf_icon": "nf-cod-debug_console",
        }
    )

    SERVICE = ObservableType(
        **{
            "short_name": "SERVICE",
            "name": "Running service",
            "description": "A network or system service that is currently active or listening.",
            "default_attributes": {"ip_address": "", "technology": "", "port": ""},
            "svg_icon": "",
            "nf_icon": "nf-mdi-web",
        }
    )

    NAMESPACE = ObservableType(
        **{
            "short_name": "NAMESPACE",
            "name": "Namespace",
            "description": "A container that holds a set of identifiers, such as classes or functions, to avoid naming conflicts.",
            "default_attributes": {"fully_qualified_name": ""},
            "svg_icon": "",
            "nf_icon": "nf-md-code_tags",
        }
    )

    LOCATION = ObservableType(
        **{
            "short_name": "LOCATION",
            "name": "Location",
            "description": "A physical or geographical place, specified by coordinates or address.",
            "default_attributes": {
                "latitude": "",
                "longitude": "",
                "altitude": "",
                "country": "",
                "state": "",
                "city": "",
                "address": "",
            },
            "svg_icon": "",
            "nf_icon": "nf-fa-globe",
        }
    )

    GENERIC = ObservableType(
        **{
            "short_name": "GENERIC",
            "name": "Generic",
            "description": "A general or unspecified observable type that does not fit other categories.",
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
