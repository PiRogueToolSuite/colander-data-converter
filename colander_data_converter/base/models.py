import abc
import enum
import json
from datetime import datetime, UTC
from enum import Enum
from importlib import resources
from typing import List, Dict, Any, Optional, Union, Annotated, Literal, get_args
from uuid import uuid4, UUID

from pydantic import (
    Field,
    PositiveInt,
    NonNegativeInt,
    UUID4,
    BaseModel,
    AnyUrl,
    computed_field,
    model_validator,
    field_validator,
    ConfigDict,
)

from colander_data_converter.base.common import (
    ObjectReference,
    TlpPapLevel,
    Singleton,
)

resource_package = __name__


def _load_entity_supported_types(name: str) -> List[Dict]:
    json_file = resources.files(resource_package).joinpath("..").joinpath("data").joinpath(f"{name}_types.json")
    with json_file.open() as f:
        return json.load(f)


# Annotated union type representing all possible entity definitions in the model.
# This type is used for fields that can accept any of the defined entity classes.
# The Field discriminator 'colander_internal_type' is used for type resolution during (de)serialization.
EntityTypes = Annotated[
    Union[
        "Actor",
        "Artifact",
        "DataFragment",
        "Observable",
        "DetectionRule",
        "Device",
        "Event",
        "Threat",
    ],
    Field(discriminator="colander_internal_type"),
]


class CommonEntityType(BaseModel, abc.ABC):
    """
    CommonEntityType is an abstract base class for defining shared attributes across various entity data types.

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

    def __str__(self):
        return self.short_name


class ColanderType(BaseModel):
    """
    Base class for all Colander model data_types, providing common functionality for
    post-initialization, reference management, and type resolution.

    This class extends Pydantic's BaseModel and is intended to be subclassed by
    all model entities. It includes methods for linking and unlinking object references,
    resolving type hints, and extracting subclass information.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
    )

    def model_post_init(self, __context):
        """
        Executes post-initialization logic for the model, ensuring the repository
        registers the current subclass instance.

        :param __context: Additional context provided for post-initialization
                          handling.
        :type __context: Any
        """
        _ = ColanderRepository()
        _ << self

    def _process_reference_fields(self, operation, strict=False):
        """
        Helper method to process reference fields for both unlinking and resolving operations.

        :param operation: The operation to perform, either 'unlink' or 'resolve'.
        :type operation: str
        :param strict: If True, raises a ValueError when a UUID reference cannot be resolved.
                       Only used for 'resolve' operation.
        :type strict: bool
        :raises ValueError: If strict is True and a UUID reference cannot be resolved.
        :raises AttributeError: If the class instance does not have the expected field or attribute.
        """
        for field, info in self.__class__.model_fields.items():
            annotation_args = get_args(info.annotation)
            if ObjectReference in annotation_args:
                ref = getattr(self, field)
                if operation == "unlink" and ref and type(ref) is not UUID:
                    setattr(self, field, ref.id)
                elif operation == "resolve" and type(ref) is UUID:
                    x = ColanderRepository() >> ref
                    if strict and isinstance(x, UUID):
                        raise ValueError(f"Unable to resolve UUID reference {x}")
                    setattr(self, field, x)
            elif List[ObjectReference] in annotation_args:
                refs = getattr(self, field)
                new_refs = []
                _update = False
                for ref in refs:
                    if operation == "unlink" and ref and type(ref) is not UUID:
                        new_refs.append(ref.id)
                        _update = True
                    elif operation == "resolve" and type(ref) is UUID:
                        x = ColanderRepository() >> ref
                        if strict and isinstance(x, UUID):
                            raise ValueError(f"Unable to resolve UUID reference {x}")
                        new_refs.append(x)
                        _update = True
                if _update:
                    setattr(self, field, new_refs)

    def unlink_references(self):
        """
        Unlinks object references by replacing them with their respective UUIDs.

        This method updates the model fields of the class instance where
        fields annotated as `ObjectReference` or `List[ObjectReference]` exist. It replaces the
        references (of type objects) with their UUIDs if they exist.

        For fields of type `ObjectReference`, the method retrieves the field's value and replaces
        it with its `id` (UUID) if the current value is not already a UUID.

        For fields of type `List[ObjectReference]`, the method iterates through the list and
        replaces each object reference with its `id` (UUID) if the current value is
        not already a UUID. The field value is updated only if at least one
        replacement occurs.

        :raises AttributeError: If the class instance does not have the expected field or attribute.
        """
        self._process_reference_fields("unlink")

    def resolve_references(self, strict=False):
        """
        Resolves references for the fields in the object's model. Fields annotated with `ObjectReference` or
        `List[ObjectReference]` are processed to fetch and replace their UUID references with respective
        entities using the `Repository`.

        This method updates the object in-place.

        :param strict: If True, raises a ValueError when a UUID reference cannot be resolved.
                       If False, unresolved references remain as UUIDs.
        :type strict: bool

        :raises ValueError: If strict is True and a UUID reference cannot be resolved.
        """
        self._process_reference_fields("resolve", strict)

    @classmethod
    def subclasses(cls) -> Dict[str, type["EntityTypes"]]:
        """
        Generates a dictionary containing all subclasses of the current class.

        This method collects all the direct subclasses of the current class and maps their
        names (converted to lowercase) to the class itself. It is primarily useful for
        organizing and accessing class hierarchies dynamically.

        :return: A dictionary where the keys are the lowercase names of the subclasses,
                 and the values are the subclass data_types themselves.
        :rtype: Dict[str, type['EntityTypes']]
        """
        subclasses = {}
        for subclass in cls.__subclasses__():
            subclasses[subclass.__name__.lower()] = subclass
        return subclasses

    @classmethod
    def resolve_type(cls, content_type: str) -> type["EntityTypes"]:
        """
        Resolves a specific type of entity definition based on the provided content type by
        matching it against the available subclasses of the class. This utility ensures that
        the given content type is valid and matches one of the registered subclasses.

        :param content_type: A string representing the type of content to be resolved.
            Must match the name of a subclass (in lowercase) of the current class.
        :type content_type: str

        :return: The resolved class type corresponding to the provided content type.
        :rtype: type['EntityTypes']
        """
        _content_type = content_type.lower()
        _subclasses = cls.subclasses()
        assert _content_type in _subclasses
        return _subclasses[_content_type]

    @classmethod
    def extract_type_hints(cls, obj: dict) -> str:
        """
        Extracts type hints from a given dictionary based on specific keys.

        This class method attempts to retrieve type hints from a dictionary using a specific
        key ("colander_internal_type") or nested keys ("super_type" and its "short_name" value).
        If the dictionary does not match the expected structure or the keys are not available,
        a ValueError is raised.

        :param obj: The dictionary from which type hints need to be extracted.
        :type obj: dict

        :return: A string representing the extracted type hint.
        :rtype: str

        :raises ValueError: If the type hint cannot be extracted from the provided dictionary.
        """
        try:
            if "colander_internal_type" in obj:
                return obj.get("colander_internal_type", "")
            elif "super_type" in obj:
                return obj.get("super_type").get("short_name").lower().replace("_", "")  # type: ignore[union-attr]
        except:
            pass
        raise ValueError("Unable to extract type hints.")

    @computed_field
    def super_type(self) -> "CommonEntitySuperType":
        return self.get_super_type()

    def get_super_type(self) -> "CommonEntitySuperType":
        return CommonEntitySuperType(
            **{
                "name": self.__class__.__name__,
                "short_name": self.__class__.__name__.upper(),
                "_class": self.__class__,
            }
        )


class Case(ColanderType):
    """
    Case represents a collection or grouping of related entities, artifacts, or events.

    This class is used to organize and manage related data, such as incidents, investigations, or projects.

    Example:
        >>> case = Case(
        ...     name='Investigation Alpha',
        ...     description='Investigation of suspicious activity'
        ... )
        >>> print(case.name)
        Investigation Alpha
    """

    id: UUID4 = Field(frozen=True, default_factory=lambda: uuid4())
    """The unique identifier for the case."""

    created_at: datetime = Field(default=datetime.now(UTC), frozen=True)
    """The timestamp when the case was created."""

    updated_at: datetime = Field(default=datetime.now(UTC))
    """The timestamp when the case was last updated."""

    name: str = Field(..., min_length=1, max_length=512)
    """The name of the case."""

    description: str = Field(..., min_length=1)
    """A description of the case."""

    documentation: str | None = None
    """Optional documentation or notes for the case."""

    pap: TlpPapLevel = TlpPapLevel.WHITE
    """The PAP (Permissible Actions Protocol) level for the case."""

    parent_case: Optional["Case"] | Optional[ObjectReference] = None
    """Reference to a parent case, if this case is a sub-case."""

    tlp: TlpPapLevel = TlpPapLevel.WHITE
    """The TLP (Traffic Light Protocol) level for the case."""

    colander_internal_type: Literal["case"] = "case"
    """Internal type discriminator for (de)serialization."""


class Entity(ColanderType, abc.ABC):
    """
    Entity is an abstract base class representing a core object in the model, such as an actor, artifact, device, etc.

    This class provides common fields for all entities, including identifiers, timestamps, descriptive fields,
    and references to cases.
    """

    id: UUID4 = Field(frozen=True, default_factory=lambda: uuid4())
    """The unique identifier for the entity."""

    created_at: datetime = Field(default=datetime.now(UTC), frozen=True)
    """The timestamp when the entity was created."""

    updated_at: datetime = Field(default=datetime.now(UTC))
    """The timestamp when the entity was last updated."""

    name: str = Field(..., min_length=1, max_length=512)
    """The name of the entity."""

    case: Optional[Case] | Optional[ObjectReference] = None
    """Reference to the case this entity belongs to."""

    description: str | None = None
    """A description of the entity."""

    pap: TlpPapLevel = TlpPapLevel.WHITE
    """The PAP (Permissible Actions Protocol) level for the entity."""

    source_url: str | AnyUrl | None = None
    """Optional source URL for the entity."""

    tlp: TlpPapLevel = TlpPapLevel.WHITE
    """The TLP (Traffic Light Protocol) level for the entity."""


class EntityRelation(ColanderType):
    """
    EntityRelation represents a relationship between two entities in the model.

    This class is used to define and manage relationships between objects, such as associations
    between observables, devices, or actors.

    Example:
        >>> obs1 = Observable(
        ...     id=uuid4(),
        ...     name='1.1.1.1',
        ...     type=ObservableTypes.enum.IPV4.value
        ... )
        >>> obs2 = Observable(
        ...     id=uuid4(),
        ...     name='8.8.8.8',
        ...     type=ObservableTypes.enum.IPV4.value
        ... )
        >>> relation = EntityRelation(
        ...     id=uuid4(),
        ...     name='connection',
        ...     obj_from=obs1,
        ...     obj_to=obs2
        ... )
        >>> print(relation.name)
        connection
    """

    id: UUID4 = Field(frozen=True, default_factory=lambda: uuid4())
    """The unique identifier for the entity relation."""

    created_at: datetime = Field(default=datetime.now(UTC), frozen=True)
    """The timestamp when the entity relation was created."""

    updated_at: datetime = Field(default=datetime.now(UTC))
    """The timestamp when the entity relation was last updated."""

    name: str = Field(..., min_length=1, max_length=512)
    """The name of the entity relation."""

    case: Optional[Case] | Optional[ObjectReference] = None
    """Reference to the case this relation belongs to."""

    attributes: Optional[Dict[str, str]] = None
    """Dictionary of additional attributes for the relation."""

    obj_from: EntityTypes | ObjectReference = Field(...)
    """The source entity or reference in the relation."""

    obj_to: EntityTypes | ObjectReference = Field(...)
    """The target entity or reference in the relation."""


class ArtifactType(CommonEntityType):
    """
    ArtifactType represents metadata for artifacts in Colander. Check :ref:`the list of supported
    types <artifact_types>`.

    Example:
        >>> artifact_type = ArtifactTypes.enum.REPORT.value
        >>> print(artifact_type.short_name)
        REPORT
    """

    type_hints: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in _load_entity_supported_types("artifact")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name

    def match_mime_type(self, mime_type) -> bool:
        wildcard = "*"
        if not mime_type:
            return False
        striped_mime_type = mime_type.lower().strip()
        if self.type_hints and "suggested_by_mime_types" in self.type_hints:
            for _mime_type in self.type_hints["suggested_by_mime_types"].get("types", []):
                _prefix = _mime_type.replace("*", "")
                if wildcard in _mime_type and striped_mime_type.startswith(_prefix):
                    return True
            return striped_mime_type in self.type_hints["suggested_by_mime_types"].get("types", [])
        return False


class ArtifactTypes:
    """
    ArtifactTypes provides access to all supported artifact types.

    This class loads artifact type definitions from the artifact types JSON file and exposes them as an enum.
    It also provides a method to look up an artifact type by its short name.

    Example:
        >>> artifact_type = ArtifactTypes.enum.REPORT.value
        >>> print(artifact_type.name)
        Report
        >>> default_type = ArtifactTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    _types: List[ArtifactType] = [ArtifactType(**t) for t in _load_entity_supported_types("artifact")]
    enum = Enum("EntityTypes", [(t.short_name, t) for t in _types])  # type: ignore[misc]
    default = enum.GENERIC.value  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str) -> ArtifactType:
        sn = short_name.replace(" ", "_").upper()
        if sn in cls.enum._member_names_:
            return cls.enum[sn].value
        return cls.default

    @classmethod
    def by_mime_type(cls, mime_type: str) -> ArtifactType:
        for _artifact_type in cls._types:
            if _artifact_type.match_mime_type(mime_type):
                return _artifact_type
        else:
            return cls.default


class ObservableType(CommonEntityType):
    """
    ObservableType represents metadata for observables in Colander. Check :ref:`the list of supported
    types <observable_types>`.

    Example:
        >>> observable_type = ObservableType(
        ...     id=uuid4(),
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
        if short_name not in {t["short_name"] for t in _load_entity_supported_types("observable")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class ObservableTypes:
    """
    ObservableTypes provides access to all supported observable types.

    This class loads observable type definitions from the observable types JSON file and exposes them as an enum.
    It also provides a method to look up an observable type by its short name.

    Example:
        >>> observable_type = ObservableTypes.enum.IPV4.value
        >>> print(observable_type.name)
        IPv4
        >>> default_type = ObservableTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    _types: List[ObservableType] = [ObservableType(**t) for t in _load_entity_supported_types("observable")]
    enum = Enum("EntityTypes", [(t.short_name, t) for t in _types])  # type: ignore[misc]
    default = enum.GENERIC.value  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str) -> ObservableType:
        sn = short_name.replace(" ", "_").upper()
        if sn in cls.enum._member_names_:
            return cls.enum[sn].value
        return cls.default


class ThreatType(CommonEntityType):
    """
    ThreatType represents metadata for threats in Colander. Check :ref:`the list of supported types <threat_types>`.

    Example:
        >>> threat_type = ThreatTypes.enum.TROJAN.value
        >>> print(threat_type.name)
        Trojan
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in _load_entity_supported_types("threat")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class ThreatTypes:
    """
    ThreatTypes provides access to all supported threat types.

    This class loads threat type definitions from the threat types JSON file and exposes them as an enum.
    It also provides a method to look up a threat type by its short name.

    Example:
        >>> threat_type = ThreatTypes.enum.TROJAN.value
        >>> print(threat_type.name)
        Trojan
        >>> default_type = ThreatTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    _types: List[ThreatType] = [ThreatType(**t) for t in _load_entity_supported_types("threat")]
    enum = Enum("EntityTypes", [(t.short_name, t) for t in _types])  # type: ignore[misc]
    default = enum.GENERIC.value  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str) -> ThreatType:
        sn = short_name.replace(" ", "_").upper()
        if sn in cls.enum._member_names_:
            return cls.enum[sn].value
        return cls.default


class ActorType(CommonEntityType):
    """
    ActorType represents metadata for actors in Colander. Check :ref:`the list of supported types <actor_types>`.

    Example:
        >>> actor_type = ActorTypes.enum.INDIVIDUAL.value
        >>> print(actor_type.name)
        Individual
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in _load_entity_supported_types("actor")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class ActorTypes:
    """
    ActorTypes provides access to all supported actor types.

    This class loads actor type definitions from the actor types JSON file and exposes them as an enum.
    It also provides a method to look up an actor type by its short name.

    Example:
        >>> actor_type = ActorTypes.enum.INDIVIDUAL.value
        >>> print(actor_type.name)
        Individual
        >>> default_type = ActorTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    _types: List[ActorType] = [ActorType(**t) for t in _load_entity_supported_types("actor")]
    enum = Enum("EntityTypes", [(t.short_name, t) for t in _types])  # type: ignore[misc]
    default = enum.GENERIC.value  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str) -> ActorType:
        sn = short_name.replace(" ", "_").upper()
        if sn in cls.enum._member_names_:
            return cls.enum[sn].value
        return cls.default


class DeviceType(CommonEntityType):
    """
    DeviceType represents metadata for devices in Colander. Check :ref:`the list of supported types <device_types>`.

    Example:
        >>> device_type = DeviceTypes.enum.MOBILE.value
        >>> print(device_type.name)
        Mobile device
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in _load_entity_supported_types("device")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class DeviceTypes:
    """
    DeviceTypes provides access to all supported device types.

    This class loads device type definitions from the device types JSON file and exposes them as an enum.
    It also provides a method to look up a device type by its short name.

    Example:
        >>> device_type = DeviceTypes.enum.LAPTOP.value
        >>> print(device_type.name)
        Laptop
        >>> default_type = DeviceTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    _types: List[DeviceType] = [DeviceType(**t) for t in _load_entity_supported_types("device")]
    enum = Enum("EntityTypes", [(t.short_name, t) for t in _types])  # type: ignore[misc]
    default = enum.GENERIC.value  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str) -> DeviceType:
        sn = short_name.replace(" ", "_").upper()
        if sn in cls.enum._member_names_:
            return cls.enum[sn].value
        return cls.default


class EventType(CommonEntityType):
    """
    EventType represents metadata for events in Colander. Check :ref:`the list of supported types <event_types>`.

    Example:
        >>> event_type = EventTypes.enum.HIT.value
        >>> print(event_type.name)
        Hit
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in _load_entity_supported_types("event")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class EventTypes:
    """
    EventTypes provides access to all supported event types.

    This class loads event type definitions from the event types JSON file and exposes them as an enum.
    It also provides a method to look up an event type by its short name.

    Example:
        >>> event_type = EventTypes.enum.HIT.value
        >>> print(event_type.name)
        Hit
        >>> default_type = EventTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    _types: List[EventType] = [EventType(**t) for t in _load_entity_supported_types("event")]
    enum = Enum("EntityTypes", [(t.short_name, t) for t in _types])  # type: ignore[misc]
    default = enum.GENERIC.value  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str) -> EventType:
        sn = short_name.replace(" ", "_").upper()
        if sn in cls.enum._member_names_:
            return cls.enum[sn].value
        return cls.default


class DetectionRuleType(CommonEntityType):
    """
    DetectionRuleType represents metadata for detection rules in Colander. Check :ref:`the list of supported
    types <detection_rule_types>`.

    Example:
        >>> detection_rule_type = DetectionRuleTypes.enum.YARA.value
        >>> print(detection_rule_type.name)
        Yara rule
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in _load_entity_supported_types("detection_rule")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class DetectionRuleTypes:
    """
    DetectionRuleTypes provides access to all supported detection rule types.

    This class loads detection rule type definitions from the detection rule types JSON file and exposes them as an enum.
    It also provides a method to look up a detection rule type by its short name.

    Example:
        >>> detection_rule_type = DetectionRuleTypes.enum.YARA.value
        >>> print(detection_rule_type.name)
        Yara rule
        >>> default_type = DetectionRuleTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    _types: List[DetectionRuleType] = [DetectionRuleType(**t) for t in _load_entity_supported_types("detection_rule")]
    enum = Enum("EntityTypes", [(t.short_name, t) for t in _types])  # type: ignore[misc]
    default = enum.GENERIC.value  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str) -> DetectionRuleType:
        sn = short_name.replace(" ", "_").upper()
        if sn in cls.enum._member_names_:
            return cls.enum[sn].value
        return cls.default


class DataFragmentType(CommonEntityType):
    """
    DataFragmentType represents metadata for data fragments in Colander. Check :ref:`the list of supported
    types <data_fragment_types>`.

    Example:
        >>> data_fragment_type = DataFragmentTypes.enum.CODE.value
        >>> print(data_fragment_type.name)
        Piece of code
    """

    @field_validator("short_name", mode="before")
    @classmethod
    def is_supported_type(cls, short_name: str):
        if short_name not in {t["short_name"] for t in _load_entity_supported_types("data_fragment")}:
            raise ValueError(f"{short_name} is not supported")
        return short_name


class DataFragmentTypes:
    """
    DataFragmentTypes provides access to all supported data fragment types.

    This class loads data fragment type definitions from the data fragment types JSON file and exposes them as an enum.
    It also provides a method to look up a data fragment type by its short name.

    Example:
        >>> data_fragment_type = DataFragmentTypes.enum.CODE.value
        >>> print(data_fragment_type.name)
        Piece of code
        >>> default_type = DataFragmentTypes.by_short_name("nonexistent")
        >>> print(default_type.name)
        Generic
    """

    _types: List[DataFragmentType] = [DataFragmentType(**t) for t in _load_entity_supported_types("data_fragment")]
    enum = Enum("EntityTypes", [(t.short_name, t) for t in _types])  # type: ignore[misc]
    default = enum.GENERIC.value  # type: ignore[attr-defined]

    @classmethod
    def by_short_name(cls, short_name: str) -> DataFragmentType:
        sn = short_name.replace(" ", "_").upper()
        if sn in cls.enum._member_names_:
            return cls.enum[sn].value
        return cls.default


class Actor(Entity):
    """
    Actor represents an individual or group involved in an event, activity, or system.

    This class extends the Entity base class and includes additional fields specific to actors.

    Example:
        >>> actor_type = ActorTypes.enum.INDIVIDUAL.value
        >>> actor = Actor(
        ...     name='John Doe',
        ...     type=actor_type
        ... )
        >>> print(actor.name)
        John Doe
    """

    type: ActorType
    """The type definition for the actor."""

    colander_internal_type: Literal["actor"] = "actor"
    """Internal type discriminator for (de)serialization."""

    attributes: Optional[Dict[str, str]] = None
    """Dictionary of additional attributes for the device."""


class Device(Entity):
    """
    Device represents a physical or virtual device in Colander.

    This class extends the Entity base class and includes additional fields specific to devices,
    such as their type, attributes, and the actor operating the device.

    Example:
        >>> device_type = DeviceTypes.enum.MOBILE.value
        >>> actor = Actor(name='John Doe', type=ActorTypes.enum.INDIVIDUAL.value)
        >>> device = Device(
        ...     name="John's Phone",
        ...     type=device_type,
        ...     operated_by=actor,
        ...     attributes={'os': 'Android', 'version': '12'}
        ... )
        >>> print(device.name)
        John's Phone
    """

    type: DeviceType
    """The type definition for the device."""

    attributes: Optional[Dict[str, str]] = None
    """Dictionary of additional attributes for the device."""

    operated_by: Optional[Actor] | Optional[ObjectReference] = None
    """Reference to the actor operating the device."""

    colander_internal_type: Literal["device"] = "device"
    """Internal type discriminator for (de)serialization."""


class Artifact(Entity):
    """
    Artifact represents a file or data object, such as a document, image, or binary, within the system.

    This class extends the Entity base class and includes additional fields specific to artifacts,
    such as type, attributes, extraction source, file metadata, and cryptographic hashes.

    Example:
        >>> artifact_type = ArtifactTypes.enum.DOCUMENT.value
        >>> device_type = DeviceTypes.enum.LAPTOP.value
        >>> device = Device(name='Analyst Laptop', type=device_type)
        >>> artifact = Artifact(
        ...     name='malware_sample.pdf',
        ...     type=artifact_type,
        ...     extracted_from=device,
        ...     extension='pdf',
        ...     original_name='invoice.pdf',
        ...     mime_type='application/pdf',
        ...     md5='d41d8cd98f00b204e9800998ecf8427e',
        ...     sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709',
        ...     sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ...     size_in_bytes=12345
        ... )
        >>> print(artifact.name)
        malware_sample.pdf
    """

    type: ArtifactType
    """The type definition for the artifact."""

    attributes: Optional[Dict[str, str]] = None
    """Dictionary of additional attributes for the artifact."""

    extracted_from: Optional[Device] | Optional[ObjectReference] = None
    """Reference to the device from which this artifact was extracted."""

    extension: str | None = None
    """The file extension of the artifact, if applicable."""

    original_name: str | None = None
    """The original name of the artifact before ingestion."""

    mime_type: str | None = None
    """The MIME type of the artifact."""

    detached_signature: str | None = None
    """Optional detached signature for the artifact."""

    md5: str | None = None
    """MD5 hash of the artifact."""

    sha1: str | None = None
    """SHA1 hash of the artifact."""

    sha256: str | None = None
    """SHA256 hash of the artifact."""

    size_in_bytes: NonNegativeInt = 0
    """The size of the artifact in bytes."""

    colander_internal_type: Literal["artifact"] = "artifact"
    """Internal type discriminator for (de)serialization."""


class DataFragment(Entity):
    """
    DataFragment represents a fragment of data, such as a code snippet, text, or other content.

    This class extends the Entity base class and includes additional fields specific to data fragments,
    such as their type, content, and the artifact from which they were extracted.

    Example:
        >>> data_fragment_type = DataFragmentTypes.enum.CODE.value
        >>> artifact = Artifact(
        ...     name='example_artifact',
        ...     type=ArtifactTypes.enum.DOCUMENT.value
        ... )
        >>> data_fragment = DataFragment(
        ...     name='Sample Code',
        ...     type=data_fragment_type,
        ...     content='print("Hello, World!")',
        ...     extracted_from=artifact
        ... )
        >>> print(data_fragment.content)
        print("Hello, World!")
    """

    type: DataFragmentType
    """The type definition for the data fragment."""

    content: str
    """The content of the data fragment."""

    extracted_from: Optional[Artifact] | Optional[ObjectReference] = None
    """Reference to the artifact from which this data fragment was extracted."""

    colander_internal_type: Literal["datafragment"] = "datafragment"
    """Internal type discriminator for (de)serialization."""


class Threat(Entity):
    """
    Threat represents a threat entity, such as a malware family, campaign, or adversary.

    This class extends the Entity base class and includes a type field for threat classification.

    Example:
        >>> threat_type = ThreatTypes.enum.TROJAN.value
        >>> threat = Threat(
        ...     name='Emotet',
        ...     type=threat_type
        ... )
        >>> print(threat.name)
        Emotet
    """

    type: ThreatType
    """The type definition for the threat."""

    colander_internal_type: Literal["threat"] = "threat"
    """Internal type discriminator for (de)serialization."""


class Observable(Entity):
    """
    Observable represents an entity that can be observed or detected within the system.

    This class extends the Entity base class and includes additional fields specific to observables,
    such as classification, raw value, extraction source, associated threat, and operator.

    Example:
        >>> ot = ObservableTypes.enum.IPV4.value
        >>> obs = Observable(
        ...     name='1.2.3.4',
        ...     type=ot,
        ...     classification='malicious',
        ...     raw_value='1.2.3.4',
        ...     attributes={'asn': 'AS123'}
        ... )
        >>> print(obs.name)
        1.2.3.4
    """

    type: ObservableType = Field(...)
    """The type definition for the observable."""

    attributes: Optional[Dict[str, str]] = None
    """Dictionary of additional attributes for the observable."""

    classification: str | None = Field(default=None, max_length=512)
    """Optional classification label for the observable."""

    raw_value: str | None = None
    """The raw value associated with the observable."""

    extracted_from: Optional[Artifact] | Optional[ObjectReference] = None
    """Reference to the artifact from which this observable was extracted."""

    associated_threat: Optional[Threat] | Optional[ObjectReference] = None
    """Reference to an associated threat."""

    operated_by: Optional[Actor] | Optional[ObjectReference] = None
    """Reference to the actor operating this observable."""

    colander_internal_type: Literal["observable"] = "observable"
    """Internal type discriminator for (de)serialization."""


class DetectionRule(Entity):
    """
    DetectionRule represents a rule used for detecting specific content or logic related to observables or
    object references.

    This class is designed to encapsulate detection rules that can be applied across various systems or platforms to
    identify patterns or conditions defined by the user.

    Example:
        >>> drt = DetectionRuleTypes.enum.YARA.value
        >>> rule = DetectionRule(
        ...     name='Detect Malicious IP',
        ...     type=drt,
        ...     content='rule malicious_ip { condition: true }',
        ... )
        >>> print(rule.name)
        Detect Malicious IP
    """

    type: DetectionRuleType
    """The type definition for the detection rule."""

    content: str
    """The content or logic of the detection rule."""

    targeted_observables: Optional[List[Observable]] | Optional[List[ObjectReference]] = None
    """List of observables or references targeted by this detection rule."""

    colander_internal_type: Literal["detectionrule"] = "detectionrule"
    """Internal type discriminator for (de)serialization."""


class Event(Entity):
    """
    Event represents an occurrence or activity observed within a system, such as a detection, alert, or log entry.

    This class extends the Entity base class and includes additional fields specific to events,
    such as timestamps, count, involved observables, and references to related entities.

    Example:
        >>> et = EventTypes.enum.HIT.value
        >>> obs_type = ObservableTypes.enum.IPV4.value
        >>> obs = Observable(
        ...     id=uuid4(),
        ...     name='8.8.8.8',
        ...     type=obs_type
        ... )
        >>> event = Event(
        ...     name='Suspicious Connection',
        ...     type=et,
        ...     first_seen=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        ...     last_seen=datetime(2024, 6, 1, 12, 5, tzinfo=UTC),
        ...     involved_observables=[obs]
        ... )
        >>> print(event.name)
        Suspicious Connection
    """

    type: EventType
    """The type definition for the event."""

    attributes: Optional[Dict[str, str]] = None
    """Dictionary of additional attributes for the event."""

    first_seen: datetime = datetime.now(UTC)
    """The timestamp when the event was first observed."""

    last_seen: datetime = datetime.now(UTC)
    """The timestamp when the event was last observed."""

    count: PositiveInt = 1
    """The number of times this event was observed."""

    extracted_from: Optional[Artifact] | Optional[ObjectReference] = None
    """Reference to the artifact from which this event was extracted."""

    observed_on: Optional[Device] | Optional[ObjectReference] = None
    """Reference to the device on which this event was observed."""

    detected_by: Optional[DetectionRule] | Optional[ObjectReference] = None
    """Reference to the detection rule that detected this event."""

    # ToDo: missing attribute in Colander implementation
    attributed_to: Optional[Actor] | Optional[ObjectReference] = None
    """Reference to the actor attributed to this event."""

    # ToDo: missing attribute in Colander implementation
    target: Optional[Actor] | Optional[ObjectReference] = None
    """Reference to the actor targeted during this event."""

    involved_observables: List[Observable] | List[ObjectReference] = []
    """List of observables or references involved in this event."""

    colander_internal_type: Literal["event"] = "event"
    """Internal type discriminator for (de)serialization."""

    @model_validator(mode="after")
    def _check_dates(self) -> Any:
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must be before last_seen")
        return self


class ColanderRepository(object, metaclass=Singleton):
    """
    Singleton repository for managing and storing Case, Entity, and EntityRelation objects.

    This class provides centralized storage and reference management for all model instances,
    supporting insertion, lookup, and reference resolution/unlinking.
    """

    cases: Dict[str, Case]
    entities: Dict[str, EntityTypes]
    relations: Dict[str, EntityRelation]

    def __init__(self):
        """
        Initializes the repository with empty dictionaries for cases, entities, and relations.
        """
        self.cases = {}
        self.entities = {}
        self.relations = {}

    def clear(self):
        self.cases.clear()
        self.entities.clear()
        self.relations.clear()

    def __lshift__(self, other: EntityTypes | Case) -> None:
        """
        Inserts an object (Entity, EntityRelation, or Case) into the appropriate repository dictionary.

        :param other: The object to insert.
        :type other: EntityTypes | Case
        """
        if isinstance(other, Entity):
            self.entities[str(other.id)] = other
        elif isinstance(other, EntityRelation):
            self.relations[str(other.id)] = other
        elif isinstance(other, Case):
            self.cases[str(other.id)] = other

    def __rshift__(self, other: str | UUID4) -> EntityTypes | EntityRelation | Case | str | UUID4:
        """
        Retrieves an object by its string or UUID identifier from entities, relations, or cases.

        :param other: The identifier to look up.
        :type other: str | UUID4

        :return: The found object or the identifier if not found.
        :rtype: EntityTypes | EntityRelation | Case | str | UUID4
        """
        _other = str(other)
        if _other in self.entities:
            return self.entities[_other]
        elif _other in self.relations:
            return self.relations[_other]
        elif _other in self.cases:
            return self.cases[_other]
        return other

    def unlink_references(self):
        """
        Unlinks all object references in entities, relations, and cases by replacing them with UUIDs.
        """
        for _, entity in self.entities.items():
            entity.unlink_references()
        for _, relation in self.relations.items():
            relation.unlink_references()
        for _, case in self.cases.items():
            case.unlink_references()

    def resolve_references(self):
        """
        Resolves all UUID references in entities, relations, and cases to their corresponding objects.
        """
        for _, entity in self.entities.items():
            entity.resolve_references()
        for _, relation in self.relations.items():
            relation.resolve_references()
        for _, case in self.cases.items():
            case.resolve_references()


class ColanderFeed(ColanderType):
    """
    ColanderFeed aggregates entities, relations, and cases for bulk operations or data exchange.

    This class is used to load, manage, and resolve references for collections of model objects.

    Example:
        >>> feed_data = {
        ...     "entities": {
        ...         "204d4590-a3ee-4f24-8eaf-350ec2fa751b": {
        ...             "id": "204d4590-a3ee-4f24-8eaf-350ec2fa751b",
        ...             "name": "Example Observable",
        ...             "type": {"name": "IPv4", "short_name": "IPV4"},
        ...             "super_type": {"short_name": "observable"},
        ...             "colander_internal_type": "observable"
        ...         }
        ...     },
        ...     "relations": {},
        ...     "cases": {}
        ... }
        >>> feed = ColanderFeed.load(feed_data)
        >>> print(list(feed.entities.keys()))
        ['204d4590-a3ee-4f24-8eaf-350ec2fa751b']
    """

    id: UUID4 = Field(frozen=True, default_factory=lambda: uuid4())
    """The unique identifier for the feed."""

    name: str = ""
    """Optional name of the feed."""

    description: str = ""
    """Optional description of the feed."""

    entities: Optional[Dict[str, EntityTypes]] = {}
    """Dictionary of entity objects, keyed by their IDs."""

    relations: Optional[Dict[str, EntityRelation]] = {}
    """Dictionary of entity relations, keyed by their IDs."""

    cases: Optional[Dict[str, Case]] = {}
    """Dictionary of case objects, keyed by their IDs."""

    @staticmethod
    def load(raw_object: dict | list) -> "ColanderFeed":
        """
        Loads an EntityFeed from a raw object, which can be either a dictionary or a list.

        :param raw_object: The raw data representing the entities and relations to be loaded into
            the EntityFeed.
        :type raw_object: dict | list

        :return: The EntityFeed loaded from a raw object.
        :rtype: ColanderFeed

        :raises ValueError: If there are inconsistencies in entity IDs or relations.
        """
        if "entities" in raw_object:
            for entity_id, entity in raw_object["entities"].items():
                if entity_id != entity.get("id"):
                    raise ValueError(f"Relation {entity_id} does not match with the ID of {entity}")
                entity["colander_internal_type"] = entity["super_type"]["short_name"].lower()
        if "relations" in raw_object:
            for relation_id, relation in raw_object["relations"].items():
                if relation_id != relation.get("id"):
                    raise ValueError(f"Relation {relation_id} does not match with the ID of {relation}")
                if (
                    "obj_from" not in relation
                    and "obj_to" not in relation
                    and "obj_from_id" in relation
                    and "obj_to_id" in relation
                ):
                    relation["obj_from"] = relation["obj_from_id"]
                    relation["obj_to"] = relation["obj_to_id"]
        entity_feed = ColanderFeed.model_validate(raw_object)
        entity_feed.resolve_references()
        for _, entity in entity_feed.entities.items():
            entity.resolve_references()
        for _, relation in entity_feed.relations.items():
            relation.resolve_references()
        for _, case in entity_feed.cases.items():
            case.resolve_references()
        return entity_feed

    def resolve_references(self, strict=False):
        """
        Resolves references within entities, relations, and cases.

        Iterates over each entity, relation, and case within the respective collections, calling their
        `resolve_references` method to update them with any referenced data. This helps in synchronizing
        internal state with external dependencies or updates.

        :param strict: If True, raises a ValueError when a UUID reference cannot be resolved.
                       If False, unresolved references remain as UUIDs.
        :type strict: bool
        """
        for _, entity in self.entities.items():
            entity.resolve_references(strict=strict)
        for _, relation in self.relations.items():
            relation.resolve_references(strict=strict)
        for _, case in self.cases.items():
            case.resolve_references(strict=strict)

    def unlink_references(self) -> None:
        """
        Unlinks references from all entities, relations, and cases within the current context.

        This method iterates through each entity, relation, and case stored in the `entities`, `relations`,
        and `cases` dictionaries respectively, invoking their `unlink_references()` methods to clear any references
        held by these objects. This operation is useful for breaking dependencies or preparing data for deletion
        or modification.
        """
        for _, entity in self.entities.items():  # type: ignore[union-attr]
            entity.unlink_references()
        for _, relation in self.relations.items():  # type: ignore[union-attr]
            relation.unlink_references()
        for _, case in self.cases.items():  # type: ignore[union-attr]
            case.unlink_references()


class CommonEntitySuperType(BaseModel):
    """
    CommonEntitySuperType defines metadata for a super type of entities in the Colander data model.

    This class is used to represent high-level categories of entities (such as Actor, Artifact, Device, etc.)
    and provides fields for the short name, display name, associated types, and the Python class implementing the entity.
    """

    short_name: str = Field(frozen=True, max_length=32)
    """A short name for the model type."""

    name: str = Field(frozen=True, max_length=512)
    """The name of the model type."""

    types: Optional[List[object]] = Field(default=None, exclude=True)
    """Optional reference to the enum or collection of supported types."""

    model_class: Any = Field(default=None, exclude=True)
    """The Python class associated with this super type (Observable...)."""

    type_class: Any = Field(default=None, exclude=True)
    """The Python class associated with the entity type (ObservableType...)."""

    default_type: Any = Field(default=None, exclude=True)
    """The default entity type (GENERIC...)."""

    def type_by_short_name(self, short_name: str):
        for t in self.types:
            if hasattr(t, short_name.upper()):
                return getattr(t, short_name.upper()).value
        return self.default_type


class CommonEntitySuperTypes(enum.Enum):
    """
    CommonEntitySuperTypes is an enumeration of all super types for entities in the Colander data model.

    Each member of this enum represents a high-level entity category (such as Actor, Artifact, Device, etc.)
    and holds a CommonEntitySuperType instance containing metadata and references to the corresponding
    entity class and its supported types.

    This enum is used for type resolution and validation across the model.

    Example:
        >>> super_type = CommonEntitySuperTypes.ACTOR.value
        >>> print(super_type.name)
        Actor
    """

    ACTOR = CommonEntitySuperType(
        short_name="ACTOR",
        name="Actor",
        model_class=Actor,
        type_class=ActorType,
        default_type=ActorTypes.default,
        types=ActorTypes.enum,
    )
    ARTIFACT = CommonEntitySuperType(
        short_name="ARTIFACT",
        name="Artifact",
        model_class=Artifact,
        type_class=ArtifactType,
        default_type=ArtifactTypes.default,
        types=ArtifactTypes.enum,
    )
    DATA_FRAGMENT = CommonEntitySuperType(
        short_name="DATA_FRAGMENT",
        name="Data fragment",
        model_class=DataFragment,
        type_class=DataFragmentType,
        default_type=DataFragmentTypes.default,
        types=DataFragmentTypes.enum,
    )
    DETECTION_RULE = CommonEntitySuperType(
        short_name="DETECTION_RULE",
        name="Detection rule",
        model_class=DetectionRule,
        type_class=DetectionRuleType,
        default_type=DetectionRuleTypes.default,
        types=DetectionRuleTypes.enum,
    )
    DEVICE = CommonEntitySuperType(
        short_name="DEVICE",
        name="Device",
        model_class=Device,
        type_class=DeviceType,
        default_type=DeviceTypes.default,
        types=DeviceTypes.enum,
    )
    EVENT = CommonEntitySuperType(
        short_name="EVENT",
        name="Event",
        model_class=Event,
        type_class=EventType,
        default_type=EventTypes.default,
        types=EventTypes.enum,
    )
    OBSERVABLE = CommonEntitySuperType(
        short_name="OBSERVABLE",
        name="Observable",
        model_class=Observable,
        type_class=ObservableType,
        default_type=ObservableTypes.default,
        types=ObservableTypes.enum,
    )
    THREAT = CommonEntitySuperType(
        short_name="THREAT",
        name="Threat",
        model_class=Threat,
        type_class=ThreatType,
        default_type=ThreatTypes.default,
        types=ThreatTypes.enum,
    )

    @classmethod
    def by_short_name(cls, short_name: str) -> Optional[CommonEntitySuperType]:
        sn = short_name.replace(" ", "_").upper()
        if sn in cls.__members__:
            return cls[sn].value
        return None
