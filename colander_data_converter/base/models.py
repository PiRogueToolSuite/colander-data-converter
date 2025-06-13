import abc
from datetime import datetime, UTC
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
)

from colander_data_converter.base.common import (
    ObjectReference,
    SuperType,
    TlpPapLevel,
    Singleton, CommonModelType,
)

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


class ColanderType(BaseModel):
    """
    Base class for all Colander model types, providing common functionality for
    post-initialization, reference management, and type resolution.

    This class extends Pydantic's BaseModel and is intended to be subclassed by
    all model entities. It includes methods for linking and unlinking object references,
    resolving type hints, and extracting subclass information.
    """

    model_config = {
        "str_strip_whitespace": True,
        "arbitrary_types_allowed": True,
    }

    def model_post_init(self, __context):
        """
        Executes post-initialization logic for the model, ensuring the repository
        registers the current subclass instance.

        :param __context: Additional context provided for post-initialization
                          handling.
        :type __context: Any
        """
        _ = Repository()
        _ << self

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
        for field, info in self.__class__.model_fields.items():
            annotation_args = get_args(info.annotation)
            if ObjectReference in annotation_args:
                ref = self.__getattribute__(field)
                if ref and type(ref) is not UUID:
                    self.__setattr__(field, ref.id)
            elif List[ObjectReference] in annotation_args:
                refs = self.__getattribute__(field)
                object_refences: List[UUID] = []
                _update = False
                for ref in refs:
                    if ref and type(ref) is not UUID:
                        object_refences.append(ref.id)
                        _update = True
                if _update:
                    self.__setattr__(field, object_refences)

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
        for field, info in self.__class__.model_fields.items():
            annotation_args = get_args(info.annotation)
            if ObjectReference in annotation_args:
                ref = self.__getattribute__(field)
                if type(ref) is UUID:
                    x = Repository() >> ref
                    if strict and isinstance(x, UUID):
                        raise ValueError(f"Unable to resolve UUID reference {x}")
                    self.__setattr__(field, x)
            elif List[ObjectReference] in annotation_args:
                refs = self.__getattribute__(field)
                object_references: List[EntityTypes] = []
                _update = False
                for ref in refs:
                    if type(ref) is UUID:
                        x = Repository() >> ref
                        if strict and isinstance(x, UUID):
                            raise ValueError(f"Unable to resolve UUID reference {x}")
                        object_references.append(x)
                        _update = True
                if _update:
                    self.__setattr__(field, object_references)

    @classmethod
    def subclasses(cls) -> Dict[str, type["EntityTypes"]]:
        """
        Generates a dictionary containing all subclasses of the current class.

        This method collects all the direct subclasses of the current class and maps their
        names (converted to lowercase) to the class itself. It is primarily useful for
        organizing and accessing class hierarchies dynamically.

        :return: A dictionary where the keys are the lowercase names of the subclasses,
                 and the values are the subclass types themselves.
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
                return obj.get("colander_internal_type")
            elif "super_type" in obj:
                return obj.get("super_type").get("short_name").lower().replace("_", "")
        except:
            pass
        raise ValueError("Unable to extract type hints.")

    @computed_field
    def super_type(self) -> SuperType:
        return SuperType(
            **{
                "name": self.__class__.__name__,
                "short_name": self.__class__.__name__.upper(),
                "class": self.__class__,
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

    created_at: datetime | None = Field(default=None, frozen=True)
    """The timestamp when the case was created."""

    updated_at: datetime | None = Field(default=None)
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

    signing_key: str | None = None
    """Optional signing key associated with the case."""

    tlp: TlpPapLevel = TlpPapLevel.WHITE
    """The TLP (Traffic Light Protocol) level for the case."""

    verify_key: str | None = None
    """Optional verification key associated with the case."""

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

    created_at: datetime | None = Field(default=None, frozen=True)
    """The timestamp when the entity was created."""

    updated_at: datetime | None = Field(default=None, frozen=True)
    """The timestamp when the entity was last updated."""

    name: str = Field(..., min_length=1, max_length=512)
    """The name of the entity."""

    case: Optional[Case] | Optional[ObjectReference] = None
    """Reference to the case this entity belongs to."""

    description: str | None = None
    """A description of the entity."""

    pap: TlpPapLevel = TlpPapLevel.WHITE
    """The PAP (Permissible Actions Protocol) level for the entity."""

    source_url: AnyUrl | None = None
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
        ...     name='1.1.1.1',
        ...     type=ObservableType(name='IP v4 address', short_name='IPV4')
        ... )
        >>> obs2 = Observable(
        ...     name='8.8.8.8',
        ...     type=ObservableType(name='IP v4 address', short_name='IPV4')
        ... )
        >>> relation = EntityRelation(
        ...     name='connection',
        ...     obj_from=obs1,
        ...     obj_to=obs2
        ... )
        >>> print(relation.name)
        Connection
    """

    id: UUID4 = Field(frozen=True, default_factory=lambda: uuid4())
    """The unique identifier for the entity relation."""

    created_at: datetime | None = Field(default=None, frozen=True)
    """The timestamp when the entity relation was created."""

    updated_at: datetime | None = Field(default=None)
    """The timestamp when the entity relation was last updated."""

    name: str = Field(..., min_length=1, max_length=512)
    """The name of the entity relation."""

    case: Optional[Case] | Optional[ObjectReference] = None
    """Reference to the case this relation belongs to."""

    attributes: Optional[Dict[str, str]] = None
    """Optional dictionary of additional attributes for the relation."""

    obj_from: EntityTypes | ObjectReference = Field(...)
    """The source entity or reference in the relation."""

    obj_to: EntityTypes | ObjectReference = Field(...)
    """The target entity or reference in the relation."""


class ArtifactType(CommonModelType):
    """
    ArtifactType represents metadata for artifacts in the system.

    Example:
        >>> artifact_type = ArtifactType(
        ...     id=uuid4(),
        ...     short_name='PDF',
        ...     name='PDF document'
        ... )
        >>> print(artifact_type.short_name)
        PDF
    """

    pass


class ObservableType(CommonModelType):
    """
    ObservableType represents metadata for observables in the system.

    Example:
        >>> observable_type = ObservableType(
        ...     id=uuid4(),
        ...     short_name='IPV4',
        ...     name='IP v4 address',
        ...     description='An IPv4 address type'
        ... )
        >>> print(observable_type.name)
        IP v4 address
    """

    pass


class ThreatType(CommonModelType):
    """
    ThreatType represents metadata for threats in the system.

    Example:
        >>> threat_type = ThreatType(
        ...     id=uuid4(),
        ...     short_name='TROJAN',
        ...     name='A trojan malware'
        ... )
        >>> print(threat_type.name)
        A trojan malware
    """

    pass


class ActorType(CommonModelType):
    """
    ActorType represents metadata for actors in the system.

    Example:
        >>> actor_type = ActorType(
        ...     id=uuid4(),
        ...     short_name='INDIVIDUAL',
        ...     name='Individual',
        ...     description='A type for actors'
        ... )
        >>> print(actor_type.name)
        Individual
    """

    pass


class DeviceType(CommonModelType):
    """
    DeviceType represents metadata for devices in the system.

    Example:
        >>> device_type = DeviceType(
        ...     id=uuid4(),
        ...     short_name='MOBILE',
        ...     name='Mobile Device',
        ...     description='A type for devices'
        ... )
        >>> print(device_type.name)
        Mobile Device
    """

    pass


class EventType(CommonModelType):
    """
    EventType represents metadata for events in the system.

    Example:
        >>> event_type = EventType(
        ...     id=uuid4(),
        ...     short_name='NETCONN',
        ...     name='Network Connection',
        ...     description='A type for events'
        ... )
        >>> print(event_type.name)
        Network Connection
    """

    pass


class DetectionRuleType(CommonModelType):
    """
    DetectionRuleType represents metadata for detection rules in the system.

    Example:
        >>> detection_rule_type = DetectionRuleType(
        ...     id=uuid4(),
        ...     short_name='YARA',
        ...     name='Yara Rule',
        ...     description='A type for detection rules'
        ... )
        >>> print(detection_rule_type.name)
        Yara Rule
    """

    pass


class DataFragmentType(CommonModelType):
    """
    DataFragmentType represents metadata for data fragments in the system.

    Example:
        >>> data_fragment_type = DataFragmentType(
        ...     id=uuid4(),
        ...     short_name='CODE',
        ...     name='Code Snippet',
        ...     description='A type for data fragments'
        ... )
        >>> print(data_fragment_type.name)
        Code Snippet
    """

    pass


class Actor(Entity):
    """
    Actor represents an individual or group involved in an event, activity, or system.

    This class extends the Entity base class and includes additional fields specific to actors.

    Example:
        >>> actor_type = ActorType(name='Individual', short_name='INDIVIDUAL')
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


class Device(Entity):
    """
    Device represents a physical or virtual device in the system.

    This class extends the Entity base class and includes additional fields specific to devices,
    such as their type, attributes, and the actor operating the device.

    Example:
        >>> device_type = DeviceType(name='Mobile Device', short_name='MOBILE')
        >>> actor = Actor(name='John Doe', type=ActorType(name='Individual', short_name='INDIVIDUAL'))
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
    """Optional dictionary of additional attributes for the device."""

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
        >>> artifact_type = ArtifactType(name='PDF document', short_name='PDF')
        >>> device_type = DeviceType(name='Laptop', short_name='LAPTOP')
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
    """Optional dictionary of additional attributes for the artifact."""

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
        >>> data_fragment_type = DataFragmentType(name='Code Snippet', short_name='CODE')
        >>> artifact = Artifact(
        ...     name='example_artifact',
        ...     type=ArtifactType(name='PDF document', short_name='PDF')
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
        >>> threat_type = ThreatType(name='Trojan', short_name='TROJAN')
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
        >>> ot = ObservableType(name='IP v4 address', short_name='IPV4')
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
    """Optional dictionary of additional attributes for the observable."""

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
        >>> drt = DetectionRuleType(name='Yara', short_name='YARA')
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

    targeted_observables: (
        Optional[List[Observable]] | Optional[List[ObjectReference]]
    ) = None
    """List of observables or references targeted by this detection rule."""

    colander_internal_type: Literal["detectionrule"] = "detectionrule"
    """Internal type discriminator for (de)serialization."""


class Event(Entity):
    """
    Event represents an occurrence or activity observed within a system, such as a detection, alert, or log entry.

    This class extends the Entity base class and includes additional fields specific to events,
    such as timestamps, count, involved observables, and references to related entities.

    Example:
        >>> et = EventType(name='Network Connection', short_name='NETCONN')
        >>> obs_type = ObservableType(name='IP v4 address', short_name='IPV4')
        >>> obs = Observable(
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
    """Optional dictionary of additional attributes for the event."""

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

    involved_observables: (
        Optional[List[Observable]] | Optional[List[ObjectReference]]
    ) = None
    """List of observables or references involved in this event."""

    colander_internal_type: Literal["event"] = "event"
    """Internal type discriminator for (de)serialization."""

    @model_validator(mode="after")
    def _check_dates(self) -> Any:
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must be before last_seen")
        return self


class Repository(object, metaclass=Singleton):
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

    def __rshift__(self, other: str | UUID4) -> EntityTypes | EntityRelation | Case:
        """
        Retrieves an object by its string or UUID identifier from entities, relations, or cases.

        :param other: The identifier to look up.
        :type other: str | UUID4

        :return: The found object or the identifier if not found.
        :rtype: EntityTypes | EntityRelation | Case
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


class EntityFeed(ColanderType):
    """
    EntityFeed aggregates entities, relations, and cases for bulk operations or data exchange.

    This class is used to load, manage, and resolve references for collections of model objects.

    Example:
        >>> feed_data = {
        ...     "entities": {
        ...         "1": {
        ...             "name": "Example Observable",
        ...             "type": {"name": "IP v4 address", "short_name": "IPV4"},
        ...             "colander_internal_type": "observable"
        ...         }
        ...     },
        ...     "relations": {},
        ...     "cases": {}
        ... }
        >>> feed = EntityFeed.load(feed_data)
        >>> print(list(feed.entities.keys()))
        ['1']
    """

    entities: Optional[Dict[str, EntityTypes]] = {}
    """Dictionary of entity objects, keyed by their IDs."""

    relations: Optional[Dict[str, EntityRelation]] = {}
    """Dictionary of entity relations, keyed by their IDs."""

    cases: Optional[Dict[str, Case]] = {}
    """Dictionary of case objects, keyed by their IDs."""

    @staticmethod
    def load(raw_object: dict | list) -> "EntityFeed":
        """
        Loads an EntityFeed from a raw object, which can be either a dictionary or a list.

        :param raw_object: The raw data representing the entities and relations to be loaded into
            the EntityFeed.
        :type raw_object: dict | list

        :return: The EntityFeed loaded from a raw object.
        :rtype: EntityFeed

        :raises ValueError: If there are inconsistencies in entity IDs or relations.
        """
        if "entities" in raw_object:
            for entity_id, entity in raw_object["entities"].items():
                if entity_id != entity.get("id"):
                    raise ValueError(
                        f"Relation {entity_id} does not match with the ID of {entity}"
                    )
                entity["colander_internal_type"] = entity["super_type"][
                    "short_name"
                ].lower()
        if "relations" in raw_object:
            for relation_id, relation in raw_object["relations"].items():
                if relation_id != relation.get("id"):
                    raise ValueError(
                        f"Relation {relation_id} does not match with the ID of {relation}"
                    )
                if (
                    "obj_from" not in relation
                    and "obj_to" not in relation
                    and "obj_from_id" in relation
                    and "obj_to_id" in relation
                ):
                    relation["obj_from"] = relation["obj_from_id"]
                    relation["obj_to"] = relation["obj_to_id"]
        entity_feed = EntityFeed.model_validate(raw_object)
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
            entity.resolve_references()
        for _, relation in self.relations.items():
            relation.resolve_references()
        for _, case in self.cases.items():
            case.resolve_references()

    def unlink_references(self) -> None:
        """
        Unlinks references from all entities, relations, and cases within the current context.

        This method iterates through each entity, relation, and case stored in the `entities`, `relations`,
        and `cases` dictionaries respectively, invoking their `unlink_references()` methods to clear any references
        held by these objects. This operation is useful for breaking dependencies or preparing data for deletion
        or modification.
        """
        for _, entity in self.entities.items():
            entity.unlink_references()
        for _, relation in self.relations.items():
            relation.unlink_references()
        for _, case in self.cases.items():
            case.unlink_references()
