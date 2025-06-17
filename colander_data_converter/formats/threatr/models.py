from datetime import datetime, UTC
from typing import Optional, Dict, Any, List, Union, get_args
from uuid import uuid4, UUID

from pydantic import Field, BaseModel, model_validator
from pydantic.types import UUID4, PositiveInt

from colander_data_converter.base.common import (
    TlpPapLevel,
    ObjectReference,
    Singleton,
)
from colander_data_converter.base.models import CommonEntityType, CommonEntitySuperType


class ThreatrRepository(object, metaclass=Singleton):
    """
    Singleton repository for managing and storing Entity, Event, and EntityRelation objects.

    This class provides centralized storage and reference management for all model instances,
    supporting insertion, lookup, and reference resolution/unlinking.
    """

    entities: Dict[str, "Entity"]
    events: Dict[str, "Event"]
    relations: Dict[str, "EntityRelation"]

    def __init__(self):
        """
        Initializes the repository with empty dictionaries for events, entities, and relations.
        """
        self.events = {}
        self.entities = {}
        self.relations = {}

    def __lshift__(self, other: Union["Entity", "Event", "EntityRelation"]) -> None:
        """
        Inserts an object (Entity, EntityRelation, or Event) into the appropriate repository dictionary.

        Args:
            other (Union[Entity, Event, EntityRelation]): The object to insert.
        """
        if isinstance(other, Entity):
            self.entities[str(other.id)] = other
        elif isinstance(other, EntityRelation):
            self.relations[str(other.id)] = other
        elif isinstance(other, Event):
            self.events[str(other.id)] = other

    def __rshift__(self, other: str | UUID4) -> Union["Entity", "Event", "EntityRelation"]:
        """
        Retrieves an object by its string or UUID identifier from entities, relations, or events.

        Args:
            other (str | UUID4): The identifier to look up.

        Returns:
            Union[Entity, Event, EntityRelation]: The found object or the identifier if not found.
        """
        _other = str(other)
        if _other in self.entities:
            return self.entities[_other]
        elif _other in self.relations:
            return self.relations[_other]
        elif _other in self.events:
            return self.events[_other]
        return other

    def unlink_references(self):
        """
        Unlinks all object references in relations and events by replacing them with UUIDs.
        """
        for _, relation in self.relations.items():
            relation.unlink_references()
        for _, event in self.events.items():
            event.unlink_references()

    def resolve_references(self):
        """
        Resolves all UUID references in relations and events to their corresponding objects.
        """
        for _, relation in self.relations.items():
            relation.resolve_references()
        for _, event in self.events.items():
            event.resolve_references()


class ThreatrType(BaseModel):
    """
    Base model for Threatr objects, providing repository registration and reference management.

    This class ensures that all subclasses are registered in the ThreatrRepository and provides
    methods to unlink and resolve object references for serialization and deserialization.
    """

    model_config = {
        "str_strip_whitespace": True,
        "arbitrary_types_allowed": True,
    }

    def model_post_init(self, __context):
        """
        Executes post-initialization logic for the model, ensuring the repository
        registers the current subclass instance.

        Args:
            __context (Any): Additional context provided for post-initialization handling.
        """
        _ = ThreatrRepository()
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

        Raises:
            AttributeError: If the class instance does not have the expected field or attribute.
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

    def resolve_references(self):
        """
        Resolves references for the fields in the object's model. Fields annotated with `ObjectReference` or
        `List[ObjectReference]` are processed to fetch and replace their UUID references with respective
        entities using the `ThreatrRepository`.

        This method updates the object in-place.
        """
        for field, info in self.__class__.model_fields.items():
            annotation_args = get_args(info.annotation)
            if ObjectReference in annotation_args:
                ref = self.__getattribute__(field)
                if type(ref) is UUID:
                    x = ThreatrRepository() >> ref
                    self.__setattr__(field, x)
            elif List[ObjectReference] in annotation_args:
                refs = self.__getattribute__(field)
                object_references: List[Entity] = []
                _update = False
                for ref in refs:
                    if type(ref) is UUID:
                        x = ThreatrRepository() >> ref
                        object_references.append(x)
                        _update = True
                if _update:
                    self.__setattr__(field, object_references)


class Entity(ThreatrType):
    """
    Represents an entity in the Threatr data model.
    """

    id: UUID4 = Field(frozen=True, default_factory=lambda: uuid4())
    """The unique identifier for the entity."""

    created_at: datetime | None = Field(default=None, frozen=True)
    """The timestamp when the entity was created."""

    updated_at: datetime | None = Field(default=None, frozen=True)
    """The timestamp when the entity was last updated."""

    name: str = Field(..., min_length=1, max_length=512)
    """The name of the entity."""

    type: CommonEntityType
    """The type of the entity such as IP v4 address."""

    super_type: CommonEntitySuperType
    """The super type of the entity such as observable or event."""

    description: str | None = None
    """A description of the entity."""

    pap: TlpPapLevel = TlpPapLevel.WHITE
    """The PAP (Permissible Actions Protocol) level for the entity."""

    source_url: str | None = None
    """Optional source URL for the entity."""

    tlp: TlpPapLevel = TlpPapLevel.WHITE
    """The TLP (Traffic Light Protocol) level for the entity."""

    attributes: Optional[Dict[str, str | None]] = None
    """Optional dictionary of additional attributes."""


class EntityRelation(ThreatrType):
    """
    Represents a relation between two entities in the Threatr data model.
    """

    id: UUID4 = Field(frozen=True, default_factory=lambda: uuid4())
    """The unique identifier for the entity relation."""

    created_at: datetime | None = Field(default=None, frozen=True)
    """The timestamp when the entity relation was created."""

    updated_at: datetime | None = Field(default=None)
    """The timestamp when the entity relation was last updated."""

    name: str = Field(..., min_length=1, max_length=512)
    """The name of the entity relation."""

    description: str | None = None
    """A description of the entity."""

    attributes: Optional[Dict[str, str | None]] = None
    """Optional dictionary of additional attributes for the relation."""

    obj_from: Entity | ObjectReference = Field(...)
    """The source entity or reference in the relation."""

    obj_to: Entity | ObjectReference = Field(...)
    """The target entity or reference in the relation."""


class Event(ThreatrType):
    """
    Represents an event in the Threatr data model.
    """

    id: UUID4 = Field(frozen=True, default_factory=lambda: uuid4())
    """The unique identifier for the entity relation."""

    created_at: datetime | None = Field(default=None, frozen=True)
    """The timestamp when the entity relation was created."""

    updated_at: datetime | None = Field(default=None)
    """The timestamp when the entity relation was last updated."""

    name: str = Field(..., min_length=1, max_length=512)
    """The name of the entity relation."""

    description: str | None = None
    """A description of the entity."""

    attributes: Optional[Dict[str, str | None]] = None
    """Optional dictionary of additional attributes for the relation."""

    first_seen: datetime = datetime.now(UTC)
    """The timestamp when the event was first observed."""

    last_seen: datetime = datetime.now(UTC)
    """The timestamp when the event was last observed."""

    count: PositiveInt = 1
    """The number of times this event was observed."""

    involved_entity: Optional[Entity] | Optional[ObjectReference] = None
    """List of entities or references involved in this event."""

    @model_validator(mode="after")
    def _check_dates(self) -> Any:
        """
        Validates that the first_seen date is before the last_seen date.

        Raises:
            ValueError: If first_seen is after last_seen.
        """
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must be before last_seen")
        return self


class ThreatrFeed(ThreatrType):
    """
    Represents a feed of Threatr data, including entities, relations, and events.
    """

    root_entity: Entity
    """The root entity of the feed. It corresponds to the entity that has been requested."""

    entities: Optional[List[Entity]] = []
    """List of entity objects."""

    relations: Optional[List[EntityRelation]] = []
    """List of entity relations objects."""

    events: Optional[List[Event]] = []
    """List of events objects."""

    @staticmethod
    def load(
        raw_object: Dict[str, Union[Entity, Event, EntityRelation]],
    ) -> "ThreatrFeed":
        """
        Loads a ThreatrFeed from a raw object dictionary, resolving references.

        Args:
            raw_object (Dict[str, Union[Entity, Event, EntityRelation]]): The raw data to validate and load.

        Returns:
            ThreatrFeed: The loaded and reference-resolved feed.
        """
        feed = ThreatrFeed.model_validate(raw_object)
        feed.resolve_references()
        return feed

    def resolve_references(self):
        """
        Resolves references within entities, relations, and events.

        Iterates over each entity, relation, and case within the respective collections, calling their
        `resolve_references` method to update them with any referenced data. This helps in synchronizing
        internal state with external dependencies or updates.
        """
        for entity in self.entities:
            entity.resolve_references()
        for event in self.events:
            event.resolve_references()
        for relation in self.relations:
            relation.resolve_references()

    def unlink_references(self) -> None:
        """
        Unlinks references from all entities, relations, and events within the current context.

        This method iterates through each entity, relation, and case stored in the `entities`, `relations`,
        and `cases` dictionaries respectively, invoking their `unlink_references()` methods to clear any references
        held by these objects. This operation is useful for breaking dependencies or preparing data for deletion
        or modification.
        """
        for entity in self.entities:
            entity.unlink_references()
        for event in self.events:
            event.unlink_references()
        for relation in self.relations:
            relation.unlink_references()
