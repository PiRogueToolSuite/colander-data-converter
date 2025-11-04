import enum
from typing import get_args, List, Any, Optional, Dict

from pydantic import BaseModel, UUID4

from colander_data_converter.base.common import ObjectReference
from colander_data_converter.base.models import ColanderFeed, Entity, EntityRelation


class MergingStrategy(str, enum.Enum):
    PRESERVE = "preserve"
    OVERWRITE = "overwrite"


class BaseModelMerger:
    """
    A utility class for merging :py:class:`pydantic.BaseModel` instances with configurable strategies.

    This class provides functionality to merge fields from a source BaseModel into a
    destination BaseModel, handling both regular model fields and extra attributes.
    Fields containing `ObjectReference` types are automatically
    excluded from merging and reported as unprocessed.

    The merger supports two strategies:

    - ``PRESERVE``: Only merge fields if the destination field is empty or `None`
    - ``OVERWRITE``: Always merge fields from source to destination

    Fields are merged based on type compatibility and field constraints. Extra
    attributes are automatically converted to strings when stored in the attribute
    dictionary (if supported by the destination model).

    Example:
        >>> from pydantic import BaseModel
        >>> class SourceModel(BaseModel):
        ...     name: str
        ...     age: int
        ...     attributes: dict = {}
        >>> class DestinationModel(BaseModel):
        ...     name: str
        ...     age: int
        ...     city: str = "Unknown"
        ...     attributes: dict = {}
        >>> source = SourceModel(name="Alice", age=30)
        >>> destination = DestinationModel(name="Bob", age=25)
        >>> merger = BaseModelMerger(strategy=MergingStrategy.OVERWRITE)
        >>> unprocessed = merger.merge(source, destination)
        >>> print(destination.name)
        Alice
        >>> print(destination.age)
        30
        >>> print(destination.city)
        Unknown

    Note:
        - Fields with ``ObjectReference`` types are never merged and are reported as unprocessed
        - Frozen fields cannot be modified and will be reported as unprocessed
        - Complex types (list, dict, tuple, set) in extra attributes are not supported
        - Extra attributes are converted to strings when stored
    """

    def __init__(self, strategy: MergingStrategy = MergingStrategy.OVERWRITE):
        """Initialize the ``BaseModelMerger`` with a merging strategy.

        Args:
            strategy: The strategy to use when merging fields.
        """
        self.strategy = strategy

    def merge_field(
        self, destination: BaseModel, field_name: str, field_value: Any, ignored_fields: Optional[List[str]] = None
    ) -> bool:
        """Merge a single field from source to destination model.

        This method handles the logic for merging individual fields, including
        type checking, field existence validation, and attribute handling. It
        processes both regular model fields and extra attributes based on the
        destination model's capabilities and field constraints.

        Note:
            The method follows these rules:

            - Skips fields listed in ignored_fields
            - Skips empty/None field values
            - For fields not in the destination model schema: stores as string in
              attributes dict (if supported) unless the value is a complex type
            - For schema fields: merges only if type-compatible, not frozen, not
              containing ObjectReference, and destination is empty (``PRESERVE``) or
              strategy is ``OVERWRITE``

        Args:
            destination: The target model to merge into.
            field_name: The name of the field to merge.
            field_value: The value to merge from the source.
            ignored_fields: List of field names to skip during merging.

        Returns:
            True if the field was processed (successfully merged or handled),
            False if the field could not be processed
        """
        field_processed = False
        if not field_value:
            return field_processed
        if not ignored_fields:
            ignored_fields = []
        extra_attributes_supported = hasattr(destination, "attributes")
        source_field_value = field_value
        source_field_value_type = type(field_value)
        if field_name in ignored_fields:
            return field_processed
        # Append in extra attribute dict if supported
        if (
            field_name not in destination.__class__.model_fields
            and extra_attributes_supported
            and source_field_value_type not in [list, dict, tuple, set, ObjectReference]
            and not isinstance(source_field_value, BaseModel)
        ):
            destination.attributes[field_name] = str(source_field_value)
            field_processed = True
        elif field_name in destination.__class__.model_fields:
            field_info = destination.__class__.model_fields[field_name]
            annotation_args = get_args(field_info.annotation) or []  # type: ignore[var-annotated]
            if (
                ObjectReference not in annotation_args
                and List[ObjectReference] not in annotation_args
                and not field_info.frozen
                and (not getattr(destination, field_name, None) or self.strategy == MergingStrategy.OVERWRITE)
                and (source_field_value_type is field_info.annotation or source_field_value_type in annotation_args)
            ):
                setattr(destination, field_name, source_field_value)
                field_processed = True
        return field_processed

    def merge(self, source: BaseModel, destination: BaseModel, ignored_fields: Optional[List[str]] = None) -> List[str]:
        """Merge all compatible fields from the source object into the destination object.

        This method iterates through all fields in the source object and attempts
        to merge them into the destination object. It handles both regular object
        fields and extra attributes dictionary if supported.

        Args:
            source: The source model to merge from
            destination: The destination model to merge to
            ignored_fields: List of field names to skip during merging

        Returns:
            A list of field names that could not be processed during
            the merge operation. Fields containing ObjectReference types
            are automatically added to this list.
        """
        unprocessed_fields = []
        source_attributes = getattr(source, "attributes", None)
        destination_attributes = getattr(destination, "attributes", None)

        if destination_attributes is None and hasattr(destination, "attributes"):
            destination.attributes = {}

        # Merge model fields
        for field_name, field_info in source.__class__.model_fields.items():
            source_field_value = getattr(source, field_name, None)
            if ObjectReference in get_args(field_info.annotation):
                unprocessed_fields.append(field_name)
            elif not self.merge_field(destination, field_name, source_field_value, ignored_fields):
                unprocessed_fields.append(field_name)

        # Merge extra attributes
        if source_attributes:
            for name, value in source_attributes.items():
                if not self.merge_field(destination, name, value):
                    unprocessed_fields.append(f"attributes.{name}")

        return unprocessed_fields


class FeedMerger:
    def __init__(self, source_feed: ColanderFeed, destination_feed: ColanderFeed):
        self.source_feed = source_feed
        self.destination_feed = destination_feed
        self.id_rewrite: Dict[UUID4, UUID4] = {}  # source, destination
        self.merging_candidates: Dict[Entity, Entity] = {}  # source, destination
        self.added_entities: List[Entity] = []  # source added to the destination feed
        self.merged_entities: Dict[Entity, Entity] = {}  # source, destination

    def merge(self, delete_unlinked: bool = False, aggressive: bool = False):
        """
        Merge the source feed into the destination feed.
        This method performs a comprehensive merge operation between two ColanderFeeds,
        handling entity merging, relation updates, and immutable relation management.
        The merge process follows these main steps:

        1. Identify merging candidates based on entity similarity
        2. Merge compatible entities or add new ones to the destination feed
        3. Update immutable relation references after merging
        4. Copy non-immutable relations from source to destination

        Args:
            delete_unlinked: If True, delete relations involving missing entities
            aggressive: If True, temporarily breaks and rebuilds immutable relations
                       to allow more flexible merging. Use with caution as this may
                       affect data integrity during the merge process.
        """
        model_merger = BaseModelMerger(strategy=MergingStrategy.PRESERVE)

        if aggressive:
            self.source_feed.break_immutable_relations()
            self.destination_feed.break_immutable_relations()

        # Identify merging candidates or add missing source entities to the destination feed
        for _, source_entity in self.source_feed.entities.items():
            destination_candidates = self.destination_feed.get_entities_similar_to(source_entity)
            # Multiple or no candidates found or multiple immutable relations, add to the destination feed
            if len(destination_candidates) != 1 or len(source_entity.get_immutable_relations()) > 0:
                self.destination_feed.entities[str(source_entity.id)] = source_entity
                self.id_rewrite[source_entity.id] = source_entity.id
                self.added_entities.append(source_entity)
            else:
                # Only one candidate found
                _, destination_candidate = destination_candidates.popitem()
                # Candidate has no immutable relations, merge
                if len(source_entity.get_immutable_relations()) == 0:
                    model_merger.merge(source_entity, destination_candidate)
                    destination_candidate.touch()
                    self.id_rewrite[source_entity.id] = destination_candidate.id
                    self.merged_entities[source_entity] = destination_candidate
                else:
                    self.merging_candidates[source_entity] = destination_candidate

        for destination_entity in self.destination_feed.entities.values():
            for _, immutable_relation in destination_entity.get_immutable_relations().items():
                # The relation destination entity is missing: add it to the destination feed
                if (
                    immutable_relation.obj_to not in self.merged_entities
                    and immutable_relation.obj_to not in self.added_entities
                ):
                    self.destination_feed.entities[str(immutable_relation.obj_to.id)] = immutable_relation.obj_to
                    self.added_entities.append(immutable_relation.obj_to)
                # The relation obj_to has been merged: update the reference
                elif immutable_relation.obj_to in self.merged_entities:
                    original_obj_to = immutable_relation.obj_to
                    merged_obj_to = self.merged_entities[original_obj_to]
                    object_reference = getattr(destination_entity, immutable_relation.name)
                    if not object_reference:
                        continue
                    if isinstance(object_reference, list):
                        object_reference.remove(original_obj_to)
                        object_reference.append(merged_obj_to)
                    else:
                        setattr(destination_entity, immutable_relation.name, merged_obj_to)

        for _, source_relation in self.source_feed.relations.items():
            obj_from: Entity = self.merged_entities.get(source_relation.obj_from, source_relation.obj_from)
            obj_to: Entity = self.merged_entities.get(source_relation.obj_to, source_relation.obj_to)
            relation_exists = False
            for _, relation in self.destination_feed.get_outgoing_relations(obj_from, exclude_immutables=True).items():
                if relation.obj_to == obj_to and relation.name == source_relation.name:
                    relation_exists = True
            if not relation_exists:
                self.destination_feed.relations[str(source_relation.id)] = EntityRelation(
                    id=source_relation.id,
                    name=source_relation.name,
                    obj_from=obj_from,
                    obj_to=obj_to,
                )

        unlinked_relations: List[str] = []
        for _, relation in self.destination_feed.relations.items():
            obj_from = relation.obj_from
            obj_to = relation.obj_to
            if not self.destination_feed.contains(obj_from) or not self.destination_feed.contains(obj_to):
                unlinked_relations.append(str(relation.id))

        if delete_unlinked:
            for relation_id in unlinked_relations:
                self.destination_feed.relations.pop(relation_id)
        elif unlinked_relations:
            raise Exception(f"{len(unlinked_relations)} unlinked relation detected")

        if aggressive:
            self.source_feed.rebuild_immutable_relations()
            self.destination_feed.rebuild_immutable_relations()
