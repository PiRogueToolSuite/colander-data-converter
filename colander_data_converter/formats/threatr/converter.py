from datetime import datetime, UTC
from typing import Union, List, get_args
from uuid import uuid4, UUID

from colander_data_converter.base.common import ObjectReference
from colander_data_converter.base.models import (
    ColanderFeed,
    EntityTypes,
    EntityRelation as ColanderEntityRelation,
    Entity as ColanderEntity,
    Event,
)
from colander_data_converter.base.utils import BaseModelMerger
from colander_data_converter.formats.threatr.mapping import ThreatrMapper
from colander_data_converter.formats.threatr.models import (
    ThreatrFeed,
    Entity as ThreatrEntity,
    Event as ThreatrEvent,
    EntityRelation as ThreatrEntityRelation,
)


class ColanderToThreatrMapper(ThreatrMapper):
    def _get_relation_name_from_field(self, source_type: str, target_type: str, field_name: str) -> str:
        relation_name = field_name.replace("_", " ")
        for mapping in self.mapping_loader.mapping_data:
            if (
                mapping["source_type"] == source_type
                and mapping["target_type"] == target_type
                and field_name in mapping["fields"]
            ):
                relation_name = mapping["fields"][field_name]
        return relation_name

    def convert(self, colander_feed: ColanderFeed, root_entity: Union[UUID, EntityTypes]) -> ThreatrFeed:
        """
        Convert a Colander data model to a Threatr data model.

        Args:
            colander_feed: The Colander feed to convert
            root_entity: The root entity ID or entity object to use as the root of the Threatr feed

        Returns:
            A ThreatrFeed object containing the converted data
        """
        # Get the root entity object if an ID was provided
        root_entity_obj = None
        if isinstance(root_entity, UUID):
            root_entity_obj = colander_feed.entities.get(str(root_entity))
            if not root_entity_obj:
                raise ValueError(f"Root entity with ID {root_entity} not found in feed")
        else:
            root_entity_obj = root_entity

        # Convert the root entity to a Threatr entity
        threatr_root_entity = self._convert_entity(root_entity_obj)
        threatr_events = []

        # Convert all entities
        threatr_entities = [threatr_root_entity]
        for entity_id, entity in colander_feed.entities.items():
            # Skip the root entity as it's already included
            if str(entity.id) == str(root_entity_obj.id):
                continue
            threatr_entity = self._convert_entity(entity)
            if isinstance(threatr_entity, ThreatrEvent):
                threatr_events.append(threatr_entity)
            else:
                threatr_entities.append(threatr_entity)

        # Convert all relations
        threatr_relations = []
        for relation_id, relation in colander_feed.relations.items():
            threatr_relation = self._convert_relation(relation)
            threatr_relations.append(threatr_relation)

        # Convert reference fields to relations
        reference_relations = self._extract_reference_relations(colander_feed)
        threatr_relations.extend(reference_relations)

        # Create and return the Threatr feed
        return ThreatrFeed(
            root_entity=threatr_root_entity,
            entities=threatr_entities,
            relations=threatr_relations,
            events=threatr_events,
        )

    def _convert_entity(self, entity: ColanderEntity) -> ThreatrEntity | ThreatrEvent:
        """
        Convert a Colander entity to a Threatr entity.

        Args:
            entity: The Colander entity to convert

        Returns:
            A Threatr entity
        """
        # Create a base entity with common fields
        model_class = ThreatrEntity
        if isinstance(entity, Event):
            model_class = ThreatrEvent
        threatr_entity = model_class(
            id=entity.id,
            created_at=getattr(entity, "created_at", datetime.now(UTC)),
            updated_at=getattr(entity, "updated_at", datetime.now(UTC)),
            name=entity.name,
            type=entity.type,
            super_type=entity.super_type,
            attributes={},
        )

        bm = BaseModelMerger()
        bm.merge(entity, threatr_entity)

        return threatr_entity

    def _convert_relation(self, relation: ColanderEntityRelation) -> ThreatrEntityRelation:
        """
        Convert a Colander entity relation to a Threatr entity relation.

        Args:
            relation: The Colander entity relation to convert

        Returns:
            A Threatr entity relation
        """
        # Create a base relation with common fields
        threatr_relation = ThreatrEntityRelation(
            id=relation.id,
            created_at=getattr(relation, "created_at", datetime.now(UTC)),
            updated_at=getattr(relation, "updated_at", datetime.now(UTC)),
            name=relation.name,
            description=getattr(relation, "description", None),
            obj_from=relation.obj_from if isinstance(relation.obj_from, UUID) else relation.obj_from.id,
            obj_to=relation.obj_to if isinstance(relation.obj_to, UUID) else relation.obj_to.id,
            attributes={},
        )

        bm = BaseModelMerger()
        bm.merge(relation, threatr_relation)

        return threatr_relation

    def _extract_reference_relations(self, colander_feed: ColanderFeed) -> List[ThreatrEntityRelation]:
        """
        Extract reference fields from Colander entities and convert them to Threatr relations.

        Args:
            colander_feed: The Colander feed containing entities

        Returns:
            A list of Threatr entity relations
        """
        relations = []

        for entity_id, entity in colander_feed.entities.items():
            entity_type_name = type(entity).__name__.lower()

            for field_name, field_info in entity.__class__.model_fields.items():
                field_annotation = get_args(field_info.annotation)
                field_value = getattr(entity, field_name, None)

                if not field_value or not field_annotation:
                    continue

                # Handle single ObjectReference
                if ObjectReference in field_annotation:
                    relation = self._create_relation_from_reference(
                        entity, field_name, field_value, entity_type_name, colander_feed, is_list=False
                    )
                    if relation:
                        relations.append(relation)

                # Handle List[ObjectReference]
                elif List[ObjectReference] in field_annotation:
                    for object_reference in field_value:
                        relation = self._create_relation_from_reference(
                            entity, field_name, object_reference, entity_type_name, colander_feed, is_list=True
                        )
                        if relation:
                            relations.append(relation)

        return relations

    def _create_relation_from_reference(
        self, entity, field_name, reference_value, entity_type_name, colander_feed, is_list=False
    ):
        """Helper method to create a relation from a reference field."""
        target_id = reference_value if isinstance(reference_value, UUID) else reference_value.id
        target_entity = colander_feed.entities.get(str(target_id))

        if not target_entity:
            return None

        target_entity_type_name = type(target_entity).__name__.lower()

        # Get relation name based on whether it's a list or single reference
        if is_list:
            relation_name = self._get_relation_name_from_field(entity_type_name, target_entity_type_name, field_name)
        else:
            relation_name = field_name.replace("_", " ")

        return ThreatrEntityRelation(
            id=uuid4(),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            name=relation_name,
            description=f"Relation extracted from {entity_type_name}.{field_name} reference to {target_entity_type_name}",
            obj_from=entity.id,
            obj_to=target_entity.id,
            attributes={},
        )


class ThreatrToColanderMapper:
    def convert(self, threatr_feed: ThreatrFeed) -> ColanderFeed:
        pass
