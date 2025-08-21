from typing import Optional, Union, List, Tuple

from pymisp import AbstractMISP, MISPTag, MISPObject, MISPAttribute, MISPEvent

from colander_data_converter.base.common import TlpPapLevel
from colander_data_converter.base.models import EntityTypes, Case, ColanderFeed, EntityRelation
from colander_data_converter.converters.misp.models import Mapping, EntityTypeMapping, TagStub
from colander_data_converter.converters.stix2.utils import get_nested_value


class MISPMapper:
    """
    Base mapper class for MISP conversions.

    Provides common functionality for mapping Colander data structures to MISP objects.
    """

    def __init__(self):
        self.mapping = Mapping()

    @staticmethod
    def tlp_level_to_tag(tlp_level: TlpPapLevel) -> MISPTag:
        """
        Convert a Colander TLP (Traffic Light Protocol) level to a MISP tag.

        Args:
            tlp_level (TlpPapLevel): The TLP level to convert

        Returns:
            MISPTag: A MISP tag object with the TLP level name
        """
        t = MISPTag()
        t.name = tlp_level.name
        return t


class ColanderToMISPMapper(MISPMapper):
    """
    Mapper class for converting Colander objects to MISP format.

    Handles the conversion of various Colander entity types (threats, actors, events,
    artifacts, etc.) to their corresponding MISP object representations using
    predefined mapping configurations.
    """

    def convert_colander_object(self, colander_object: EntityTypes) -> Optional[Union[AbstractMISP, TagStub]]:
        """
        Convert a Colander object to its corresponding MISP representation.

        This method performs the core conversion logic by:
        1. Looking up the appropriate mapping for the Colander object type
        2. Creating the corresponding MISP object (Attribute or Object)
        3. Mapping fields, literals, and attributes from Colander to MISP format

        Args:
            colander_object (EntityTypes): The Colander object to convert

        Returns:
            Optional[Union[AbstractMISP, TagStub]]: The converted MISP object, or None if no mapping exists
        """
        # Get the mapping configuration for this Colander object type
        entity_type_mapping: EntityTypeMapping = self.mapping.get_mapping(
            colander_object.get_super_type(), colander_object.type
        )

        if entity_type_mapping is None:
            return None

        # Determine the MISP model class and type to create
        misp_model, misp_type = entity_type_mapping.get_misp_model_class()

        # Create the appropriate MISP object based on the model type
        if issubclass(misp_model, MISPAttribute):
            misp_object: MISPAttribute = misp_model(strict=True)
            misp_object.type = misp_type
        elif issubclass(misp_model, MISPObject):
            misp_object: MISPObject = misp_model(name=misp_type, strict=True)
        elif issubclass(misp_model, MISPTag):
            tag_pattern = entity_type_mapping.colander_misp_mapping.get("literals", {}).get("name")
            return TagStub(tag_pattern.format(value=colander_object.name))
        else:
            return None

        # Set common MISP object properties
        # ToDo: add tag for TLP
        misp_object.uuid = str(colander_object.id)
        misp_object.first_seen = colander_object.created_at
        misp_object.last_seen = colander_object.updated_at

        # Convert Colander object to dictionary for nested field access
        colander_object_dict = colander_object.model_dump(mode="json")

        # Map direct field mappings from Colander to MISP object properties
        for source_field, target_field in entity_type_mapping.get_colander_misp_field_mapping():
            value = getattr(colander_object, source_field, None)
            if value is not None:
                setattr(misp_object, target_field, value)

        # Set constant/literal values on the MISP object
        for target_field, value in entity_type_mapping.get_colander_misp_literals_mapping():
            if target_field in ["category", "comment"]:
                setattr(misp_object, target_field, value)
            else:
                misp_object.add_attribute(target_field, value=value)

        # Map Colander fields to MISP object attributes
        for source_field, target_field in entity_type_mapping.get_colander_misp_attributes_mapping():
            if "." in source_field:
                # Handle nested field access using dot notation
                value = get_nested_value(colander_object_dict, source_field)
                if value is not None:
                    misp_object.add_attribute(target_field, value=value)
            else:
                # Handle direct field access
                value = getattr(colander_object, source_field, None)
                if value is not None:
                    misp_object.add_attribute(target_field, value=value)

        return misp_object

    @staticmethod
    def get_element_from_event(
        event: MISPEvent, uuid: str, types: List[str]
    ) -> Tuple[Optional[Union[MISPObject, MISPAttribute]], Optional[str]]:
        if "object" in types:
            for obj in event.objects:
                if hasattr(obj, "uuid") and obj.uuid == uuid:
                    return obj, "Object"
        if "attribute" in types:
            for obj in event.attributes:
                if hasattr(obj, "uuid") and obj.uuid == uuid:
                    return obj, "Attribute"
        return None, None

    def convert_immutable_relations(self, event: MISPEvent, colander_object: EntityTypes):
        super_type = colander_object.super_type
        # Create relationships based on immutable relations
        for _, relation in colander_object.get_immutable_relations().items():
            reference_name = relation.name
            relation_mapping = self.mapping.get_relation_mapping(super_type, reference_name)

            if not relation_mapping:
                continue

            reverse = relation_mapping.get("reverse", False)
            source_id = str(relation.obj_from.id) if not reverse else str(relation.obj_to.id)
            target_id = str(relation.obj_to.id) if not reverse else str(relation.obj_from.id)
            relation_name = relation_mapping.get("name", reference_name.replace("_", "-"))

            # Tags only on MISPAttribute or MISPEvent
            if relation_mapping.get("use_tag", False):
                source_object, _ = self.get_element_from_event(event, source_id, types=["attribute"])
                if reverse:
                    tag = self.convert_colander_object(relation.obj_from)
                else:
                    tag = self.convert_colander_object(relation.obj_to)
                if source_object and isinstance(tag, TagStub):
                    event.add_attribute_tag(tag, source_id)
            # Regular immutable relation between a MISPObject and another MISPObject or MISPAttribute
            else:
                source_object, _ = self.get_element_from_event(event, source_id, types=["object"])
                target_object, type_name = self.get_element_from_event(event, target_id, types=["object", "attribute"])
                if source_object and target_object:
                    source_object.add_relationship(type_name, target_id, relation_name)

    def convert_relations(self, event: MISPEvent, colander_relations: List[EntityRelation]):
        for relation in colander_relations:
            source_id = str(relation.obj_from.id)
            target_id = str(relation.obj_to.id)
            source_object, _ = self.get_element_from_event(event, source_id, types=["object"])
            target_object, type_name = self.get_element_from_event(event, target_id, types=["object", "attribute"])
            if source_object and target_object:
                source_object.add_relationship(type_name, target_id, relation.name)

    def convert_case(self, case: Case, feed: ColanderFeed) -> Tuple[Optional[MISPEvent], List[EntityTypes]]:
        skipped = []
        misp_event = MISPEvent()
        misp_event.uuid = str(case.id)
        misp_event.info = case.description
        misp_event.date = case.created_at
        for entity in feed.entities.values():
            misp_object = self.convert_colander_object(entity)
            if not misp_object:
                skipped.append(entity)
                continue
            if isinstance(misp_object, MISPAttribute):
                misp_event.add_attribute(**misp_object.to_dict())
            elif isinstance(misp_object, MISPObject):
                misp_event.add_object(misp_object)

        # Immutable relations
        for entity in feed.entities.values():
            self.convert_immutable_relations(misp_event, entity)

        # Regular relations
        for entity in feed.entities.values():
            self.convert_relations(misp_event, list(feed.get_outgoing_relations(entity).values()))

        return misp_event, skipped
