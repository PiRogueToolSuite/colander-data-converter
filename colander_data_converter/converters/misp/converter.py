from typing import Optional

from pymisp import AbstractMISP, MISPTag, MISPObject, MISPAttribute

from colander_data_converter.base.common import TlpPapLevel
from colander_data_converter.base.models import Observable, EntityTypes
from colander_data_converter.converters.misp.models import Mapping, EntityTypeMapping
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

    def convert_colander_object(self, colander_object: EntityTypes) -> Optional[AbstractMISP]:
        """
        Convert a Colander object to its corresponding MISP representation.

        This method performs the core conversion logic by:
        1. Looking up the appropriate mapping for the Colander object type
        2. Creating the corresponding MISP object (Attribute or Object)
        3. Mapping fields, literals, and attributes from Colander to MISP format

        Args:
            colander_object (EntityTypes): The Colander object to convert

        Returns:
            Optional[AbstractMISP]: The converted MISP object, or None if no mapping exists
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
            if target_field in ["category"]:
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

    def convert_observable(self, colander_object: Observable) -> Optional[AbstractMISP]:
        """
        Convert a Colander Observable to MISP format.

        This is a convenience method that delegates to convert_colander_object()
        for Observable-specific conversions.

        Args:
            colander_object (Observable): The Colander Observable to convert

        Returns:
            Optional[AbstractMISP]: The converted MISP object, or None if conversion fails
        """
        return self.convert_colander_object(colander_object)
