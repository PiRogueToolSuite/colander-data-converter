from datetime import datetime, UTC
from typing import Dict, Any, Optional, Union, List
from uuid import uuid4

from colander_data_converter.base.models import (
    Actor,
    Device,
    Artifact,
    Observable,
    Threat,
    Event,
    DetectionRule,
    DataFragment,
    EntityRelation,
    ColanderFeed,
    Repository,
    DeviceTypes,
    ArtifactTypes,
    ObservableTypes,
    ThreatTypes,
    CommonEntitySuperType,
    CommonEntitySuperTypes,
    ActorTypes,
)
from colander_data_converter.formats.stix2.mapping import Stix2MappingLoader
from colander_data_converter.formats.stix2.utils import (
    extract_uuid_from_stix2_id,
    get_nested_value,
    set_nested_value,
    extract_stix2_pattern_name,
)


class Stix2Mapper:
    """
    Base class for mapping between STIX2 and Colander data using the mapping file.
    """

    def __init__(self):
        """
        Initialize the mapper.
        """
        self.mapping_loader = Stix2MappingLoader()


class Stix2ToColanderMapper(Stix2Mapper):
    """
    Maps STIX2 data to Colander data using the mapping file.
    """

    def convert(self, stix2_data: Dict[str, Any]) -> ColanderFeed:
        """
        Convert STIX2 data to Colander data.

        Args:
            stix2_data (Dict[str, Any]): The STIX2 data to convert.

        Returns:
            ColanderFeed: The converted Colander data.
        """
        repository = Repository()

        # Keep track of processed STIX2 object IDs to handle duplicates
        processed_ids: Dict[str, str] = {}

        # Process STIX2 objects
        for stix2_object in stix2_data.get("objects", []):
            stix2_id = stix2_object.get("id", "")
            stix2_type = stix2_object.get("type", "")

            # Skip if this ID has already been processed with a different type
            if stix2_id in processed_ids and processed_ids[stix2_id] != stix2_type:
                # Generate a new UUID for this object to avoid overwriting
                stix2_object = stix2_object.copy()
                stix2_object["id"] = f"{stix2_type}--{uuid4()}"

            colander_entity = self.convert_stix2_object(stix2_object)
            if colander_entity:
                repository << colander_entity
                processed_ids[stix2_id] = stix2_type

        bundle_id = extract_uuid_from_stix2_id(stix2_data.get("id", ""))

        feed_data = {
            "id": bundle_id,
            "name": stix2_data.get("name", "STIX2 Feed"),
            "description": stix2_data.get("description", "Converted from STIX2"),
            "entities": repository.entities,
            "relations": repository.relations,
        }

        return ColanderFeed.model_validate(feed_data)

    def convert_stix2_object(
        self, stix2_object: Dict[str, Any]
    ) -> Optional[
        Union[Actor, Device, Artifact, Observable, Threat, Event, DetectionRule, DataFragment, EntityRelation]
    ]:
        """
        Convert a STIX2 object to a Colander entity.

        Args:
            stix2_object (Dict[str, Any]): The STIX2 object to convert.

        Returns:
            Optional[Union[Actor, Device, Artifact, Observable, Threat, Event, DetectionRule, DataFragment, EntityRelation]]:
                The converted Colander entity, or None if the object type is not supported.
        """
        stix2_type = stix2_object.get("type", "")

        # Get the Colander entity type for this STIX2 type
        entity_type, entity_subtype_candidates = self.mapping_loader.get_entity_type_for_stix2(stix2_type)

        if entity_type and entity_subtype_candidates:
            # Use the appropriate conversion method based on the entity type
            if entity_type == "actor":
                return self._convert_to_actor(stix2_object, entity_subtype_candidates)
            elif entity_type == "device":
                return self._convert_to_device(stix2_object, entity_subtype_candidates)
            elif entity_type == "artifact":
                return self._convert_to_artifact(stix2_object, entity_subtype_candidates)
            elif entity_type == "observable":
                return self._convert_to_observable(stix2_object, entity_subtype_candidates)
            elif entity_type == "threat":
                return self._convert_to_threat(stix2_object, entity_subtype_candidates)

        # Handle relationship objects
        if stix2_type == "relationship":
            return self._convert_to_relation(stix2_object)

        return None

    def _convert_to_entity(
        self,
        stix2_object: Dict[str, Any],
        model_class: type,
        colander_entity_type,
        default_name: str = "Unknown Entity",
    ) -> Any:
        """
        Converts a STIX2-compliant dictionary object to a specific entity model representation
        using the provided mapping and model class. This function extracts relevant fields,
        maps them to the target entity structure, and validates the final structure using the
        `model_class`.

        Parameters:
            stix2_object (Dict[str, Any]): The input dictionary adhering to the STIX2 format.
                It contains raw data that will be converted into the specific entity model.
            model_class (type): The target model class to which the STIX2 object will be
                converted. The model class must support a `model_validate` method for validation.
            colander_entity_type: The specific entity type that the converted object should
                adhere to. This is used for determining the final type of the entity.
            default_name (str): A default name to assign to the entity if the "name" field
                is not present in the provided STIX2 object. Default is "Unknown Entity".

        Returns:
            Any: The validated and converted entity object as specified by the `model_class`.

        Raises:
            ValueError: If the `colander_entity_type` parameter is invalid.
            Exception: If the `model_class.model_validate` method raises an error during
                validation of the final converted entity structure.
        """
        # Get the field mapping for the entity type
        colander_entity_super_type: CommonEntitySuperType = CommonEntitySuperTypes.by_short_name(model_class.__name__)
        field_mapping = self.mapping_loader.get_stix2_to_colander_field_mapping(model_class.__name__)

        if not colander_entity_type:
            raise ValueError("Invalid entity type")

        # Create the base entity data
        stix2_id = stix2_object.get("id", "")
        extracted_uuid = extract_uuid_from_stix2_id(stix2_id)
        entity_data = {
            "id": extracted_uuid,
            "name": stix2_object.get("name", default_name),
            "description": stix2_object.get("description", ""),
            "super_type": colander_entity_super_type,
            "type": colander_entity_type,
            "attributes": {},
        }

        # Apply the field mapping
        for stix2_field, colander_field in field_mapping.items():
            value = get_nested_value(stix2_object, stix2_field)
            if value is not None:
                if "." in colander_field:
                    # Handle nested fields
                    set_nested_value(entity_data, colander_field, value)
                else:
                    entity_data[colander_field] = value

        # Add any additional attributes from the STIX2 object
        _ignore = ["id", "type"]
        for key, value in stix2_object.items():
            if key not in field_mapping and key not in _ignore and isinstance(value, (str, int, float, bool)):
                entity_data["attributes"][key] = str(value)

        try:
            return model_class.model_validate(entity_data)
        except Exception as e:
            raise e

    def _get_actor_type(self, stix2_object: Dict[str, Any], subtype_candidates: Optional[List[str]]) -> str:
        """
        Determines the actor type based on a given STIX 2.0 object and a list of subtype candidates.

        This method analyzes the type of a STIX 2.0 object and checks for matches within
        its "threat_actor_types" field against a provided list of subtype candidates. If a subtype
        candidate matches, it returns the matching candidate. If no match is found, the method
        assigns a default type depending on the object's type and other conditions.

        Parameters:
            stix2_object (Dict[str, Any]): The STIX 2.0 object to evaluate.
            subtype_candidates (Optional[List[str]]): A list containing possible subtype options
                                                      for the STIX 2.0 object.

        Returns:
            str: The determined actor type based on the input object and subtype candidates.
        """
        default_type = ArtifactTypes.default.short_name.lower()
        if not subtype_candidates:
            return default_type

        if stix2_object.get("type", "") == "threat-actor":
            default_type = "threat_actor"
            for subtype_candidate in subtype_candidates:
                if subtype_candidate.lower() in stix2_object.get("threat_actor_types", []):
                    return subtype_candidate
            return default_type

        if len(subtype_candidates) == 1:
            return subtype_candidates[0]

        return default_type

    def _convert_to_actor(self, stix2_object: Dict[str, Any], subtype_candidates: Optional[List[str]]) -> Actor:
        """
        Convert a STIX2 object to a Colander Actor entity.

        Args:
            stix2_object (Dict[str, Any]): The STIX2 object to convert.
            subtype_candidates (Optional[List[str]]): A list providing
                potential subtype candidates to aid in subtype resolution during the
                conversion process.

        Returns:
            Actor: The converted Colander Actor entity.
        """

        _stix2_object = stix2_object.copy()
        if "threat_actor_types" in _stix2_object and _stix2_object["threat_actor_types"] is not None:
            _stix2_object["threat_actor_types"] = ",".join(_stix2_object["threat_actor_types"])

        _actor_type = self._get_actor_type(_stix2_object, subtype_candidates)

        return self._convert_to_entity(
            stix2_object=_stix2_object,
            model_class=Actor,
            colander_entity_type=ActorTypes.by_short_name(_actor_type),
        )

    def _get_device_type(self, stix2_object: Dict[str, Any], subtype_candidates: Optional[List[str]]) -> str:
        """
        Determines the device type from the provided STIX object and subtype candidates.

        This method analyzes a given STIX 2.0 object and a list of subtype candidates to determine
        the most appropriate device type. If there is exactly one subtype candidate, it is returned directly.
        Otherwise, the method checks if each candidate matches an infrastructure type in the STIX object.
        If no matching subtype is found, a default type of "generic" is returned.
        The method assumes that the `infrastructure_types` field in the STIX object contains the relevant
        information for matching.

        Args:
            stix2_object (Dict[str, Any]): A dictionary representing a STIX 2.0 object.
            subtype_candidates (Optional[List[str]]): A list of strings representing potential device subtypes.

        Returns:
            str: The determined device type, or "generic" if no suitable subtype is found.
        """
        default_type = DeviceTypes.default.short_name.lower()
        if not subtype_candidates:
            return default_type

        if len(subtype_candidates) == 1:
            return subtype_candidates[0]

        for subtype_candidate in subtype_candidates:
            if subtype_candidate.lower() in stix2_object.get("infrastructure_types", []):
                return subtype_candidate

        return default_type

    def _convert_to_device(self, stix2_object: Dict[str, Any], subtype_candidates: Optional[List[str]]) -> Device:
        """
        Convert a STIX2 object to a Colander Device entity.

        Args:
            stix2_object (Dict[str, Any]): The STIX2 object to convert.
            subtype_candidates (Optional[List[str]]): A list providing
                potential subtype candidates to aid in subtype resolution during the
                conversion process.

        Returns:
            Device: The converted Colander Device entity.
        """
        _stix2_object = stix2_object.copy()
        if "infrastructure_types" in _stix2_object and _stix2_object["infrastructure_types"] is not None:
            _stix2_object["infrastructure_types"] = ",".join(_stix2_object["infrastructure_types"])

        _device_type = self._get_device_type(_stix2_object, subtype_candidates)
        return self._convert_to_entity(
            stix2_object=_stix2_object,
            model_class=Device,
            colander_entity_type=DeviceTypes.by_short_name(_device_type),
        )

    def _get_artifact_type(self, stix2_object: Dict[str, Any], subtype_candidates: Optional[List[str]]) -> str:
        """
        Determines the artifact type for a given STIX 2 object based on its MIME type.

        This method evaluates the MIME type of a provided STIX 2 object and attempts to
        map it to a corresponding artifact type using a predefined mapping. If no
        specific artifact type mapping is found, a default type is returned.

        Args:
            stix2_object (Dict[str, Any]): A dictionary representing a STIX 2 object.
                It is expected to contain a "mime_type" key indicating the MIME type
                of the object. If "mime_type" is not present, "unspecified" is used
                as a default value.
            subtype_candidates (Optional[List[str]]): A list of possible subtype candidates
                for classification. This parameter is not currently utilized by the method.

        Returns:
            str: The resolved artifact type based on the MIME type of the STIX 2 object,
                or a default artifact type ("generic") if no specific mapping is available.
        """
        default_type = ArtifactTypes.default.short_name.lower()
        if not subtype_candidates:
            return default_type

        artifact_type = ArtifactTypes.by_mime_type(stix2_object.get("mime_type", "unspecified")).short_name

        return artifact_type or default_type

    def _convert_to_artifact(self, stix2_object: Dict[str, Any], subtype_candidates: Optional[List[str]]) -> Artifact:
        """
        Converts a given STIX 2.0 object into an Artifact entity.

        This function transforms a STIX 2.0 object into an internal Artifact entity
        representation. It uses the provided subtype candidates to assist with resolving
        the proper subtype for the Artifact entity when converting it.

        Args:
            stix2_object (Dict[str, Any]): The input STIX 2.0 object containing the data
                to transform into an Artifact.
            subtype_candidates (Optional[List[str]]): A list providing
                potential subtype candidates to aid in subtype resolution during the
                conversion process.

        Returns:
            Artifact: The resulting Artifact entity converted from the STIX 2.0 object.
        """
        _artifact_type = self._get_artifact_type(stix2_object, subtype_candidates)

        return self._convert_to_entity(
            stix2_object=stix2_object,
            model_class=Artifact,
            colander_entity_type=ArtifactTypes.by_short_name(_artifact_type),
        )

    def _get_observable_type(self, stix2_object: Dict[str, Any], subtype_candidates: Optional[List[str]]) -> str:
        default_type = ObservableTypes.default.short_name.lower()
        if not subtype_candidates:
            return default_type

        _pattern_name = extract_stix2_pattern_name(stix2_object.get("pattern", "")) or "unspecified"
        for _candidate in subtype_candidates:
            _mapping = self.mapping_loader.get_entity_subtype_mapping("observable", _candidate)
            if _pattern_name in _mapping["pattern"]:
                return _candidate

        # Return the generic subtype as it was not possible to narrow down the type selection
        return default_type

    def _convert_to_observable(
        self, stix2_object: Dict[str, Any], subtype_candidates: Optional[List[str]]
    ) -> Observable:
        """
        Convert a STIX2 object to a Colander Observable entity.

        Args:
            stix2_object (Dict[str, Any]): The STIX2 object to convert.
            subtype_candidates (Optional[List[str]]): A list providing
                potential subtype candidates to aid in subtype resolution during the
                conversion process.

        Returns:
            Observable: The converted Colander Observable entity.
        """
        _observable_type = self._get_observable_type(stix2_object, subtype_candidates)
        # Use the generic conversion method
        return self._convert_to_entity(
            stix2_object=stix2_object,
            model_class=Observable,
            colander_entity_type=ObservableTypes.by_short_name(_observable_type),
        )

    def _get_threat_type(self, stix2_object: Dict[str, Any], subtype_candidates: Optional[List[str]]) -> str:
        default_type = ThreatTypes.default.short_name.lower()
        if not subtype_candidates:
            return default_type

        for _candidate in subtype_candidates:
            if _candidate in stix2_object.get("malware_types", []):
                return _candidate

        # Return the generic subtype as it was not possible to narrow down the type selection
        return default_type

    def _convert_to_threat(self, stix2_object: Dict[str, Any], subtype_candidates: Optional[List[str]]) -> Threat:
        """
        Convert a STIX2 object to a Colander Threat entity.

        Args:
            stix2_object (Dict[str, Any]): The STIX2 object to convert.
            subtype_candidates (Optional[List[str]]): A list providing
                potential subtype candidates to aid in subtype resolution during the
                conversion process.

        Returns:
            Threat: The converted Colander Threat entity.
        """
        _threat_type = self._get_threat_type(stix2_object, subtype_candidates)
        # Use the generic conversion method
        return self._convert_to_entity(
            stix2_object=stix2_object,
            model_class=Threat,
            colander_entity_type=ThreatTypes.by_short_name(_threat_type),
        )

    def _convert_to_relation(self, stix2_object: Dict[str, Any]) -> Optional[EntityRelation]:
        """
        Convert a STIX2 relationship object to a Colander EntityRelation.

        Args:
            stix2_object (Dict[str, Any]): The STIX2 relationship object to convert.

        Returns:
            Optional[EntityRelation]: The converted Colander EntityRelation, or None if the relationship is not valid.
        """
        relationship_type = stix2_object.get("relationship_type", "")
        source_ref = stix2_object.get("source_ref", "")
        target_ref = stix2_object.get("target_ref", "")

        if not relationship_type or not source_ref or not target_ref:
            return None

        # Extract UUIDs from the references
        source_id = extract_uuid_from_stix2_id(source_ref)
        target_id = extract_uuid_from_stix2_id(target_ref)

        if not source_id or not target_id:
            return None

        # Create the relation data
        relation_data = {
            "id": extract_uuid_from_stix2_id(stix2_object.get("id", "")),
            "name": stix2_object.get("name", relationship_type),
            "description": stix2_object.get("description", ""),
            "created_at": stix2_object.get("created"),
            "updated_at": stix2_object.get("modified"),
            "obj_from": source_id,
            "obj_to": target_id,
            "attributes": {},
        }

        # Add any additional attributes from the STIX2 object
        for key, value in stix2_object.items():
            if key not in [
                "id",
                "type",
                "name",
                "description",
                "created",
                "modified",
                "source_ref",
                "target_ref",
            ] and isinstance(value, (str, int, float, bool)):
                relation_data["attributes"][key] = str(value)

        return EntityRelation.model_validate(relation_data)


class ColanderToStix2Mapper(Stix2Mapper):
    """
    Maps Colander data to STIX2 data using the mapping file.
    """

    def convert(self, colander_feed: ColanderFeed) -> Dict[str, Any]:
        """
        Convert Colander data to STIX2 data.

        Args:
            colander_feed (ColanderFeed): The Colander data to convert.

        Returns:
            Dict[str, Any]: The converted STIX2 data.
        """
        stix2_data = {"type": "bundle", "id": f"bundle--{uuid4()}", "spec_version": "2.1", "objects": []}

        # Convert entities
        if hasattr(colander_feed, "entities"):
            for entity_id, entity in colander_feed.entities.items():
                stix2_object = self.convert_colander_entity(entity)
                if stix2_object:
                    stix2_data["objects"].append(stix2_object)

                # Extract and convert ObjectReference relationships
                ref_relationships = self._extract_object_reference_relationships(entity)
                for rel in ref_relationships:
                    stix2_data["objects"].append(rel)

        # Convert relations
        if hasattr(colander_feed, "relations"):
            for relation_id, relation in colander_feed.relations.items():
                if isinstance(relation, EntityRelation):
                    stix2_object = self.convert_colander_relation(relation)
                    if stix2_object:
                        stix2_data["objects"].append(stix2_object)

        return stix2_data

    def convert_colander_entity(
        self, entity: Union[Actor, Device, Artifact, Observable, Threat, DetectionRule, DataFragment]
    ) -> Optional[Dict[str, Any]]:
        """
        Convert a Colander entity to a STIX2 object.

        Args:
            entity: The Colander entity to convert.

        Returns:
            Optional[Dict[str, Any]]: The converted STIX2 object, or None if the entity type is not supported.
        """
        if isinstance(entity, Actor):
            return self._convert_from_actor(entity)
        elif isinstance(entity, Device):
            return self._convert_from_device(entity)
        elif isinstance(entity, Artifact):
            return self._convert_from_artifact(entity)
        elif isinstance(entity, Observable):
            return self._convert_from_observable(entity)
        elif isinstance(entity, Threat):
            return self._convert_from_threat(entity)

        return None

    def convert_colander_relation(self, relation: EntityRelation) -> Optional[Dict[str, Any]]:
        """
        Convert a Colander EntityRelation to a STIX2 relationship object.

        Args:
            relation (EntityRelation): The Colander EntityRelation to convert.

        Returns:
            Optional[Dict[str, Any]]: The converted STIX2 relationship object, or None if the relation cannot be converted.
        """
        return self._convert_from_relation(relation)

    def _convert_from_entity(
        self, entity: Any, entity_type: str, additional_fields: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generic method to convert a Colander entity to a STIX2 object.

        Args:
            entity (Any): The Colander entity to convert.
            entity_type (str): The type of entity being converted (e.g., "actor", "device").
            additional_fields (Optional[Dict[str, Any]], optional): Additional fields to add to the STIX2 object.

        Returns:
            Dict[str, Any]: The converted STIX2 object.
        """
        # Get the STIX2 type for the entity
        stix2_type = self.mapping_loader.get_stix2_type_for_entity(entity_type)

        # Get the field mapping for the entity type
        field_mapping = self.mapping_loader.get_colander_to_stix2_field_mapping(entity_type)

        # Create the base STIX2 object
        stix2_object = {
            "type": stix2_type,
            "id": f"{stix2_type}--{entity.id}",
            "created": entity.created_at.isoformat()
            if hasattr(entity, "created_at") and entity.created_at
            else datetime.now(UTC).isoformat(),
            "modified": entity.updated_at.isoformat()
            if hasattr(entity, "updated_at") and entity.updated_at
            else datetime.now(UTC).isoformat(),
        }

        # Add any additional fields
        if additional_fields:
            stix2_object.update(additional_fields)

        # Apply the field mapping
        for colander_field, stix2_field in field_mapping.items():
            value = get_nested_value(entity.model_dump(), colander_field)
            if value is not None:
                if "." in stix2_field:
                    # Handle nested fields
                    set_nested_value(stix2_object, stix2_field, value)
                else:
                    stix2_object[stix2_field] = value

        # Add any additional attributes
        if hasattr(entity, "attributes") and entity.attributes:
            for key, value in entity.attributes.items():
                if key not in [field.split(".")[-1] for field in field_mapping.keys() if "." in field]:
                    stix2_object[key] = value

        return stix2_object

    def _convert_from_entity_by_type(
        self, entity: Any, entity_type: str, additional_fields: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generic method to convert a specific Colander entity type to a STIX2 object.

        Args:
            entity (Any): The Colander entity to convert.
            entity_type (str): The type of entity being converted (e.g., "actor", "device").
            additional_fields (Optional[Dict[str, Any]], optional): Additional fields to add to the STIX2 object.

        Returns:
            Dict[str, Any]: The converted STIX2 object.
        """
        return self._convert_from_entity(entity, entity_type, additional_fields)

    def _convert_from_actor(self, actor: Actor) -> Dict[str, Any]:
        """
        Convert a Colander Actor entity to a STIX2 object.

        Args:
            actor (Actor): The Colander Actor entity to convert.

        Returns:
            Dict[str, Any]: The converted STIX2 object.
        """
        return self._convert_from_entity_by_type(actor, "actor")

    def _convert_from_device(self, device: Device) -> Dict[str, Any]:
        """
        Convert a Colander Device entity to a STIX2 object.

        Args:
            device (Device): The Colander Device entity to convert.

        Returns:
            Dict[str, Any]: The converted STIX2 object.
        """
        return self._convert_from_entity_by_type(device, "device")

    def _convert_from_artifact(self, artifact: Artifact) -> Dict[str, Any]:
        """
        Convert a Colander Artifact entity to a STIX2 object.

        Args:
            artifact (Artifact): The Colander Artifact entity to convert.

        Returns:
            Dict[str, Any]: The converted STIX2 object.
        """
        return self._convert_from_entity_by_type(artifact, "artifact")

    def _generate_observable_pattern(self, observable: Observable) -> Dict[str, Any]:
        """
        Generate a pattern for an observable based on its type and value.

        Args:
            observable (Observable): The observable to generate a pattern for.

        Returns:
            Dict[str, Any]: A dictionary containing pattern and pattern_type.
        """
        pattern_fields = {}

        if hasattr(observable, "type") and observable.type:
            observable_type_short_name = observable.type.short_name.lower()
            try:
                pattern_template = self.mapping_loader.get_pattern_template(observable_type_short_name)
                pattern_type = self.mapping_loader.get_pattern_type(observable_type_short_name)

                if pattern_template and observable.name:
                    pattern_fields["pattern"] = pattern_template.format(value=observable.name)
                    pattern_fields["pattern_type"] = pattern_type
            except ValueError:
                # If the observable type is not found in the mapping, use a generic pattern
                pattern_fields["pattern"] = f"[unknown:value = '{observable.name}']"
                pattern_fields["pattern_type"] = "stix"

        return pattern_fields

    def _convert_from_observable(self, observable: Observable) -> Dict[str, Any]:
        """
        Convert a Colander Observable entity to a STIX2 object.

        Args:
            observable (Observable): The Colander Observable entity to convert.

        Returns:
            Dict[str, Any]: The converted STIX2 object.
        """
        # Generate pattern fields for the observable
        pattern_fields = self._generate_observable_pattern(observable)

        # Add indicator_types to the additional fields
        additional_fields = {"indicator_types": ["malicious-activity"]}
        additional_fields.update(pattern_fields)

        return self._convert_from_entity_by_type(observable, "observable", additional_fields)

    def _get_threat_malware_types(self, threat: Threat) -> Dict[str, Any]:
        """
        Get the malware types for a threat based on its type.

        Args:
            threat (Threat): The threat to get malware types for.

        Returns:
            Dict[str, Any]: A dictionary containing malware_types.
        """
        additional_fields = {}

        # Get the STIX2 type for threats
        stix2_type = self.mapping_loader.get_stix2_type_for_entity("threat")

        # Add malware_types if the type is malware
        if stix2_type == "malware" and hasattr(threat, "type") and threat.type:
            threat_type_short_name = threat.type.short_name.lower()
            try:
                malware_types = self.mapping_loader.get_malware_types_for_threat(threat_type_short_name)
                if malware_types:
                    additional_fields["malware_types"] = malware_types
                else:
                    additional_fields["malware_types"] = "unknown"
            except ValueError:
                additional_fields["malware_types"] = "unknown"

        return additional_fields

    def _convert_from_threat(self, threat: Threat) -> Dict[str, Any]:
        """
        Convert a Colander Threat entity to a STIX2 object.

        Args:
            threat (Threat): The Colander Threat entity to convert.

        Returns:
            Dict[str, Any]: The converted STIX2 object.
        """
        # Get additional fields for the threat
        additional_fields = self._get_threat_malware_types(threat)

        return self._convert_from_entity_by_type(threat, "threat", additional_fields)

    def _extract_object_reference_relationships(self, entity: Any) -> list:
        """
        Extract and create STIX2 relationship objects from ObjectReference attributes in a Colander entity.

        Args:
            entity (Any): The Colander entity to extract relationships from.

        Returns:
            list: A list of STIX2 relationship objects.
        """
        from typing import get_args
        from colander_data_converter.base.common import ObjectReference
        from uuid import UUID

        relationships = []

        # Get the entity's STIX2 type
        entity_type = None
        if isinstance(entity, Actor):
            entity_type = "actor"
        elif isinstance(entity, Device):
            entity_type = "device"
        elif isinstance(entity, Artifact):
            entity_type = "artifact"
        elif isinstance(entity, Observable):
            entity_type = "observable"
        elif isinstance(entity, Threat):
            entity_type = "threat"

        if not entity_type:
            return relationships

        stix2_type = self.mapping_loader.get_stix2_type_for_entity(entity_type)
        if not stix2_type:
            return relationships

        # Inspect the entity's fields for ObjectReference attributes
        for field_name, field_info in entity.__class__.model_fields.items():
            annotation_args = get_args(field_info.annotation)

            # Check if this field is an ObjectReference
            if ObjectReference in annotation_args:
                ref_value = getattr(entity, field_name, None)
                if ref_value and isinstance(ref_value, UUID):
                    # Create a relationship based on the field name
                    relationship_type = self._determine_relationship_type(field_name)

                    # Get the target entity type
                    target_entity = Repository() >> ref_value
                    if target_entity and not isinstance(target_entity, UUID):
                        target_type = self._get_entity_stix2_type(target_entity)
                        if target_type:
                            relationship = {
                                "type": "relationship",
                                "id": f"relationship--{uuid4()}",
                                "created": datetime.now(UTC).isoformat(),
                                "modified": datetime.now(UTC).isoformat(),
                                "relationship_type": relationship_type,
                                "source_ref": f"{stix2_type}--{entity.id}",
                                "target_ref": f"{target_type}--{ref_value}",
                            }
                            relationships.append(relationship)

            # Check if this field is a List[ObjectReference]
            elif any(
                hasattr(arg, "__origin__") and arg.__origin__ is list and ObjectReference in get_args(arg)
                for arg in annotation_args
            ):
                ref_values = getattr(entity, field_name, [])
                if ref_values and isinstance(ref_values, list):
                    relationship_type = self._determine_relationship_type(field_name)

                    for ref_value in ref_values:
                        if isinstance(ref_value, UUID):
                            # Get the target entity type
                            target_entity = Repository() >> ref_value
                            if target_entity and not isinstance(target_entity, UUID):
                                target_type = self._get_entity_stix2_type(target_entity)
                                if target_type:
                                    relationship = {
                                        "type": "relationship",
                                        "id": f"relationship--{uuid4()}",
                                        "created": datetime.now(UTC).isoformat(),
                                        "modified": datetime.now(UTC).isoformat(),
                                        "relationship_type": relationship_type,
                                        "source_ref": f"{stix2_type}--{entity.id}",
                                        "target_ref": f"{target_type}--{ref_value}",
                                    }
                                    relationships.append(relationship)

        return relationships

    def _determine_relationship_type(self, field_name: str) -> str:
        """
        Determine the STIX2 relationship type based on the field name.

        Args:
            field_name (str): The name of the field.

        Returns:
            str: The STIX2 relationship type.
        """
        return self.mapping_loader.get_field_relationship_type(field_name)

    def _get_entity_stix2_type(self, entity: Any) -> Optional[str]:
        """
        Get the STIX2 type for a Colander entity.

        Args:
            entity (Any): The Colander entity.

        Returns:
            Optional[str]: The STIX2 type, or None if not found.
        """
        if isinstance(entity, Actor):
            return self.mapping_loader.get_stix2_type_for_entity("actor")
        elif isinstance(entity, Device):
            return self.mapping_loader.get_stix2_type_for_entity("device")
        elif isinstance(entity, Artifact):
            return self.mapping_loader.get_stix2_type_for_entity("artifact")
        elif isinstance(entity, Observable):
            return self.mapping_loader.get_stix2_type_for_entity("observable")
        elif isinstance(entity, Threat):
            return self.mapping_loader.get_stix2_type_for_entity("threat")

        return None

    def _convert_from_relation(self, relation: EntityRelation) -> Optional[Dict[str, Any]]:
        """
        Convert a Colander EntityRelation to a STIX2 relationship object.

        Args:
            relation (EntityRelation): The Colander EntityRelation to convert.

        Returns:
            Optional[Dict[str, Any]]: The converted STIX2 relationship object, or None if the relation cannot be converted.
        """
        if not relation.obj_from or not relation.obj_to:
            return None

        # Create the base STIX2 relationship object
        stix2_object = {
            "type": "relationship",
            "id": f"relationship--{relation.id}",
            "created": relation.created_at.isoformat()
            if hasattr(relation, "created_at") and relation.created_at
            else datetime.now(UTC).isoformat(),
            "modified": relation.updated_at.isoformat()
            if hasattr(relation, "updated_at") and relation.updated_at
            else datetime.now(UTC).isoformat(),
            "source_ref": f"unknown--{relation.source_id}",  # ToDo: placeholder, will be updated if source entity is found
            "target_ref": f"unknown--{relation.target_id}",  # ToDo: placeholder, will be updated if target entity is found
        }

        # Add any additional attributes
        if hasattr(relation, "attributes") and relation.attributes:
            for key, value in relation.attributes.items():
                stix2_object[key] = value

        return stix2_object
