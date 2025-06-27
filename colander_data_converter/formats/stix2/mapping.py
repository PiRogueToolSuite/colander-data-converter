import json
from importlib import resources
from typing import Dict, Any, List, Optional, Set, Tuple


resource_package = __name__


class Stix2MappingLoader:
    """
    Loads and provides access to the STIX2 to Colander mapping data.
    """

    def __init__(self):
        """
        Initialize the mapping loader.
        """
        # Load the mapping data
        self.mapping_data = self._load_mapping_data()

    @staticmethod
    def _load_mapping_data() -> Dict[str, Any]:
        """
        Load the mapping data from the JSON file.

        Returns:
            Dict[str, Any]: The mapping data.
        """
        json_file = resources.files(resource_package).joinpath("data").joinpath("stix2_colander_mapping.json")
        try:
            with json_file.open() as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load mapping data: {e}")

    def get_entity_type_mapping(self, entity_type: str) -> Dict[str, Any]:
        """
        Get the mapping data for a specific Colander entity type.

        Args:
            entity_type (str): The entity type (e.g., "actor", "device").

        Returns:
            Dict[str, Any]: The mapping data for the entity type.
        """
        _entity_type = entity_type.lower()
        if _entity_type not in self.mapping_data:
            raise ValueError(f"Unknown entity type: {_entity_type}")
        return self.mapping_data[_entity_type]

    def get_entity_subtype_mapping(self, entity_type: str, entity_subtype: str) -> Dict[str, Any]:
        """
        Get the mapping data for a specific Colander entity type.

        Args:
            entity_type (str): The entity type (e.g., "actor", "device").
            entity_subtype (str): The Colander entity subtype (e.g. "ipv4").

        Returns:
            Dict[str, Any]: The mapping data for the entity type.
        """
        _entity_type = entity_type.lower()
        _entity_subtype = entity_subtype.lower()
        if _entity_type not in self.mapping_data:
            raise ValueError(f"Unknown entity type: {_entity_type}")
        _entity_type_mapping = self.mapping_data[_entity_type]
        if _entity_subtype not in _entity_type_mapping["types"]:
            raise ValueError(f"Unknown entity type: {_entity_type}/{_entity_subtype}")
        return _entity_type_mapping["types"][_entity_subtype]

    def get_stix2_type_for_entity(self, entity_type: str, entity_subtype: str) -> str:
        """
        Get the STIX2 type for a Colander entity type.

        Args:
            entity_type (str): The Colander entity type (e.g., "actor", "device").
            entity_subtype (str): The Colander entity subtype (e.g. "ipv4").

        Returns:
            str: The corresponding STIX2 type.
        """
        _entity_mapping = self.get_entity_subtype_mapping(entity_type, entity_subtype)
        return _entity_mapping.get("stix2_type", "")

    def get_supported_colander_types(self) -> List[str]:
        return self.mapping_data.get("supported_colander_types", [])

    def get_supported_stix2_types(self) -> List[str]:
        _types: Set[str] = set()
        for _supported_colander_type in self.get_supported_colander_types():
            _type_mapping = self.mapping_data.get(_supported_colander_type, {})
            for _subtype_name, _mapping in _type_mapping.get("types", {}).items():
                _types.add(_mapping.get("stix2_type", ""))
        return list(_types)

    def get_entity_type_for_stix2(self, stix2_type: str) -> Tuple[Optional[str], Optional[List[str]]]:
        """
        Get the Colander entity type for a STIX2 type (e.g. "indicator", "threat-actor").

        Args:
            stix2_type (str): The STIX2 type.

        Returns:
            Tuple[Optional[str], Optional[List[str]]]: The corresponding Colander type and the list of
            subtype candidates, or None if not found.
        """
        if stix2_type not in self.get_supported_stix2_types():
            return None, None

        # Create mapping between STIX2 and Colander types (e.g. "treat-actor" -> "actor")
        _stix2_type_mapping: Dict[str, str] = {}
        for _supported_colander_type in self.get_supported_colander_types():
            for _supported_colander_subtype, _mapping in self.mapping_data[_supported_colander_type]["types"].items():
                _stix2_type_mapping[_mapping["stix2_type"]] = _supported_colander_type
        if stix2_type not in _stix2_type_mapping:
            return None, None

        _colander_type_name = _stix2_type_mapping[stix2_type]  # e.g. observable
        _colander_type_mapping = self.get_entity_type_mapping(_colander_type_name)

        # Iterate over Colander subtypes(e.g. ipv4, domain)
        _subtype_candidates: Set[str] = set()
        for _colander_subtype_name, _mapping in _colander_type_mapping.get("types", {}).items():
            # List subtype candidates
            if "stix2_type" in _mapping and _mapping["stix2_type"] == stix2_type:
                _subtype_candidates.add(_colander_subtype_name)

        # If not candidates, append the "generic" subtype
        if len(_subtype_candidates) == 0:
            _subtype_candidates.add("generic")

        return _colander_type_name, list(_subtype_candidates)

        # Handle the specific case of STIX2 indicators
        # if stix2_type == "indicator" and "pattern" in stix2_entity and "name" in stix2_entity:
        #     _pattern_name = extract_stix2_pattern_name(stix2_entity["pattern"])
        #     for _candidate_type, _candidate_mapping in _subtype_candidates.items():
        #         if _pattern_name in _candidate_mapping["pattern"]:
        #             return _colander_type_name, _candidate_type
        #     # Return the generic subtype as it was not possible to narrow down the type selection
        #     return "observable", "generic"
        # if stix2_type == "threat-actor":
        #     return "actor", "threat_actor"
        # elif len(_subtype_candidates) == 1:
        #     return _colander_type_name, list(_subtype_candidates.keys())[0]
        # else:
        #     return _colander_type_name, "generic"

    def get_stix2_to_colander_field_mapping(self, entity_type: str) -> Dict[str, str]:
        """
        Get the field mapping from STIX2 to Colander for a specific entity type.

        Args:
            entity_type (str): The entity type.

        Returns:
            Dict[str, str]: The field mapping from STIX2 to Colander.
        """
        entity_mapping = self.get_entity_type_mapping(entity_type)
        return entity_mapping.get("stix2_to_colander", {})

    def get_colander_to_stix2_field_mapping(self, entity_type: str) -> Dict[str, str]:
        """
        Get the field mapping from Colander to STIX2 for a specific entity type.

        Args:
            entity_type (str): The entity type.

        Returns:
            Dict[str, str]: The field mapping from Colander to STIX2.
        """
        entity_mapping = self.get_entity_type_mapping(entity_type)
        return entity_mapping.get("colander_to_stix2", {})

    def get_relation_mapping(self, relation_type: str) -> Dict[str, Any]:
        """
        Get the mapping data for a specific relation type.

        Args:
            relation_type (str): The relation type (e.g., "uses", "targets").

        Returns:
            Dict[str, Any]: The mapping data for the relation type.
        """
        relation_types = self.mapping_data.get("relation_types", {})
        if relation_type not in relation_types:
            raise ValueError(f"Unknown relation type: {relation_type}")
        return relation_types[relation_type]

    def get_source_types_for_relation(self, relation_type: str) -> List[str]:
        """
        Get the valid source entity types for a relation type.

        Args:
            relation_type (str): The relation type.

        Returns:
            List[str]: The valid source entity types.
        """
        relation_mapping = self.get_relation_mapping(relation_type)
        return relation_mapping.get("source_types", [])

    def get_target_types_for_relation(self, relation_type: str) -> List[str]:
        """
        Get the valid target entity types for a relation type.

        Args:
            relation_type (str): The relation type.

        Returns:
            List[str]: The valid target entity types.
        """
        relation_mapping = self.get_relation_mapping(relation_type)
        return relation_mapping.get("target_types", [])

    def get_observable_pattern(self, observable_type: str) -> Dict[str, Any]:
        """
        Get the pattern data for a specific observable type.

        Args:
            observable_type (str): The observable type (e.g., "ipv4", "domain").

        Returns:
            Dict[str, Any]: The pattern data for the observable type.
        """
        observable_patterns = self.mapping_data.get("observable_patterns", {})
        if observable_type not in observable_patterns:
            raise ValueError(f"Unknown observable type: {observable_type}")
        return observable_patterns[observable_type]

    def get_pattern_template(self, observable_type: str) -> str:
        """
        Get the pattern template for a specific observable type.

        Args:
            observable_type (str): The observable type.

        Returns:
            str: The pattern template.
        """
        pattern_data = self.get_observable_pattern(observable_type)
        return pattern_data.get("pattern_template", "")

    def get_pattern_type(self, observable_type: str) -> str:
        """
        Get the pattern type for a specific observable type.

        Args:
            observable_type (str): The observable type.

        Returns:
            str: The pattern type.
        """
        pattern_data = self.get_observable_pattern(observable_type)
        return pattern_data.get("pattern_type", "")

    def get_threat_mapping(self, threat_type: str) -> Dict[str, Any]:
        """
        Get the mapping data for a specific threat type.

        Args:
            threat_type (str): The threat type (e.g., "ransomware", "trojan").

        Returns:
            Dict[str, Any]: The mapping data for the threat type.
        """
        threat_types = self.mapping_data.get("threat_types", {})
        if threat_type not in threat_types:
            raise ValueError(f"Unknown threat type: {threat_type}")
        return threat_types[threat_type]

    def get_stix2_type_for_threat(self, threat_type: str) -> str:
        """
        Get the STIX2 type for a specific threat type.

        Args:
            threat_type (str): The threat type.

        Returns:
            str: The STIX2 type.
        """
        threat_mapping = self.get_threat_mapping(threat_type)
        return threat_mapping.get("stix2_type", "")

    def get_malware_types_for_threat(self, threat_type: str) -> List[str]:
        """
        Get the malware types for a specific threat type.

        Args:
            threat_type (str): The threat type.

        Returns:
            List[str]: The malware types.
        """
        threat_mapping = self.get_threat_mapping(threat_type)
        return threat_mapping.get("malware_types", [])

    def get_field_relationship_type(self, field_name: str) -> str:
        """
        Get the STIX2 relationship type for a field name.

        Args:
            field_name (str): The field name.

        Returns:
            str: The STIX2 relationship type, or "related-to" if not found.
        """
        field_relationship_map = self.mapping_data.get("field_relationship_map", {})
        return field_relationship_map.get(field_name, "related-to")
