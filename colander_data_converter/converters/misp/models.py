import json
from importlib import resources
from typing import Optional, Dict, Any, Type, List, Tuple

from pydantic import BaseModel, ConfigDict
from pymisp import MISPObject, AbstractMISP, MISPAttribute

from colander_data_converter.base.models import CommonEntitySuperTypes, CommonEntitySuperType
from colander_data_converter.base.types.base import CommonEntityType

type MispColanderMapping = Dict[str, Any]
type ColanderMispMapping = Dict[str, Any]


class EntityTypeMapping(BaseModel):
    colander_type: str
    misp_object: str
    misp_type: Optional[str] = None
    misp_definition: Optional[str] = None
    misp_colander_mapping: MispColanderMapping
    colander_misp_mapping: ColanderMispMapping

    def get_misp_model_class(self) -> (Type[AbstractMISP], str):
        if self.misp_object == "misp-attribute":
            return MISPAttribute, self.misp_type
        return MISPObject, self.misp_object

    def get_colander_misp_field_mapping(self) -> List[Optional[Tuple[str, str]]]:
        return [(src, dst) for src, dst in self.colander_misp_mapping.items() if isinstance(dst, str)]

    def get_colander_misp_literals_mapping(self) -> List[Optional[Tuple[str, str]]]:
        return [(src, dst) for src, dst in self.colander_misp_mapping.get("literals", {}).items()]

    def get_colander_misp_attributes_mapping(self) -> List[Optional[Tuple[str, str]]]:
        return [
            (src, dst)
            for src, dst in self.colander_misp_mapping.get("misp_attributes", {}).items()
            if isinstance(dst, str)
        ]


class EntitySuperTypeMapping(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
    )
    colander_super_type: str
    model_class: Any
    types_mapping: Dict[str, EntityTypeMapping] = {}

    def get_supported_colander_types(self) -> List[Optional[str]]:
        return list(self.types_mapping.keys())


class Mapping(object):
    TYPES = [
        (CommonEntitySuperTypes.ACTOR.value, "actor"),
        (CommonEntitySuperTypes.ARTIFACT.value, "artifact"),
        (CommonEntitySuperTypes.DEVICE.value, "device"),
        (CommonEntitySuperTypes.DETECTION_RULE.value, "detection_rule"),
        (CommonEntitySuperTypes.OBSERVABLE.value, "observable"),
    ]

    def __init__(self):
        self.super_types_mapping: Dict[str, EntitySuperTypeMapping] = {}
        for type_class, prefix in self.TYPES:
            self.super_types_mapping[type_class.short_name] = self._load_mapping_definition(type_class, prefix)

    @staticmethod
    def _load_mapping_definition(type_class, filename_prefix: str) -> EntitySuperTypeMapping:
        resource_package = __name__
        json_file = resources.files(resource_package).joinpath("data").joinpath(f"{filename_prefix}_misp_mapping.json")
        super_type_mapping = EntitySuperTypeMapping(colander_super_type=type_class.short_name, model_class=type_class)
        with json_file.open() as f:
            raw = json.load(f)
            for definition in raw:
                type_mapping = EntityTypeMapping.model_validate(definition)
                super_type_mapping.types_mapping[type_mapping.colander_type] = type_mapping
        return super_type_mapping

    def get_mapping(
        self, entity_super_type: CommonEntitySuperType, entity_type: CommonEntityType
    ) -> Optional[EntityTypeMapping]:
        est_mapping = self.super_types_mapping.get(entity_super_type.short_name, None)
        if est_mapping:
            return est_mapping.types_mapping.get(entity_type.short_name, None)
        return None
