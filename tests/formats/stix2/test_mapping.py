import json
from importlib import resources

from colander_data_converter.base.models import ColanderRepository
from colander_data_converter.formats.stix2 import Stix2MappingLoader, Stix2ToColanderMapper


class TestStix2ToColanderMapping:
    def test_actor_mapping(self):
        ColanderRepository().clear()
        loader = Stix2MappingLoader()
        mapper = Stix2ToColanderMapper()
        _type, _candidates = loader.get_entity_type_for_stix2("threat-actor")
        _subtype = mapper._get_actor_type({"type": "threat-actor"}, _candidates)
        assert _type == "actor"
        assert _subtype == "threat_actor"
        _type, _candidates = loader.get_entity_type_for_stix2("unknown")
        _subtype = mapper._get_actor_type({"type": "threat-unknown"}, _candidates)
        assert _type is None
        assert _subtype == "generic"

    def test_observable_mapping(self):
        ColanderRepository().clear()
        loader = Stix2MappingLoader()
        mapper = Stix2ToColanderMapper()
        _type, _candidates = loader.get_entity_type_for_stix2("indicator")
        stix2_object = {"name": "foo.local", "pattern": "[domain-name:value = 'foo.local']"}
        _subtype = mapper._get_observable_type(stix2_object, _candidates)
        assert _type == "observable"
        assert _subtype == "domain"
        _type, _candidates = loader.get_entity_type_for_stix2("indicator")
        stix2_object = {"name": "foo.local", "pattern": "[invalid:value = 'foo.local']"}
        _subtype = mapper._get_observable_type(stix2_object, _candidates)
        assert _type == "observable"
        assert _subtype == "generic"

    def test_stix2_converter(self):
        ColanderRepository().clear()
        mapper = Stix2ToColanderMapper()
        f = mapper.convert(
            {
                "objects": [
                    {
                        "type": "threat-actor",
                        "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                        "created": "2023-01-01T00:00:00.000Z",
                        "modified": "2023-01-01T00:00:00.000Z",
                        "name": "Evil Hacker Group",
                        "description": "A malicious threat actor group known for targeting financial institutions.",
                    }
                ]
            }
        )
        assert f is not None

    def test_stix2_bundle(self):
        ColanderRepository().clear()
        mapper = Stix2ToColanderMapper()
        resource_package = __name__
        json_file = resources.files(resource_package).joinpath("data").joinpath("stix2_bundle.json")
        with json_file.open() as f:
            raw = json.load(f)
        f = mapper.convert(raw)
