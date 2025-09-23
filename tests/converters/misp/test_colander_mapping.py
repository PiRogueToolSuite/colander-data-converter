import json
import unittest
from importlib import resources

from pymisp import MISPOrganisation

from colander_data_converter.base.models import (
    Observable,
    Artifact,
    DetectionRule,
    Device,
    Actor,
    ColanderFeed,
    Case,
    Event,
    DataFragment,
    CommonEntitySuperTypes,
)
from colander_data_converter.base.types.actor import ActorTypes
from colander_data_converter.base.types.artifact import ArtifactTypes
from colander_data_converter.base.types.data_fragment import DataFragmentTypes
from colander_data_converter.base.types.detection_rule import DetectionRuleTypes
from colander_data_converter.base.types.device import DeviceTypes
from colander_data_converter.base.types.event import EventTypes
from colander_data_converter.base.types.observable import ObservableTypes
from colander_data_converter.converters.misp.converter import ColanderToMISPMapper, MISPToColanderMapper


class TestColanderMapping(unittest.TestCase):
    def test_observable_mapping(self):
        obs_type = ObservableTypes.IPV4.value
        obs = Observable(name="8.8.8.8", type=obs_type, description="Test description")
        mapper = ColanderToMISPMapper()
        attr = mapper.convert_colander_object(obs)
        self.assertIsNotNone(attr)

    def test_observable_mappings(self):
        mapper = ColanderToMISPMapper()
        supported_types = mapper.mapping.colander_super_types_mapping["OBSERVABLE"].get_supported_colander_types()
        for obs_type in ObservableTypes:
            if obs_type.value.short_name not in supported_types:
                print(f"Skipping {obs_type.value.short_name}")
                continue
            obs = Observable(name="8.8.8.8", type=obs_type.value, description="Test description")
            misp_obj = mapper.convert_colander_object(obs)
            self.assertIsNotNone(misp_obj)
            misp_obj.to_json()

    def test_artifact_mapping(self):
        artifact_type = ArtifactTypes.DOCUMENT.value
        artifact = Artifact(
            name="malware_sample.pdf",
            type=artifact_type,
            extension="pdf",
            mime_type="application/pdf",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        )
        mapper = ColanderToMISPMapper()
        obj = mapper.convert_colander_object(artifact)
        self.assertIsNotNone(obj)

    def test_artifact_mappings(self):
        mapper = ColanderToMISPMapper()
        supported_types = mapper.mapping.colander_super_types_mapping["ARTIFACT"].get_supported_colander_types()
        for colander_type in ArtifactTypes:
            if colander_type.value.short_name not in supported_types:
                print(f"Skipping {colander_type.value.short_name}")
                continue
            colander_obj = Artifact(
                name="malware_sample.pdf",
                type=colander_type.value,
                extension="pdf",
                mime_type="application/pdf",
                sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            )
            misp_obj = mapper.convert_colander_object(colander_obj)
            self.assertIsNotNone(misp_obj)
            misp_obj.to_json()

    def test_detection_rule_mapping(self):
        rule_type = DetectionRuleTypes.YARA.value
        rule = DetectionRule(
            name="Test Yara rules",
            type=rule_type,
            content="""
                rule CoulusCoelib
                {
                    strings:
                        $java_class = /Lcoelib.c.couluslibrary/
                        $url = "mobile.measurelib.com" ascii
                    condition:
                        uint16(0) == 0x6564 and #java_class > 10 and $url
                }
                """,
        )
        mapper = ColanderToMISPMapper()
        obj = mapper.convert_colander_object(rule)
        self.assertIsNotNone(obj)

    def test_device_mapping(self):
        device = Device(
            name="Device", type=DeviceTypes.LAPTOP.value, attributes={"ip": "192.168.127.12", "os": "Linux"}
        )
        mapper = ColanderToMISPMapper()
        obj = mapper.convert_colander_object(device)
        j = obj.to_json()
        self.assertIsNotNone(obj)

    def test_device_mappings(self):
        mapper = ColanderToMISPMapper()
        supported_types = mapper.mapping.colander_super_types_mapping["DEVICE"].get_supported_colander_types()
        for colander_type in DeviceTypes:
            if colander_type.value.short_name not in supported_types:
                print(f"Skipping {colander_type.value.short_name}")
                continue
            colander_obj = Device(
                name="Device", type=colander_type.value, attributes={"ip": "192.168.127.12", "os": "Linux"}
            )
            misp_obj = mapper.convert_colander_object(colander_obj)
            self.assertIsNotNone(misp_obj)
            misp_obj.to_json()

    def test_actor_mappings(self):
        mapper = ColanderToMISPMapper()
        supported_types = mapper.mapping.colander_super_types_mapping["ACTOR"].get_supported_colander_types()
        for colander_type in ActorTypes:
            if colander_type.value.short_name not in supported_types:
                print(f"Skipping {colander_type.value.short_name}")
                continue
            colander_obj = Actor(name="Test actor", type=colander_type.value, description="Example of actor")
            misp_obj = mapper.convert_colander_object(colander_obj)
            self.assertIsNotNone(misp_obj)
            j = misp_obj.to_json()

    def test_event_mappings(self):
        mapper = ColanderToMISPMapper()
        supported_types = mapper.mapping.colander_super_types_mapping["EVENT"].get_supported_colander_types()
        for colander_type in EventTypes:
            if colander_type.value.short_name not in supported_types:
                print(f"Skipping {colander_type.value.short_name}")
                continue
            colander_obj = Event(name="Test event", type=colander_type.value, description="Example of event")
            misp_obj = mapper.convert_colander_object(colander_obj)
            self.assertIsNotNone(misp_obj)
            j = misp_obj.to_json()

    def test_data_fragment_mappings(self):
        mapper = ColanderToMISPMapper()
        supported_types = mapper.mapping.colander_super_types_mapping["DATAFRAGMENT"].get_supported_colander_types()
        for colander_type in DataFragmentTypes:
            if colander_type.value.short_name not in supported_types:
                print(f"Skipping {colander_type.value.short_name}")
                continue
            colander_obj = DataFragment(
                name="Test data fragment",
                type=colander_type.value,
                content="This is a random content",
                description="Example of data fragment",
            )
            misp_obj = mapper.convert_colander_object(colander_obj)
            self.assertIsNotNone(misp_obj)
            j = misp_obj.to_json()

    def test_case_conversion(self):
        mapper = ColanderToMISPMapper()
        resource_package = __name__
        json_file = resources.files(resource_package).joinpath("data").joinpath("colander_feed.json")
        with json_file.open() as f:
            raw = json.load(f)
            feed = ColanderFeed.load(raw)
        case = Case(name="Test case", description="Test case description")

        n_actor = len(feed.get_by_super_type(CommonEntitySuperTypes.ACTOR.value))
        n_artifact = len(feed.get_by_super_type(CommonEntitySuperTypes.ARTIFACT.value))
        n_device = len(feed.get_by_super_type(CommonEntitySuperTypes.DEVICE.value))
        n_event = len(feed.get_by_super_type(CommonEntitySuperTypes.EVENT.value))
        n_data_fragment = len(feed.get_by_super_type(CommonEntitySuperTypes.DATA_FRAGMENT.value))
        n_detection_rule = len(feed.get_by_super_type(CommonEntitySuperTypes.DETECTION_RULE.value))
        n_observable = len(feed.get_by_super_type(CommonEntitySuperTypes.OBSERVABLE.value))
        n_threat = len(feed.get_by_super_type(CommonEntitySuperTypes.THREAT.value))
        n_entities = sum([n_actor, n_artifact, n_device, n_event, n_data_fragment, n_detection_rule])

        misp_event, skipped = mapper.convert_case(case, feed)

        mapper = MISPToColanderMapper()
        case, feed = mapper.convert_misp_event(misp_event)
        assert len(feed.entities) == n_entities + n_observable - len(skipped)

        n_attributes = len(misp_event.attributes)
        n_objects = len(misp_event.objects)

        assert n_attributes == n_observable - len(skipped)
        assert n_objects == n_entities

        org = MISPOrganisation()
        org.from_dict(
            **{
                "name": "TestLab",
                "uuid": "068d1297-444d-4f8c-a299-a496509920c8",
            }
        )
        misp_event.orgc = org
        j = misp_event.to_json()
        misp_feed = misp_event.to_feed()
        j = json.dumps(misp_feed)
