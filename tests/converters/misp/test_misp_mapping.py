import unittest
from importlib import resources

from pymisp import MISPEvent, MISPObject, MISPFeed

from colander_data_converter.base.types.actor import ActorTypes
from colander_data_converter.base.types.artifact import ArtifactTypes
from colander_data_converter.base.types.data_fragment import DataFragmentTypes
from colander_data_converter.base.types.detection_rule import DetectionRuleTypes
from colander_data_converter.base.types.device import DeviceTypes
from colander_data_converter.base.types.event import EventTypes
from colander_data_converter.base.types.observable import ObservableTypes
from colander_data_converter.base.types.threat import ThreatTypes
from colander_data_converter.converters.misp.converter import MISPToColanderMapper, MISPConverter


class TestMISPMapping(unittest.TestCase):
    def test_observable_mappings(self):
        mapper = MISPToColanderMapper()
        super_type_mapping = mapper.mapping.colander_super_types_mapping.get("OBSERVABLE")
        for t in ObservableTypes:
            observable_type = t.value
            if (type_mapping := super_type_mapping.types_mapping.get(observable_type.short_name)) is None:
                continue
            if type_mapping.misp_object != "misp-attribute":
                continue
            event = MISPEvent()
            attribute_type = type_mapping.misp_type
            attribute_value = observable_type.value_example or "xxx"
            event.add_attribute(attribute_type, value=attribute_value)
            mapping = mapper.mapping.get_misp_attribute_mapping(event.attributes[0])
            self.assertEqual(mapping.colander_type, t.value.short_name)
            entity = mapper._convert_attribute(event.attributes[0])
            self.assertIsNotNone(entity)
            self.assertEqual(entity.name, attribute_value)
            self.assertEqual(entity.type, t.value)

    def test_artifact_mappings(self):
        mapper = MISPToColanderMapper()
        super_type_mapping = mapper.mapping.colander_super_types_mapping.get("ARTIFACT")
        for t in ArtifactTypes:
            artifact_type = t.value
            if (type_mapping := super_type_mapping.types_mapping.get(artifact_type.short_name)) is None:
                continue
            if type_mapping.misp_object == "misp-attribute":
                continue
            if not artifact_type.type_hints:
                continue
            misp_object = MISPObject(name=type_mapping.misp_object)
            attribute_value = "test.txt"
            misp_object.add_attribute("filename", value=attribute_value)
            mimetype = artifact_type.type_hints["suggested_by_mime_types"]["types"][0]
            misp_object.add_attribute("mimetype", value=mimetype)
            mapping = mapper.mapping.get_misp_object_mapping(misp_object)
            self.assertEqual(mapping.colander_type, t.value.short_name)
            entity = mapper._convert_object(misp_object)
            self.assertIsNotNone(entity)
            self.assertEqual(entity.name, attribute_value)
            self.assertEqual(entity.type, t.value)

    def test_device_mappings(self):
        mapper = MISPToColanderMapper()
        super_type_mapping = mapper.mapping.colander_super_types_mapping.get("DEVICE")
        for t in DeviceTypes:
            device_type = t.value
            if (type_mapping := super_type_mapping.types_mapping.get(device_type.short_name)) is None:
                continue
            if type_mapping.misp_object == "misp-attribute":
                continue
            misp_object = MISPObject(name=type_mapping.misp_object)
            attribute_value = "foo"
            misp_object.add_attribute("name", value=attribute_value)
            device_type_name = type_mapping.colander_misp_mapping["literals"]["device-type"]
            misp_object.add_attribute("device-type", value=device_type_name)
            mapping = mapper.mapping.get_misp_object_mapping(misp_object)
            self.assertEqual(mapping.colander_type, t.value.short_name)
            entity = mapper._convert_object(misp_object)
            self.assertIsNotNone(entity)
            self.assertEqual(entity.name, attribute_value)
            self.assertEqual(entity.type, t.value)

    def test_actor_mappings(self):
        mapper = MISPToColanderMapper()
        super_type_mapping = mapper.mapping.colander_super_types_mapping.get("ACTOR")
        for t in ActorTypes:
            actor_type = t.value
            if (type_mapping := super_type_mapping.types_mapping.get(actor_type.short_name)) is None:
                continue
            if type_mapping.misp_object == "misp-attribute":
                continue
            misp_object = MISPObject(name=type_mapping.misp_object)
            attr_name = type_mapping.colander_misp_mapping["misp_attributes"]["name"]
            attribute_value = "foo"
            misp_object.add_attribute(attr_name, value=attribute_value)
            for name, value in type_mapping.colander_misp_mapping["literals"].items():
                misp_object.add_attribute(name, value=value)
            mapping = mapper.mapping.get_misp_object_mapping(misp_object)
            self.assertEqual(mapping.colander_type, t.value.short_name)
            entity = mapper._convert_object(misp_object)
            self.assertIsNotNone(entity)
            self.assertEqual(entity.name, attribute_value)
            self.assertEqual(entity.type, t.value)

    def test_event_mappings(self):
        mapper = MISPToColanderMapper()
        super_type_mapping = mapper.mapping.colander_super_types_mapping.get("EVENT")
        for t in EventTypes:
            event_type = t.value
            if (type_mapping := super_type_mapping.types_mapping.get(event_type.short_name)) is None:
                continue
            if type_mapping.misp_object == "misp-attribute":
                continue
            misp_object = MISPObject(name=type_mapping.misp_object)
            attr_name = type_mapping.colander_misp_mapping["misp_attributes"]["name"]
            attribute_value = "foo"
            misp_object.add_attribute(attr_name, value=attribute_value)
            for name, value in type_mapping.colander_misp_mapping["literals"].items():
                misp_object.add_attribute(name, value=value)
            mapping = mapper.mapping.get_misp_object_mapping(misp_object)
            self.assertEqual(mapping.colander_type, t.value.short_name)
            entity = mapper._convert_object(misp_object)
            self.assertIsNotNone(entity)
            self.assertEqual(entity.name, attribute_value)
            self.assertEqual(entity.type, t.value)

    def test_data_fragment_mappings(self):
        mapper = MISPToColanderMapper()
        super_type_mapping = mapper.mapping.colander_super_types_mapping.get("DATAFRAGMENT")
        for t in DataFragmentTypes:
            data_fragment_type = t.value
            if (type_mapping := super_type_mapping.types_mapping.get(data_fragment_type.short_name)) is None:
                continue
            if type_mapping.misp_object == "misp-attribute":
                continue
            misp_object = MISPObject(name=type_mapping.misp_object)
            attr_name = type_mapping.colander_misp_mapping["misp_attributes"]["name"]
            attribute_value = "foo"
            misp_object.add_attribute(attr_name, value=attribute_value)
            for name, value in type_mapping.colander_misp_mapping["literals"].items():
                misp_object.add_attribute(name, value=value)
            mapping = mapper.mapping.get_misp_object_mapping(misp_object)
            self.assertEqual(mapping.colander_type, t.value.short_name)
            entity = mapper._convert_object(misp_object)
            self.assertIsNotNone(entity)
            self.assertEqual(entity.name, attribute_value)
            self.assertEqual(entity.type, t.value)

    def test_detection_rule_mappings(self):
        mapper = MISPToColanderMapper()
        super_type_mapping = mapper.mapping.colander_super_types_mapping.get("DETECTIONRULE")
        for t in DetectionRuleTypes:
            detection_rule_type = t.value
            if (type_mapping := super_type_mapping.types_mapping.get(detection_rule_type.short_name)) is None:
                continue
            if type_mapping.misp_object == "misp-attribute":
                continue
            misp_object = MISPObject(name=type_mapping.misp_object)
            attr_name = type_mapping.colander_misp_mapping["misp_attributes"]["name"]
            attribute_value = "foo"
            misp_object.add_attribute(attr_name, value=attribute_value)
            mapping = mapper.mapping.get_misp_object_mapping(misp_object)
            self.assertEqual(mapping.colander_type, t.value.short_name)
            entity = mapper._convert_object(misp_object)
            self.assertIsNotNone(entity)
            self.assertEqual(entity.name, attribute_value)
            self.assertEqual(entity.type, t.value)

    def test_threat_mappings(self):
        mapper = MISPToColanderMapper()
        super_type_mapping = mapper.mapping.colander_super_types_mapping.get("THREAT")
        for t in ThreatTypes:
            threat_type = t.value
            if (type_mapping := super_type_mapping.types_mapping.get(threat_type.short_name)) is None:
                continue
            if type_mapping.misp_object != "misp-tag":
                continue
            misp_event = MISPEvent()
            tag_name = type_mapping.colander_misp_mapping["literals"]["name"]
            misp_event.add_tag(tag_name)
            mapping = mapper.mapping.get_misp_tag_mapping(misp_event.tags[0])
            self.assertEqual(mapping.colander_type, t.value.short_name)

    def test_misp_converter(self):
        converter = MISPConverter()
        # Load MISP feed
        resource_package = __name__
        json_file = resources.files(resource_package).joinpath("data").joinpath("misp_feed.json")
        misp_feed = MISPFeed()
        with json_file.open() as json_file:
            misp_feed.from_json(json_file.read())
        feeds = converter.misp_to_colander(misp_feed)
        self.assertEqual(len(feeds), 1)
        feed = feeds[0]
        self.assertEqual(len(feed.entities), 39)
