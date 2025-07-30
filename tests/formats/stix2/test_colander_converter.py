import json
import unittest
from importlib import resources

from colander_data_converter.base.models import (
    ColanderFeed,
    Artifact,
    Actor,
    Device,
    Observable,
    Threat,
)
from colander_data_converter.base.types.actor import *
from colander_data_converter.base.types.artifact import *
from colander_data_converter.base.types.device import *
from colander_data_converter.base.types.observable import *
from colander_data_converter.base.types.threat import *
from colander_data_converter.formats.stix2.converter import ColanderToStix2Mapper


class TestColanderConverter(unittest.TestCase):
    def test_convert_artifact(self):
        feed = ColanderFeed()
        artifact_type = ArtifactTypes.REPORT.value
        artifact = Artifact(
            name="malware_sample.pdf",
            type=artifact_type,
            extension="pdf",
            original_name="invoice.pdf",
            mime_type="application/pdf",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            size_in_bytes=12345,
            attributes={"source": "email"},
        )
        feed.entities[str(artifact.id)] = artifact
        bundle = ColanderToStix2Mapper().convert(feed)
        self.assertEqual(len(bundle.objects), 1)
        a = bundle.objects[0]
        self.assertEqual(a.name, artifact.name)
        self.assertEqual(a.type, "file")
        self.assertEqual(a.size, artifact.size_in_bytes)
        self.assertEqual(a.mime_type, artifact.mime_type)
        self.assertEqual(a.source, artifact.attributes.get("source"))
        self.assertEqual(a.hashes["MD5"], artifact.md5)
        self.assertEqual(a.hashes["SHA-1"], artifact.sha1)
        self.assertEqual(a.hashes["SHA-256"], artifact.sha256)

    def test_convert_identity(self):
        feed = ColanderFeed()
        actor_type = ActorTypes.COMPANY.value
        actor = Actor(
            name="Dolpador",
            type=actor_type,
        )
        feed.entities[str(actor.id)] = actor
        bundle = ColanderToStix2Mapper().convert(feed)
        self.assertEqual(len(bundle.objects), 1)
        a = bundle.objects[0]
        self.assertEqual(a.name, actor.name)
        self.assertEqual(a.type, "identity")
        self.assertEqual(a.identity_class, "organization")

    def test_convert_threat_actor(self):
        feed = ColanderFeed()
        actor_type = ActorTypes.THREAT_ACTOR.value
        actor = Actor(
            name="Dolpador",
            type=actor_type,
        )
        feed.entities[str(actor.id)] = actor
        bundle = ColanderToStix2Mapper().convert(feed)
        self.assertEqual(len(bundle.objects), 1)
        a = bundle.objects[0]
        self.assertEqual(a.name, actor.name)
        self.assertEqual(a.type, "threat-actor")

    def test_convert_threat(self):
        feed = ColanderFeed()
        threat_type = ThreatTypes.SPYWARE.value
        threat = Threat(
            name="Dolpador",
            type=threat_type,
        )
        feed.entities[str(threat.id)] = threat
        bundle = ColanderToStix2Mapper().convert(feed)
        self.assertEqual(len(bundle.objects), 1)
        a = bundle.objects[0]
        self.assertEqual(a.name, threat.name)
        self.assertEqual(a.type, "malware")
        self.assertEqual(a.malware_types, ["spyware"])

    def test_convert_device(self):
        feed = ColanderFeed()
        device_type = DeviceTypes.SERVER.value
        device = Device(
            name="Dolpador",
            type=device_type,
        )
        feed.entities[str(device.id)] = device
        bundle = ColanderToStix2Mapper().convert(feed)
        self.assertEqual(len(bundle.objects), 1)
        a = bundle.objects[0]
        self.assertEqual(a.name, device.name)
        self.assertEqual(a.type, "infrastructure")
        self.assertEqual(a.infrastructure_types, ["server"])

    def test_convert_observable(self):
        feed = ColanderFeed()
        observable_type = ObservableTypes.DOMAIN.value
        observable = Observable(
            name="google.com",
            type=observable_type,
        )
        feed.entities[str(observable.id)] = observable
        bundle = ColanderToStix2Mapper().convert(feed)
        self.assertEqual(len(bundle.objects), 1)
        a = bundle.objects[0]
        self.assertEqual(a.name, observable.name)
        self.assertEqual(a.type, "indicator")
        self.assertEqual(a.pattern, "[domain-name:value = '{value}']".format(value=observable.name))

    def test_colander_converter(self):
        resource_package = __name__
        json_file = resources.files(resource_package).joinpath("data").joinpath("colander_feed.json")
        with json_file.open() as f:
            raw = json.load(f)
            feed = ColanderFeed.load(raw)

        bundle = ColanderToStix2Mapper().convert(feed)
        self.assertIsNotNone(bundle)

    def test_convert_empty_feed(self):
        feed = ColanderFeed()
        bundle = ColanderToStix2Mapper().convert(feed)
        self.assertEqual(len(bundle.objects), 0)

    def test_convert_unknown_entity_type(self):
        class UnknownEntity:
            def __init__(self):
                self.id = "unknown-1"
                self.name = "Mystery"
                self.type = "UNKNOWN_TYPE"

        feed = ColanderFeed()
        unknown = UnknownEntity()
        feed.entities[str(unknown.id)] = unknown
        bundle = ColanderToStix2Mapper().convert(feed)
        self.assertEqual(len(bundle.objects), 0)

    def test_convert_missing_fields(self):
        artifact_type = ArtifactTypes.REPORT.value
        artifact = Artifact(
            name="foo.txt",
            type=artifact_type,
            extension=None,
            original_name=None,
            mime_type=None,
            md5=None,
            sha1=None,
            sha256=None,
            size_in_bytes=1,
            attributes=None,
        )
        feed = ColanderFeed()
        feed.entities[str(artifact.id)] = artifact
        bundle = ColanderToStix2Mapper().convert(feed)
        self.assertEqual(len(bundle.objects), 1)
        a = bundle.objects[0]
        self.assertFalse(hasattr(a, "hashes"))
        self.assertEqual(a.type, "file")

    def test_convert_relationship(self):
        from colander_data_converter.base.models import EntityRelation

        feed = ColanderFeed()
        # Create two entities
        actor_type = ActorTypes.COMPANY.value
        actor = Actor(name="A", type=actor_type)
        device_type = DeviceTypes.SERVER.value
        device = Device(name="B", type=device_type)
        feed.entities[str(actor.id)] = actor
        feed.entities[str(device.id)] = device
        # Create a relation
        relation = EntityRelation(
            obj_from=actor,
            obj_to=device,
            name="uses",
        )
        feed.relations[str(relation.id)] = relation
        bundle = ColanderToStix2Mapper().convert(feed)
        # Should include both entities and the relationship
        self.assertEqual(len(bundle.objects), 3)
        types = set(o.type for o in bundle.objects)
        self.assertIn("identity", types)
        self.assertIn("infrastructure", types)
        self.assertIn("relationship", types)
