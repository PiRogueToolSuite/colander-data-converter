import unittest
from datetime import datetime, UTC, timedelta

from colander_data_converter.base.models import (
    ColanderFeed,
    ColanderRepository,
    Actor,
    Observable,
    EntityRelation,
    ActorTypes,
    ObservableTypes,
    Device,
    DeviceTypes,
    EventTypes,
    Artifact,
    ArtifactTypes,
    DetectionRule,
    DetectionRuleTypes,
    Event,
)
from colander_data_converter.formats.threatr.converter import ColanderToThreatrMapper
from colander_data_converter.formats.threatr.models import ThreatrFeed


class TestColanderToThreatrConverter(unittest.TestCase):
    def setUp(self):
        # Clear the repository before each test
        ColanderRepository().clear()

    def test_convert_entity(self):
        # Create a Colander entity
        actor = Actor(
            name="Test Actor",
            type=ActorTypes.by_short_name("threat_actor"),
            description="A test actor",
            attributes={"custom_field": "custom_value"},
        )

        # Create a mapper and convert the entity
        mapper = ColanderToThreatrMapper()
        threatr_entity = mapper._convert_entity(actor)

        # Verify the conversion
        self.assertEqual(threatr_entity.id, actor.id)
        self.assertEqual(threatr_entity.name, actor.name)
        self.assertEqual(threatr_entity.type, actor.type)
        self.assertEqual(threatr_entity.description, actor.description)
        self.assertIn("custom_field", threatr_entity.attributes)
        self.assertEqual(threatr_entity.attributes["custom_field"], "custom_value")

    def test_convert_relation(self):
        # Create Colander entities
        source = Actor(name="Source Actor", type=ActorTypes.by_short_name("threat_actor"))
        target = Observable(name="Target Observable", type=ObservableTypes.by_short_name("domain"))

        # Create a Colander relation
        relation = EntityRelation(name="uses", obj_from=source.id, obj_to=target.id, attributes={"confidence": "high"})

        # Create a mapper and convert the relation
        mapper = ColanderToThreatrMapper()
        threatr_relation = mapper._convert_relation(relation)

        # Verify the conversion
        self.assertEqual(threatr_relation.id, relation.id)
        self.assertEqual(threatr_relation.name, relation.name)
        self.assertEqual(threatr_relation.obj_from, relation.obj_from)
        self.assertEqual(threatr_relation.obj_to, relation.obj_to)
        self.assertIn("confidence", threatr_relation.attributes)
        self.assertEqual(threatr_relation.attributes["confidence"], "high")

    def test_convert_to_threatr(self):
        # Create Colander entities
        actor = Actor(
            name="Test Actor",
            type=ActorTypes.by_short_name("threat_actor"),
            description="A test actor",
            attributes={"custom_field": "custom_value"},
        )
        observable = Observable(
            name="Test Observable", type=ObservableTypes.by_short_name("domain"), description="A test observable"
        )

        # Create a Colander relation
        relation = EntityRelation(name="uses", obj_from=actor.id, obj_to=observable.id)

        # Add the entities and relation to a feed
        feed = ColanderFeed()
        feed.entities = {str(actor.id): actor, str(observable.id): observable}
        feed.relations = {str(relation.id): relation}

        # Create a mapper and convert the feed
        mapper = ColanderToThreatrMapper()
        threatr_feed = mapper.convert(feed, actor.id)

        # Verify the conversion
        self.assertIsInstance(threatr_feed, ThreatrFeed)
        self.assertEqual(threatr_feed.root_entity.id, actor.id)
        self.assertEqual(len(threatr_feed.entities), 2)
        self.assertEqual(len(threatr_feed.relations), 1)
        self.assertEqual(threatr_feed.relations[0].id, relation.id)
        self.assertEqual(threatr_feed.relations[0].id, relation.id)
        self.assertEqual(threatr_feed.relations[0].obj_from, actor.id)
        self.assertEqual(threatr_feed.relations[0].obj_to, observable.id)

    def test_convert_to_threatr_with_references(self):
        # Create Colander entities with a reference field
        actor = Actor(name="Test Actor", type=ActorTypes.by_short_name("threat_actor"))
        device = Device(name="Test Device", type=DeviceTypes.by_short_name("mobile"), operated_by=actor)

        # Add the entities to a feed
        feed = ColanderFeed()
        feed.entities = {str(actor.id): actor, str(device.id): device}

        # Create a mapper and convert the feed
        mapper = ColanderToThreatrMapper()
        threatr_feed = mapper.convert(feed, actor)

        # Verify the conversion
        self.assertIsInstance(threatr_feed, ThreatrFeed)
        self.assertEqual(threatr_feed.root_entity.id, actor.id)
        self.assertEqual(len(threatr_feed.entities), 2)

        # Verify that a relation was created from the reference field
        self.assertEqual(len(threatr_feed.relations), 1)
        relation = threatr_feed.relations[0]
        self.assertEqual(relation.name, "operated by")
        self.assertEqual(relation.obj_from, device.id)
        self.assertEqual(relation.obj_to, actor.id)

    def test_convert_event(self):
        event_type = EventTypes.enum.HIT.value
        obs_type = ObservableTypes.enum.IPV4.value
        obs_1 = Observable(name="8.8.8.8", type=obs_type)
        obs_2 = Observable(name="1.1.1.1", type=obs_type)
        artifact = Artifact(
            name="file.txt",
            type=ArtifactTypes.enum.BINARY.value,
        )
        detection_rule = DetectionRule(
            name="Rule",
            type=DetectionRuleTypes.enum.YARA.value,
            content="rule",
        )
        device = Device(
            name="Device",
            type=DeviceTypes.enum.LAPTOP.value,
        )
        now = datetime.now(UTC)
        event = Event(
            name="Event 2",
            type=event_type,
            attributes={"key": "value"},
            first_seen=now,
            last_seen=now + timedelta(minutes=5),
            count=3,
            extracted_from=artifact,
            observed_on=device,
            detected_by=detection_rule,
            involved_observables=[obs_1, obs_2],
        )
        feed = ColanderFeed()
        feed.entities = {
            str(obs_1.id): obs_1,
            str(artifact.id): artifact,
            str(detection_rule.id): detection_rule,
            str(device.id): device,
            str(event.id): event,
        }
        mapper = ColanderToThreatrMapper()
        threatr_feed = mapper.convert(feed, obs_1.id)
        self.assertIsInstance(threatr_feed, ThreatrFeed)
        self.assertEqual(threatr_feed.root_entity.id, obs_1.id)
        self.assertEqual(len(threatr_feed.entities), 4)
        self.assertEqual(len(threatr_feed.events), 1)
        self.assertEqual(len(threatr_feed.relations), 4)
        self.assertNotIn("involved_observables", threatr_feed.events[0].attributes)
