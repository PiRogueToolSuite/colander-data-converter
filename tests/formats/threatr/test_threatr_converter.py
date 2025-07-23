import json
import unittest
from importlib import resources
from typing import cast, List

import pytest
from pydantic import BaseModel, ValidationError

from colander_data_converter.base.models import (
    ColanderRepository,
    ObservableTypes,
    CommonEntitySuperTypes,
    EventTypes,
    ActorTypes,
    Observable,
    Actor,
    Event,
)
from colander_data_converter.formats.threatr.converter import ThreatrToColanderMapper
from colander_data_converter.formats.threatr.models import (
    Entity as ThreatrEntity,
    Event as ThreatrEvent,
    EntityRelation as ThreatrEntityRelation,
    ThreatrRepository,
    ThreatrFeed,
)


class TestThreatrToColanderConverter(unittest.TestCase):
    def setUp(self):
        # Clear the repository before each test
        ColanderRepository().clear()
        ThreatrRepository().clear()

    def _compare_fields(self, obj1: BaseModel, obj2: BaseModel, ignore_fields: List[str] = None):
        obj1_field_names = set(obj1.__class__.model_fields.keys())
        obj2_field_names = set(obj2.__class__.model_fields.keys())
        field_names = list(obj1_field_names & obj2_field_names)
        ignore_fields = ignore_fields or []
        for field_name in field_names:
            if field_name in ignore_fields:
                continue
            self.assertEqual(getattr(obj1, field_name), getattr(obj2, field_name))

    def test_entity_conversion(self):
        entity = ThreatrEntity(
            name="1.1.1.1",
            type=ObservableTypes.by_short_name("IPV4"),
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        )
        colander_mapper = ThreatrToColanderMapper()
        colander_entity = colander_mapper._convert_entity(entity)

        self.assertEqual(colander_entity.id, entity.id)
        self.assertEqual(colander_entity.name, entity.name)
        self.assertEqual(colander_entity.type, entity.type)
        self.assertEqual(colander_entity.super_type.short_name, entity.super_type.short_name)
        self.assertIsNotNone(colander_entity.created_at)
        self.assertIsNotNone(colander_entity.updated_at)
        self.assertEqual(colander_entity.type.short_name, "IPV4")
        self.assertEqual(colander_entity.super_type.short_name, "OBSERVABLE")

    def test_event_with_object_reference_conversion(self):
        actor = ThreatrEntity(
            name="Alice & Bob",
            type=ActorTypes.by_short_name("INDIVIDUAL"),
            super_type=CommonEntitySuperTypes.ACTOR.value,
            attributes={"foo": "bar"},
        )
        observable = ThreatrEntity(
            name="1.1.1.1",
            type=ObservableTypes.by_short_name("IPV4"),
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
            attributes={"foo": "bar"},
        )
        event = ThreatrEvent(
            name="Event 1",
            type=EventTypes.by_short_name("GENERIC"),
            involved_entity=observable,
        )
        threatr_feed = ThreatrFeed(root_entity=observable)
        threatr_feed.entities = [
            actor,
            observable,
        ]
        threatr_feed.relations = [
            ThreatrEntityRelation(
                name="operated by",
                obj_from=observable,
                obj_to=actor,
            ),
            ThreatrEntityRelation(
                name="indicates",
                obj_from=observable,
                obj_to=actor,
            ),
        ]
        threatr_feed.events = [event]
        colander_mapper = ThreatrToColanderMapper()
        colander_feed = colander_mapper.convert(threatr_feed)

        colander_actor: Actor = cast(Actor, colander_feed.entities.get(str(actor.id), None))
        colander_observable: Observable = cast(Observable, colander_feed.entities.get(str(observable.id), None))
        colander_event: Event = cast(Event, colander_feed.entities.get(str(event.id), None))

        self.assertIsNotNone(colander_actor)
        self.assertIsNotNone(colander_observable)
        self.assertIsNotNone(colander_event)
        self.assertEqual(len(colander_feed.entities), 3)
        self.assertEqual(len(colander_feed.relations), 1)
        self._compare_fields(actor, colander_actor)
        self._compare_fields(observable, colander_observable)
        self._compare_fields(event, colander_event, ignore_fields=["attributes"])
        self.assertEqual(colander_observable.operated_by, colander_actor)
        self.assertIn(colander_observable, colander_event.involved_observables)

    def test_load(self):
        resource_package = __name__
        json_file = resources.files(resource_package).joinpath("data").joinpath("threatr_feed.json")
        with json_file.open() as f:
            raw = json.load(f)
        threatr_feed = ThreatrFeed.load(raw)
        colander_mapper = ThreatrToColanderMapper()
        colander_feed = colander_mapper.convert(threatr_feed)
        for entity in threatr_feed.entities:
            if str(entity.id) not in colander_feed.entities:
                continue
            self._compare_fields(entity, colander_feed.entities[str(entity.id)], ignore_fields=["type", "super_type"])
        for event in threatr_feed.events:
            self._compare_fields(
                event, colander_feed.entities[str(event.id)], ignore_fields=["type", "super_type", "attributes"]
            )
        self.assertIsNotNone(colander_feed)

    def test_dump(self):
        resource_package = __name__
        json_file = resources.files(resource_package).joinpath("data").joinpath("threatr_feed.json")
        with json_file.open() as f:
            raw = json.load(f)
        threatr_feed = ThreatrFeed.load(raw)
        colander_mapper = ThreatrToColanderMapper()
        colander_feed = colander_mapper.convert(threatr_feed)
        tf = threatr_feed.model_dump()
        self.assertIsNotNone(tf)
        self.assertTrue(isinstance(tf, dict))
        threatr_feed.model_dump_json(indent=2)
        cf = colander_feed.model_dump()
        self.assertIsNotNone(cf)
        self.assertTrue(isinstance(cf, dict))
        colander_feed.model_dump_json()

    def test_empty_feed_conversion(self):
        """Test conversion of an empty ThreatrFeed."""
        with pytest.raises(ValidationError):
            threatr_feed = ThreatrFeed(root_entity=None, entities=[], relations=[], events=[])

    def test_entity_with_unknown_super_type(self):
        """Test conversion of an entity with an unknown super_type."""

        class DummySuperType:
            short_name = "UNKNOWN"
            type_by_short_name = staticmethod(lambda x: None)
            model_class = None

        with pytest.raises(ValidationError):
            entity = ThreatrEntity(
                name="Unknown Entity",
                type=None,
                super_type=DummySuperType,
            )

    def test_entity_with_unknown_type(self):
        """Test conversion of an entity with a known super_type but unknown type."""
        super_type = CommonEntitySuperTypes.OBSERVABLE.value

        class DummyType:
            short_name = "UNKNOWN"

        with pytest.raises(ValidationError):
            entity = ThreatrEntity(
                name="Unknown Type Entity",
                type=DummyType,
                super_type=super_type,
            )

    def test_event_conversion_with_involved_entity(self):
        """Test conversion of a ThreatrEvent with an involved_entity."""
        observable = ThreatrEntity(
            name="2.2.2.2",
            type=ObservableTypes.by_short_name("IPV4"),
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        )
        event = ThreatrEvent(
            name="Event 2",
            type=EventTypes.by_short_name("GENERIC"),
            involved_entity=observable,
        )
        threatr_feed = ThreatrFeed(root_entity=observable, entities=[observable], relations=[], events=[event])
        colander_mapper = ThreatrToColanderMapper()
        colander_feed = colander_mapper.convert(threatr_feed)
        colander_event: Event = cast(Event, colander_feed.entities.get(str(event.id), None))
        self.assertIsNotNone(colander_event)
        self.assertEqual(colander_event.name, event.name)
        self.assertEqual(len(colander_event.involved_observables), 1)
        self.assertEqual(colander_event.involved_observables[0].name, observable.name)

    def test_relation_conversion_and_field_mapping(self):
        """Test conversion of a ThreatrEntityRelation and mapping to reference field."""
        actor = ThreatrEntity(
            name="Charlie",
            type=ActorTypes.by_short_name("INDIVIDUAL"),
            super_type=CommonEntitySuperTypes.ACTOR.value,
        )
        observable = ThreatrEntity(
            name="3.3.3.3",
            type=ObservableTypes.by_short_name("IPV4"),
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        )
        relation = ThreatrEntityRelation(
            name="operated by",
            obj_from=observable,
            obj_to=actor,
        )
        threatr_feed = ThreatrFeed(root_entity=observable, entities=[actor, observable], relations=[relation],
                                   events=[])
        colander_mapper = ThreatrToColanderMapper()
        colander_feed = colander_mapper.convert(threatr_feed)
        colander_actor: Actor = cast(Actor, colander_feed.entities.get(str(actor.id), None))
        colander_observable: Observable = cast(Observable, colander_feed.entities.get(str(observable.id), None))
        self.assertIsNotNone(colander_actor)
        self.assertIsNotNone(colander_observable)
        self.assertEqual(colander_observable.operated_by, colander_actor)
        self.assertEqual(len(colander_feed.relations), 0)  # Should be mapped to field, not explicit relation

    def test_relation_conversion_without_field_mapping(self):
        """Test conversion of a ThreatrEntityRelation that cannot be mapped to a reference field."""
        actor = ThreatrEntity(
            name="Delta",
            type=ActorTypes.by_short_name("INDIVIDUAL"),
            super_type=CommonEntitySuperTypes.ACTOR.value,
        )
        observable = ThreatrEntity(
            name="4.4.4.4",
            type=ObservableTypes.by_short_name("IPV4"),
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        )
        relation = ThreatrEntityRelation(
            name="custom relation",
            obj_from=observable,
            obj_to=actor,
        )
        threatr_feed = ThreatrFeed(root_entity=observable, entities=[actor, observable], relations=[relation],
                                   events=[])
        colander_mapper = ThreatrToColanderMapper()
        colander_feed = colander_mapper.convert(threatr_feed)
        self.assertEqual(len(colander_feed.relations), 1)
        rel = list(colander_feed.relations.values())[0]
        self.assertEqual(rel.name, "custom relation")
        self.assertEqual(rel.obj_from.name, "4.4.4.4")
        self.assertEqual(rel.obj_to.name, "Delta")

    def test_duplicate_entities(self):
        """Test conversion when ThreatrFeed contains duplicate entities (same id)."""
        entity = ThreatrEntity(
            name="Duplicate",
            type=ObservableTypes.by_short_name("IPV4"),
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        )
        # Duplicate entity with same id but different name
        entity_dup = ThreatrEntity(
            id=entity.id,
            name="Duplicate2",
            type=ObservableTypes.by_short_name("IPV4"),
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        )
        threatr_feed = ThreatrFeed(root_entity=entity, entities=[entity, entity_dup], relations=[], events=[])
        colander_mapper = ThreatrToColanderMapper()
        colander_feed = colander_mapper.convert(threatr_feed)
        # Should only contain one entity for the id
        self.assertEqual(len(colander_feed.entities), 1)
        self.assertIn(str(entity.id), colander_feed.entities)
        # Name should be from the first occurrence
        self.assertEqual(colander_feed.entities[str(entity.id)].name, "Duplicate")

    def test_circular_relations(self):
        """Test conversion of circular relations between entities."""
        entity_a = ThreatrEntity(
            name="A",
            type=ObservableTypes.by_short_name("IPV4"),
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        )
        entity_b = ThreatrEntity(
            name="B",
            type=ObservableTypes.by_short_name("IPV4"),
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        )
        relation_ab = ThreatrEntityRelation(
            name="points to",
            obj_from=entity_a,
            obj_to=entity_b,
        )
        relation_ba = ThreatrEntityRelation(
            name="points to",
            obj_from=entity_b,
            obj_to=entity_a,
        )
        threatr_feed = ThreatrFeed(root_entity=entity_a, entities=[entity_a, entity_b],
                                   relations=[relation_ab, relation_ba], events=[])
        colander_mapper = ThreatrToColanderMapper()
        colander_feed = colander_mapper.convert(threatr_feed)
        self.assertEqual(len(colander_feed.entities), 2)
        self.assertEqual(len(colander_feed.relations), 2)
        rel_names = [rel.name for rel in colander_feed.relations.values()]
        self.assertEqual(rel_names.count("points to"), 2)

    def test_missing_attributes(self):
        """Test conversion of entity with missing optional attributes."""
        entity = ThreatrEntity(
            name="NoAttrs",
            type=ObservableTypes.by_short_name("IPV4"),
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
            attributes=None,
        )
        threatr_feed = ThreatrFeed(root_entity=entity, entities=[entity], relations=[], events=[])
        colander_mapper = ThreatrToColanderMapper()
        colander_feed = colander_mapper.convert(threatr_feed)
        self.assertIn(str(entity.id), colander_feed.entities)
        self.assertEqual(colander_feed.entities[str(entity.id)].name, "NoAttrs")

    def test_invalid_entity_type(self):
        """Test conversion of entity with completely invalid type."""

        class InvalidType:
            short_name = None

        with pytest.raises(ValidationError):
            entity = ThreatrEntity(
                name="InvalidType",
                type=InvalidType,
                super_type=CommonEntitySuperTypes.OBSERVABLE.value,
            )

    def test_invalid_feed_input(self):
        """Test conversion with invalid input type (not a ThreatrFeed)."""
        colander_mapper = ThreatrToColanderMapper()
        with self.assertRaises(AssertionError):
            colander_mapper.convert(None)
