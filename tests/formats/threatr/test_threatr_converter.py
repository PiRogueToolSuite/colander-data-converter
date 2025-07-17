import json
import unittest
from importlib import resources
from typing import cast, List

from pydantic import BaseModel

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
