from datetime import datetime, UTC, timedelta

import pytest
from pydantic import ValidationError

from colander_data_converter.base.models import (
    EntityRelation,
    Observable,
    Case,
    Artifact,
    DetectionRule,
    Device,
    Event,
)
from colander_data_converter.base.types.artifact import *
from colander_data_converter.base.types.detection_rule import *
from colander_data_converter.base.types.device import *
from colander_data_converter.base.types.event import *
from colander_data_converter.base.types.observable import *


class TestEntityRelation:
    def test_creates_entity_relation_with_minimal_fields(self):
        obs_type = ObservableType(short_name="IPV4", name="IP v4 address")
        obs1 = Observable(name="1.1.1.1", type=obs_type)
        obs2 = Observable(name="8.8.8.8", type=obs_type)
        relation = EntityRelation(name="connection", obj_from=obs1, obj_to=obs2)
        assert relation.name == "connection"
        assert relation.obj_from == obs1
        assert relation.obj_to == obs2
        assert relation.attributes is None
        assert relation.case is None

    def test_creates_entity_relation_with_all_fields(self):
        obs_type = ObservableType(short_name="IPV4", name="IP v4 address")
        obs1 = Observable(name="1.1.1.1", type=obs_type)
        obs2 = Observable(name="8.8.8.8", type=obs_type)
        case = Case(name="Case 1", description="desc")
        relation = EntityRelation(
            name="related",
            obj_from=obs1,
            obj_to=obs2,
            attributes={"key": "value"},
            case=case,
        )
        assert relation.attributes["key"] == "value"
        assert relation.case == case

    def test_fails_when_name_is_missing(self):
        obs_type = ObservableType(short_name="IPV4", name="IP v4 address")
        obs1 = Observable(name="1.1.1.1", type=obs_type)
        obs2 = Observable(name="8.8.8.8", type=obs_type)
        with pytest.raises(ValidationError):
            EntityRelation(obj_from=obs1, obj_to=obs2)

    def test_fails_when_obj_from_is_missing(self):
        obs_type = ObservableType(short_name="IPV4", name="IP v4 address")
        obs2 = Observable(name="8.8.8.8", type=obs_type)
        with pytest.raises(ValidationError):
            EntityRelation(name="rel", obj_to=obs2)

    def test_fails_when_obj_to_is_missing(self):
        obs_type = ObservableType(short_name="IPV4", name="IP v4 address")
        obs1 = Observable(name="1.1.1.1", type=obs_type)
        with pytest.raises(ValidationError):
            EntityRelation(name="rel", obj_from=obs1)

    def test_event_immutable_relations(self):
        event_type = EventTypes.HIT.value
        obs_type = ObservableTypes.IPV4.value
        obs = Observable(name="8.8.8.8", type=obs_type)
        artifact = Artifact(
            name="file.txt",
            type=ArtifactTypes.BINARY.value,
        )
        detection_rule = DetectionRule(
            name="Rule",
            type=DetectionRuleTypes.YARA.value,
            content="rule",
        )
        device = Device(
            name="Device",
            type=DeviceTypes.LAPTOP.value,
        )
        now = datetime.now(UTC)
        event = Event(
            name="Event 2",
            type=event_type,
            first_seen=now,
            last_seen=now + timedelta(minutes=5),
            count=3,
            extracted_from=artifact,
            observed_on=device,
            detected_by=detection_rule,
            involved_observables=[obs],
        )
        immutable_relations = event.get_immutable_relations()
        assert len(immutable_relations) == 4
