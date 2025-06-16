from datetime import datetime, timedelta, UTC

import pytest

from colander_data_converter.base.models import (
    Event,
    Observable,
    Artifact,
    DetectionRule,
    Device,
    EventTypes,
    ObservableTypes,
    ArtifactTypes,
    DetectionRuleTypes,
    DeviceTypes,
)


class TestEvent:
    def test_creates_event_with_minimal_fields(self):
        event_type = EventTypes.enum.HIT.value
        event = Event(name="Event 1", type=event_type)
        assert event.name == "Event 1"
        assert event.type == event_type
        assert event.count == 1
        assert event.first_seen <= event.last_seen

    def test_creates_event_with_all_fields(self):
        event_type = EventTypes.enum.HIT.value
        obs_type = ObservableTypes.enum.IPV4.value
        obs = Observable(name="8.8.8.8", type=obs_type)
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
            involved_observables=[obs],
        )
        assert event.attributes["key"] == "value"
        assert event.count == 3
        assert event.extracted_from == artifact
        assert event.observed_on == device
        assert event.detected_by == detection_rule
        assert event.involved_observables[0] == obs

    def test_fails_when_first_seen_after_last_seen(self):
        event_type = EventTypes.enum.HIT.value
        now = datetime.now(UTC)
        with pytest.raises(ValueError):
            Event(
                name="Invalid Event",
                type=event_type,
                first_seen=now + timedelta(minutes=10),
                last_seen=now,
            )

    def test_allows_optional_fields_to_be_none(self):
        event_type = EventTypes.enum.HIT.value
        event = Event(name="Event 3", type=event_type)
        assert event.attributes is None
        assert event.extracted_from is None
        assert event.observed_on is None
        assert event.detected_by is None
        assert event.involved_observables is None
