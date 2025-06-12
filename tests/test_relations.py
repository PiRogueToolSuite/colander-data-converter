from uuid import uuid4

import pytest
from pydantic import ValidationError

from colander_data_converter.base.models import (
    EntityRelation,
    Observable,
    ObservableType,
    Case,
)


def test_creates_entity_relation_with_minimal_fields():
    obs_type = ObservableType(id=uuid4(), short_name="IPV4", name="IP v4 address")
    obs1 = Observable(name="1.1.1.1", type=obs_type)
    obs2 = Observable(name="8.8.8.8", type=obs_type)
    relation = EntityRelation(name="connection", obj_from=obs1, obj_to=obs2)
    assert relation.name == "connection"
    assert relation.obj_from == obs1
    assert relation.obj_to == obs2
    assert relation.attributes is None
    assert relation.case is None


def test_creates_entity_relation_with_all_fields():
    obs_type = ObservableType(id=uuid4(), short_name="IPV4", name="IP v4 address")
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


def test_fails_when_name_is_missing():
    obs_type = ObservableType(id=uuid4(), short_name="IPV4", name="IP v4 address")
    obs1 = Observable(name="1.1.1.1", type=obs_type)
    obs2 = Observable(name="8.8.8.8", type=obs_type)
    with pytest.raises(ValidationError):
        EntityRelation(obj_from=obs1, obj_to=obs2)


def test_fails_when_obj_from_is_missing():
    obs_type = ObservableType(id=uuid4(), short_name="IPV4", name="IP v4 address")
    obs2 = Observable(name="8.8.8.8", type=obs_type)
    with pytest.raises(ValidationError):
        EntityRelation(name="rel", obj_to=obs2)


def test_fails_when_obj_to_is_missing():
    obs_type = ObservableType(id=uuid4(), short_name="IPV4", name="IP v4 address")
    obs1 = Observable(name="1.1.1.1", type=obs_type)
    with pytest.raises(ValidationError):
        EntityRelation(name="rel", obj_from=obs1)
