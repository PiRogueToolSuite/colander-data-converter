import json
from uuid import uuid4, UUID
from importlib import resources

import pytest

from colander_data_converter.base.models import EntityFeed, Observable, ObservableType, EntityRelation, Case


def test_loads_entity_feed_with_minimal_entities():
    ot = ObservableType(id=uuid4(), short_name='IPV4', name='IP v4 address')
    obs = Observable(name='1.2.3.4', type=ot)
    feed = EntityFeed(entities={str(obs.id): obs})
    assert str(obs.id) in feed.entities
    assert feed.entities[str(obs.id)].name == '1.2.3.4'


def test_loads_entity_feed_with_relations_and_cases():
    ot = ObservableType(id=uuid4(), short_name='IPV4', name='IP v4 address')
    obs1 = Observable(name='1.1.1.1', type=ot)
    obs2 = Observable(name='8.8.8.8', type=ot)
    case = Case(name='Case X', description='desc')
    rel = EntityRelation(name='rel', obj_from=obs1, obj_to=obs2, case=case)
    feed = EntityFeed(
        entities={str(obs1.id): obs1, str(obs2.id): obs2},
        relations={str(rel.id): rel},
        cases={str(case.id): case}
    )
    assert str(rel.id) in feed.relations
    assert feed.relations[str(rel.id)].obj_from == obs1
    assert str(case.id) in feed.cases
    assert feed.cases[str(case.id)].name == 'Case X'


def test_load_method_handles_missing_ids():
    raw = {
        "entities": {
            "81afaa00-d67c-4805-b66e-53371a6ce7cc": {
                "ixd": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                "name": "obs",
                "type": {"name": "IP v4 address", "short_name": "IPV4"},
                "super_type": {"short_name": "observable"},
            }
        },
        "relations": {
            "5f35ceeb-52c9-4244-88fb-043b3e4c8aae": {
                "ixd": "5f35ceeb-52c9-4244-88fb-043b3e4c8aae",
                "name": "rel",
                "obj_from_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                "obj_to_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc"
            }
        },
        "cases": {}
    }
    with pytest.raises(ValueError):
        EntityFeed.load(raw)


def test_load_method_success():
    raw = {
        "entities": {
            "81afaa00-d67c-4805-b66e-53371a6ce7cc": {
                "id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                "name": "obs",
                "type": {"name": "IP v4 address", "short_name": "IPV4"},
                "super_type": {"short_name": "observable"},
            }
        },
        "relations": {
            "5f35ceeb-52c9-4244-88fb-043b3e4c8aae": {
                "id": "5f35ceeb-52c9-4244-88fb-043b3e4c8aae",
                "name": "rel",
                "obj_from_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                "obj_to_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc"
            }
        },
        "cases": {}
    }
    feed = EntityFeed.load(raw)
    assert "81afaa00-d67c-4805-b66e-53371a6ce7cc" in feed.entities
    assert "5f35ceeb-52c9-4244-88fb-043b3e4c8aae" in feed.relations
    assert feed.relations["5f35ceeb-52c9-4244-88fb-043b3e4c8aae"].obj_from == feed.entities[
        "81afaa00-d67c-4805-b66e-53371a6ce7cc"]
    assert feed.relations["5f35ceeb-52c9-4244-88fb-043b3e4c8aae"].obj_to == feed.entities[
        "81afaa00-d67c-4805-b66e-53371a6ce7cc"]


def test_load_method_missing_entity():
    raw = {
        "entities": {
            "81afaa00-d67c-4805-b66e-53371a6ce7cc": {
                "id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                "name": "obs",
                "type": {"name": "IP v4 address", "short_name": "IPV4"},
                "super_type": {"short_name": "observable"},
            }
        },
        "relations": {
            "5f35ceeb-52c9-4244-88fb-043b3e4c8aae": {
                "id": "5f35ceeb-52c9-4244-88fb-043b3e4c8aae",
                "name": "rel",
                "obj_from_id": "81afaa00-d67c-4805-b66e-53371a6ce7cd",
                "obj_to_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc"
            }
        },
        "cases": {}
    }
    feed = EntityFeed.load(raw)
    assert "81afaa00-d67c-4805-b66e-53371a6ce7cc" in feed.entities
    assert "5f35ceeb-52c9-4244-88fb-043b3e4c8aae" in feed.relations
    assert feed.relations["5f35ceeb-52c9-4244-88fb-043b3e4c8aae"].obj_from == UUID(
        '81afaa00-d67c-4805-b66e-53371a6ce7cd')
    assert feed.relations["5f35ceeb-52c9-4244-88fb-043b3e4c8aae"].obj_to == feed.entities[
        "81afaa00-d67c-4805-b66e-53371a6ce7cc"]


def test_load_method_mismatching_ids():
    raw = {
        "entities": {
            "81afaa00-d67c-4805-b66e-53371a6ce7cd": {
                "id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                "name": "obs",
                "type": {"name": "IP v4 address", "short_name": "IPV4"},
                "super_type": {"short_name": "observable"},
            }
        },
        "relations": {
            "5f35ceeb-52c9-4244-88fb-043b3e4c8aae": {
                "id": "5f35ceeb-52c9-4244-88fb-043b3e4c8aae",
                "name": "rel",
                "obj_from_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                "obj_to_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc"
            }
        },
        "cases": {}
    }
    with pytest.raises(ValueError):
        EntityFeed.load(raw)


def test_load():
    resource_package = __name__
    json_file = resources.files(resource_package).joinpath('data').joinpath('colander_feed.json')
    with json_file.open() as f:
        raw = json.load(f)
        feed = EntityFeed.load(raw)
        feed.unlink_references()
        feed.resolve_references()


def test_unlink_references_replaces_objects_with_ids():
    ot = ObservableType(id=uuid4(), short_name='IPV4', name='IP v4 address')
    obs1 = Observable(name='1.1.1.1', type=ot)
    obs2 = Observable(name='8.8.8.8', type=ot)
    rel = EntityRelation(name='rel', obj_from=obs1, obj_to=obs2)
    feed = EntityFeed(entities={str(obs1.id): obs1, str(obs2.id): obs2}, relations={str(rel.id): rel})
    feed.unlink_references()
    assert isinstance(feed.relations[str(rel.id)].obj_from, type(obs1.id))
    assert isinstance(feed.relations[str(rel.id)].obj_to, type(obs2.id))


def test_handles_empty_feed_gracefully():
    feed = EntityFeed()
    assert feed.entities == {}
    assert feed.relations == {}
    assert feed.cases == {}
