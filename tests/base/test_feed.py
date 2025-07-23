import json
from importlib import resources
from uuid import UUID

import pytest

from colander_data_converter.base.common import TlpPapLevel
from colander_data_converter.base.models import (
    ColanderFeed,
    Observable,
    EntityRelation,
    Case,
    ObservableTypes,
)


class TestFeed:
    def test_loads_entity_feed_with_minimal_entities(self):
        ot = ObservableTypes.enum.IPV4.value
        obs = Observable(name="1.2.3.4", type=ot)
        feed = ColanderFeed(entities={str(obs.id): obs})
        assert str(obs.id) in feed.entities
        assert feed.entities[str(obs.id)].name == "1.2.3.4"

    def test_loads_entity_feed_with_relations_and_cases(self):
        ot = ObservableTypes.enum.IPV4.value
        obs1 = Observable(name="1.1.1.1", type=ot)
        obs2 = Observable(name="8.8.8.8", type=ot)
        case = Case(name="Case X", description="desc")
        rel = EntityRelation(name="rel", obj_from=obs1, obj_to=obs2, case=case)
        feed = ColanderFeed(
            entities={str(obs1.id): obs1, str(obs2.id): obs2},
            relations={str(rel.id): rel},
            cases={str(case.id): case},
        )
        assert str(rel.id) in feed.relations
        assert feed.relations[str(rel.id)].obj_from == obs1
        assert str(case.id) in feed.cases
        assert feed.cases[str(case.id)].name == "Case X"

    def test_load_method_handles_missing_ids(self):
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
                    "obj_to_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                }
            },
            "cases": {},
        }
        with pytest.raises(ValueError):
            ColanderFeed.load(raw)

    def test_load_method_success(self):
        raw = {
            "entities": {
                "81afaa00-d67c-4805-b66e-53371a6ce7cc": {
                    "id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                    "name": "obs",
                    "tlp": "RED",
                    "type": {"name": "IP v4 address", "short_name": "IPV4"},
                    "super_type": {"short_name": "observable"},
                }
            },
            "relations": {
                "5f35ceeb-52c9-4244-88fb-043b3e4c8aae": {
                    "id": "5f35ceeb-52c9-4244-88fb-043b3e4c8aae",
                    "name": "rel",
                    "obj_from_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                    "obj_to_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                }
            },
            "cases": {},
        }
        feed = ColanderFeed.load(raw)
        d = feed.model_dump()
        assert d["entities"]["81afaa00-d67c-4805-b66e-53371a6ce7cc"]["tlp"] == "RED"
        assert feed.entities["81afaa00-d67c-4805-b66e-53371a6ce7cc"].tlp == TlpPapLevel.RED
        assert "81afaa00-d67c-4805-b66e-53371a6ce7cc" in feed.entities
        assert "5f35ceeb-52c9-4244-88fb-043b3e4c8aae" in feed.relations
        assert (
            feed.relations["5f35ceeb-52c9-4244-88fb-043b3e4c8aae"].obj_from
            == feed.entities["81afaa00-d67c-4805-b66e-53371a6ce7cc"]
        )
        assert (
            feed.relations["5f35ceeb-52c9-4244-88fb-043b3e4c8aae"].obj_to
            == feed.entities["81afaa00-d67c-4805-b66e-53371a6ce7cc"]
        )

    def test_load_method_missing_entity(self):
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
                    "obj_to_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                }
            },
            "cases": {},
        }
        feed = ColanderFeed.load(raw)
        assert "81afaa00-d67c-4805-b66e-53371a6ce7cc" in feed.entities
        assert "5f35ceeb-52c9-4244-88fb-043b3e4c8aae" in feed.relations
        assert feed.relations["5f35ceeb-52c9-4244-88fb-043b3e4c8aae"].obj_from == UUID(
            "81afaa00-d67c-4805-b66e-53371a6ce7cd"
        )
        assert (
            feed.relations["5f35ceeb-52c9-4244-88fb-043b3e4c8aae"].obj_to
            == feed.entities["81afaa00-d67c-4805-b66e-53371a6ce7cc"]
        )

    def test_load_method_mismatching_ids(self):
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
                    "obj_to_id": "81afaa00-d67c-4805-b66e-53371a6ce7cc",
                }
            },
            "cases": {},
        }
        with pytest.raises(ValueError):
            ColanderFeed.load(raw)

    def test_load(self):
        resource_package = __name__
        json_file = resources.files(resource_package).joinpath("data").joinpath("colander_feed.json")
        with json_file.open() as f:
            raw = json.load(f)
            feed = ColanderFeed.load(raw)
            feed.unlink_references()
            feed.resolve_references()

    def test_unlink_references_replaces_objects_with_ids(self):
        ot = ObservableTypes.enum.IPV4.value
        obs1 = Observable(name="1.1.1.1", type=ot)
        obs2 = Observable(name="8.8.8.8", type=ot)
        rel = EntityRelation(name="rel", obj_from=obs1, obj_to=obs2)
        feed = ColanderFeed(
            entities={str(obs1.id): obs1, str(obs2.id): obs2},
            relations={str(rel.id): rel},
        )
        feed.unlink_references()
        assert isinstance(feed.relations[str(rel.id)].obj_from, type(obs1.id))
        assert isinstance(feed.relations[str(rel.id)].obj_to, type(obs2.id))

    def test_handles_empty_feed_gracefully(self):
        feed = ColanderFeed()
        assert feed.entities == {}
        assert feed.relations == {}
        assert feed.cases == {}

    def test_filter_by_maximum_tlp_level_includes_lower_or_equal(self):
        from colander_data_converter.base.models import ColanderFeed, Observable, ObservableTypes
        from colander_data_converter.base.common import TlpPapLevel

        ot = ObservableTypes.enum.IPV4.value
        obs_red = Observable(name="1.1.1.1", type=ot, tlp=TlpPapLevel.RED)
        obs_amber = Observable(name="2.2.2.2", type=ot, tlp=TlpPapLevel.AMBER)
        obs_green = Observable(name="3.3.3.3", type=ot, tlp=TlpPapLevel.GREEN)
        obs_white = Observable(name="4.4.4.4", type=ot, tlp=TlpPapLevel.WHITE)
        feed = ColanderFeed(
            entities={
                str(obs_red.id): obs_red,
                str(obs_amber.id): obs_amber,
                str(obs_green.id): obs_green,
                str(obs_white.id): obs_white,
            }
        )
        filtered = feed.filter(maximum_tlp_level=TlpPapLevel.AMBER)
        tlps = [e.tlp for e in filtered.entities.values()]
        assert TlpPapLevel.RED not in tlps
        assert TlpPapLevel.AMBER not in tlps
        assert TlpPapLevel.GREEN in tlps
        assert TlpPapLevel.WHITE in tlps
        assert len(filtered.entities) == 2

    def test_filter_by_maximum_tlp_level_includes_exact_match(self):
        from colander_data_converter.base.models import ColanderFeed, Observable, ObservableTypes
        from colander_data_converter.base.common import TlpPapLevel

        ot = ObservableTypes.enum.IPV4.value
        obs_green = Observable(name="3.3.3.3", type=ot, tlp=TlpPapLevel.GREEN)
        obs_white = Observable(name="4.4.4.4", type=ot, tlp=TlpPapLevel.WHITE)
        feed = ColanderFeed(
            entities={
                str(obs_green.id): obs_green,
                str(obs_white.id): obs_white,
            }
        )
        filtered = feed.filter(maximum_tlp_level=TlpPapLevel.AMBER)
        assert len(filtered.entities) == 2
        assert all(e.tlp.value <= TlpPapLevel.GREEN.value for e in filtered.entities.values())

    def test_filter_by_maximum_tlp_level_returns_empty_if_none_match(self):
        from colander_data_converter.base.models import ColanderFeed, Observable, ObservableTypes
        from colander_data_converter.base.common import TlpPapLevel

        ot = ObservableTypes.enum.IPV4.value
        obs_red = Observable(name="1.1.1.1", type=ot, tlp=TlpPapLevel.RED)
        obs_amber = Observable(name="2.2.2.2", type=ot, tlp=TlpPapLevel.AMBER)
        feed = ColanderFeed(
            entities={
                str(obs_red.id): obs_red,
                str(obs_amber.id): obs_amber,
            }
        )
        filtered = feed.filter(maximum_tlp_level=TlpPapLevel.GREEN)
        assert filtered.entities == {}

    def test_filter_with_relations_by_maximum_tlp_level(self):
        from colander_data_converter.base.models import ColanderFeed, Observable, EntityRelation, ObservableTypes
        from colander_data_converter.base.common import TlpPapLevel

        ot = ObservableTypes.enum.IPV4.value
        obs_red = Observable(name="1.1.1.1", type=ot, tlp=TlpPapLevel.RED)
        obs_green = Observable(name="3.3.3.3", type=ot, tlp=TlpPapLevel.GREEN)
        obs_white = Observable(name="4.4.4.4", type=ot, tlp=TlpPapLevel.WHITE)
        rel1 = EntityRelation(name="rel1", obj_from=obs_red, obj_to=obs_green)
        rel2 = EntityRelation(name="rel2", obj_from=obs_green, obj_to=obs_white)
        feed = ColanderFeed(
            entities={
                str(obs_red.id): obs_red,
                str(obs_green.id): obs_green,
                str(obs_white.id): obs_white,
            },
            relations={
                str(rel1.id): rel1,
                str(rel2.id): rel2,
            },
        )
        filtered = feed.filter(maximum_tlp_level=TlpPapLevel.AMBER)
        assert str(obs_red.id) not in filtered.entities
        assert str(obs_green.id) in filtered.entities
        assert str(obs_white.id) in filtered.entities
        assert str(rel2.id) in filtered.relations
        assert str(rel1.id) not in filtered.relations

    def test_filter_with_relations_all_entities_removed(self):
        from colander_data_converter.base.models import ColanderFeed, Observable, EntityRelation, ObservableTypes
        from colander_data_converter.base.common import TlpPapLevel

        ot = ObservableTypes.enum.IPV4.value
        obs_red = Observable(name="1.1.1.1", type=ot, tlp=TlpPapLevel.RED)
        obs_amber = Observable(name="2.2.2.2", type=ot, tlp=TlpPapLevel.AMBER)
        rel = EntityRelation(name="rel", obj_from=obs_red, obj_to=obs_amber)
        feed = ColanderFeed(
            entities={
                str(obs_red.id): obs_red,
                str(obs_amber.id): obs_amber,
            },
            relations={
                str(rel.id): rel,
            },
        )
        filtered = feed.filter(maximum_tlp_level=TlpPapLevel.GREEN)
        assert filtered.entities == {}
        assert filtered.relations == {}

    def test_filter_with_relations_partial_entity_removal(self):
        from colander_data_converter.base.models import ColanderFeed, Observable, EntityRelation, ObservableTypes
        from colander_data_converter.base.common import TlpPapLevel

        ot = ObservableTypes.enum.IPV4.value
        obs_green = Observable(name="3.3.3.3", type=ot, tlp=TlpPapLevel.GREEN)
        obs_white = Observable(name="4.4.4.4", type=ot, tlp=TlpPapLevel.WHITE)
        obs_red = Observable(name="1.1.1.1", type=ot, tlp=TlpPapLevel.RED)
        rel1 = EntityRelation(name="rel1", obj_from=obs_green, obj_to=obs_white)
        rel2 = EntityRelation(name="rel2", obj_from=obs_green, obj_to=obs_red)
        feed = ColanderFeed(
            entities={
                str(obs_green.id): obs_green,
                str(obs_white.id): obs_white,
                str(obs_red.id): obs_red,
            },
            relations={
                str(rel1.id): rel1,
                str(rel2.id): rel2,
            },
        )
        filtered = feed.filter(maximum_tlp_level=TlpPapLevel.AMBER)
        assert str(rel1.id) in filtered.relations
        assert str(rel2.id) not in filtered.relations
        assert str(obs_green.id) in filtered.entities
        assert str(obs_white.id) in filtered.entities
        assert str(obs_red.id) not in filtered.entities
