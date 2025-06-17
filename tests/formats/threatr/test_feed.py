import json
from datetime import datetime, timedelta, UTC
from importlib import resources
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from colander_data_converter.base.common import TlpPapLevel
from colander_data_converter.base.models import CommonEntitySuperTypes
from colander_data_converter.formats.threatr.models import (
    Entity,
    EntityRelation,
    Event,
    ThreatrRepository,
    ThreatrFeed,
)


@pytest.fixture
def clean_repository():
    """Provides a clean repository instance for each test"""
    repo = ThreatrRepository()
    repo.entities = {}
    repo.events = {}
    repo.relations = {}
    return repo


@pytest.fixture
def sample_entity():
    """Creates a sample entity for testing"""
    return Entity(
        name="Test Entity",
        type=CommonEntitySuperTypes.OBSERVABLE.value.types.DOMAIN.value,
        super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        description="Test description",
    )


@pytest.fixture
def sample_entities():
    """Creates two related entities for testing"""
    entity1 = Entity(
        name="Source Entity",
        type=CommonEntitySuperTypes.OBSERVABLE.value.types.DOMAIN.value,
        super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        description="Source entity for testing",
    )
    entity2 = Entity(
        name="Target Entity",
        type=CommonEntitySuperTypes.OBSERVABLE.value.types.DOMAIN.value,
        super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        description="Target entity for testing",
    )
    return entity1, entity2


@pytest.fixture
def sample_relation(sample_entities):
    """Creates a sample relation between two entities"""
    return EntityRelation(
        name="test_relation",
        description="Test relation",
        obj_from=sample_entities[0],
        obj_to=sample_entities[1],
    )


class TestThreatrRepository:
    def test_singleton_pattern(self):
        """Test that ThreatrRepository follows singleton pattern"""
        repo1 = ThreatrRepository()
        repo2 = ThreatrRepository()
        assert repo1 is repo2
        assert id(repo1) == id(repo2)

    def test_repository_initialization(self, clean_repository):
        """Test repository is initialized with empty collections"""
        assert isinstance(clean_repository.entities, dict)
        assert isinstance(clean_repository.events, dict)
        assert isinstance(clean_repository.relations, dict)
        assert len(clean_repository.entities) == 0
        assert len(clean_repository.events) == 0
        assert len(clean_repository.relations) == 0

    def test_entity_insertion(self, clean_repository, sample_entity):
        """Test inserting an entity into repository"""
        clean_repository << sample_entity
        assert str(sample_entity.id) in clean_repository.entities
        assert clean_repository.entities[str(sample_entity.id)] is sample_entity

    def test_relation_insertion(self, clean_repository, sample_relation):
        """Test inserting a relation into repository"""
        clean_repository << sample_relation
        assert str(sample_relation.id) in clean_repository.relations
        assert clean_repository.relations[str(sample_relation.id)] is sample_relation

    def test_event_insertion(self, clean_repository):
        """Test inserting an event into repository"""
        event = Event(
            name="Test Event",
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC) + timedelta(hours=1),
        )
        clean_repository << event
        assert str(event.id) in clean_repository.events
        assert clean_repository.events[str(event.id)] is event

    def test_object_retrieval(self, clean_repository, sample_entity):
        """Test retrieving objects from repository"""
        clean_repository << sample_entity
        retrieved = clean_repository >> sample_entity.id
        assert retrieved is sample_entity
        assert retrieved.id == sample_entity.id

    def test_nonexistent_object_retrieval(self, clean_repository):
        """Test retrieving non-existent object returns the ID"""
        random_id = uuid4()
        retrieved = clean_repository >> random_id
        assert retrieved == random_id


class TestEntity:
    def test_entity_creation_minimal(self):
        """Test creating entity with minimal required fields"""
        entity = Entity(
            name="Test Entity",
            type=CommonEntitySuperTypes.OBSERVABLE.value.types.DOMAIN.value,
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
        )
        assert isinstance(entity.id, UUID)
        assert entity.name == "Test Entity"
        assert entity.type == CommonEntitySuperTypes.OBSERVABLE.value.types.DOMAIN.value
        assert entity.super_type == CommonEntitySuperTypes.OBSERVABLE.value
        assert entity.tlp == TlpPapLevel.WHITE  # default value
        assert entity.pap == TlpPapLevel.WHITE  # default value

    def test_entity_creation_full(self):
        """Test creating entity with all fields"""
        entity = Entity(
            name="Full Test Entity",
            type=CommonEntitySuperTypes.OBSERVABLE.value.types.DOMAIN.value,
            super_type=CommonEntitySuperTypes.OBSERVABLE.value,
            description="Test description",
            pap=TlpPapLevel.RED,
            tlp=TlpPapLevel.RED,
            source_url="https://example.com",
            attributes={"key": "value"},
        )
        assert entity.description == "Test description"
        assert entity.pap == TlpPapLevel.RED
        assert entity.tlp == TlpPapLevel.RED
        assert str(entity.source_url) == "https://example.com"
        assert entity.attributes == {"key": "value"}

    def test_entity_name_validation(self):
        """Test entity name validation"""
        with pytest.raises(ValidationError):
            Entity(
                name="",  # Empty name should fail
                type=CommonEntitySuperTypes.OBSERVABLE.value.types.DOMAIN.value,
                super_type=CommonEntitySuperTypes.OBSERVABLE.value,
            )

        with pytest.raises(ValidationError):
            Entity(
                name="a" * 513,  # Name too long
                type=CommonEntitySuperTypes.OBSERVABLE.value.types.DOMAIN.value,
                super_type=CommonEntitySuperTypes.OBSERVABLE.value,
            )


class TestEntityRelation:
    def test_relation_creation(self, sample_entities):
        """Test creating relation between entities"""
        source, target = sample_entities
        relation = EntityRelation(name="test_relation", obj_from=source, obj_to=target)
        assert isinstance(relation.id, UUID)
        assert relation.name == "test_relation"
        assert relation.obj_from is source
        assert relation.obj_to is target

    def test_relation_reference_handling(self, sample_relation, clean_repository):
        """Test unlinking and resolving references in relations"""
        # Store entities in repository
        clean_repository << sample_relation.obj_from
        clean_repository << sample_relation.obj_to

        # Test unlinking
        sample_relation.unlink_references()
        assert isinstance(sample_relation.obj_from, UUID)
        assert isinstance(sample_relation.obj_to, UUID)

        # Test resolving
        sample_relation.resolve_references()
        assert isinstance(sample_relation.obj_from, Entity)
        assert isinstance(sample_relation.obj_to, Entity)


class TestEvent:
    def test_event_creation_minimal(self):
        """Test creating event with minimal required fields"""
        event = Event(name="Test Event")
        assert isinstance(event.id, UUID)
        assert event.name == "Test Event"
        assert event.count == 1
        assert isinstance(event.first_seen, datetime)
        assert isinstance(event.last_seen, datetime)

    def test_event_creation_full(self, sample_entity):
        """Test creating event with all fields"""
        now = datetime.now(UTC)
        event = Event(
            name="Full Test Event",
            description="Test description",
            first_seen=now,
            last_seen=now + timedelta(hours=1),
            count=5,
            involved_entity=sample_entity,
            attributes={"key": "value"},
        )
        assert event.description == "Test description"
        assert event.first_seen == now
        assert event.last_seen == now + timedelta(hours=1)
        assert event.count == 5
        assert event.involved_entity is sample_entity
        assert event.attributes == {"key": "value"}

    def test_event_date_validation(self):
        """Test event date validation"""
        now = datetime.now(UTC)
        with pytest.raises(ValueError, match="first_seen must be before last_seen"):
            Event(name="Invalid Event", first_seen=now + timedelta(hours=1), last_seen=now)


class TestThreatrFeed:
    def test_feed_creation(self, sample_entity):
        """Test creating feed with minimal configuration"""
        feed = ThreatrFeed(root_entity=sample_entity)
        assert feed.root_entity is sample_entity
        assert feed.entities == []
        assert feed.relations == []
        assert feed.events == []

    def test_feed_with_data(self, sample_entities, sample_relation):
        """Test creating feed with entities and relations"""
        source, target = sample_entities
        feed = ThreatrFeed(root_entity=source, entities=[source, target], relations=[sample_relation])
        assert feed.root_entity is source
        assert len(feed.entities) == 2
        assert len(feed.relations) == 1

    def test_feed_references(self, clean_repository, sample_entities, sample_relation):
        """Test feed reference handling"""
        source, target = sample_entities
        # Store entities in repository
        clean_repository << source
        clean_repository << target

        feed = ThreatrFeed(root_entity=source, entities=[source, target], relations=[sample_relation])

        # Test unlinking
        feed.unlink_references()
        assert isinstance(sample_relation.obj_from, UUID)
        assert isinstance(sample_relation.obj_to, UUID)

        # Test resolving
        feed.resolve_references()
        assert isinstance(sample_relation.obj_from, Entity)
        assert isinstance(sample_relation.obj_to, Entity)

    def test_feed_loading(self, sample_entities, sample_relation):
        """Test loading feed from raw data"""
        source, target = sample_entities
        raw_data = {
            "root_entity": source,
            "entities": [source, target],
            "relations": [sample_relation],
            "events": [],
        }
        feed = ThreatrFeed.load(raw_data)
        assert feed.root_entity == source
        assert len(feed.entities) == 2
        assert len(feed.relations) == 1
        assert len(feed.events) == 0


class TestLoadingThreatrFeedFromJSON:
    def test_load(self):
        resource_package = __name__
        json_file = resources.files(resource_package).joinpath("data").joinpath("threatr_feed.json")
        with json_file.open() as f:
            raw = json.load(f)
        feed = ThreatrFeed.load(raw)
        feed.unlink_references()
        feed.model_dump_json()
