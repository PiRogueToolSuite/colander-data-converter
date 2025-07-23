import uuid
from typing import Optional, Union

from pydantic import BaseModel

from colander_data_converter.base.common import ObjectReference
from colander_data_converter.base.utils import BaseModelMerger, MergingStrategy


class SourceModel(BaseModel):
    name: str
    age: int
    city: Optional[str] = None


class DestinationModel(BaseModel):
    name: str
    age: int
    city: Optional[str] = None
    country: Optional[str] = None


class ModelWithAttributes(BaseModel):
    name: str
    attributes: Optional[dict] = None


class ModelWithFrozenField(BaseModel):
    name: str
    frozen_field: str

    class Config:
        frozen = True


class ModelWithObjectReference(BaseModel):
    name: str
    reference: Optional[ObjectReference] = None


class TestMerger:
    def test_merge_overwrites_existing_fields_by_default(self):
        source = SourceModel(name="Alice", age=30)
        destination = DestinationModel(name="Bob", age=25)
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Alice"
        assert destination.age == 30
        assert unprocessed == ["city"]

    def test_merge_preserves_existing_fields_when_strategy_is_preserve(self):
        source = SourceModel(name="Alice", age=30)
        destination = DestinationModel(name="Bob", age=25)
        merger = BaseModelMerger(strategy=MergingStrategy.PRESERVE)

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Bob"
        assert destination.age == 25
        assert unprocessed == ["name", "age", "city"]

    def test_merge_handles_none_values_in_source(self):
        source = SourceModel(name="Alice", age=30, city=None)
        destination = DestinationModel(name="Bob", age=25, city="New York")
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Alice"
        assert destination.age == 30
        assert destination.city == "New York"
        assert unprocessed == ["city"]

    def test_merge_overwrites_none_values_in_destination(self):
        source = SourceModel(name="Alice", age=30, city="Boston")
        destination = DestinationModel(name="Bob", age=25, city=None)
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.city == "Boston"
        assert unprocessed == []

    def test_merge_adds_extra_fields_to_attributes_when_supported(self):
        source = SourceModel(name="Alice", age=30, city="Boston")
        destination = ModelWithAttributes(name="Bob", attributes={})
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Alice"
        assert destination.attributes["age"] == "30"
        assert destination.attributes["city"] == "Boston"
        assert unprocessed == []

    def test_merge_initializes_attributes_dict_when_none(self):
        source = SourceModel(name="Alice", age=30)
        destination = ModelWithAttributes(name="Bob", attributes=None)
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.attributes == {"age": "30"}
        assert unprocessed == ["city"]

    def test_merge_handles_source_with_extra_attributes(self):
        source = ModelWithAttributes(name="Alice", attributes={"key1": "value1", "key2": "value2"})
        destination = ModelWithAttributes(name="Bob", attributes={})
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Alice"
        assert destination.attributes["key1"] == "value1"
        assert destination.attributes["key2"] == "value2"
        assert unprocessed == []

    def test_merge_skips_object_reference_fields(self):
        source = ModelWithObjectReference(name="Alice", reference=uuid.uuid4())
        destination = ModelWithObjectReference(name="Bob", reference=None)
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Alice"
        assert destination.reference is None
        assert "reference" in unprocessed

    def test_merge_handles_type_mismatch(self):
        class TypeMismatchSource(BaseModel):
            name: str
            value: int

        class TypeMismatchDestination(BaseModel):
            name: str
            value: str

        source = TypeMismatchSource(name="Alice", value=42)
        destination = TypeMismatchDestination(name="Bob", value="test")
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Alice"
        assert destination.value == "test"
        assert "value" in unprocessed

    def test_merge_handles_union_types(self):
        class UnionSource(BaseModel):
            name: str
            value: Union[str, int]

        class UnionDestination(BaseModel):
            name: str
            value: Union[str, int]

        source = UnionSource(name="Alice", value="string_value")
        destination = UnionDestination(name="Bob", value=42)
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Alice"
        assert destination.value == "string_value"
        assert unprocessed == []

    def test_merge_returns_unprocessed_fields_for_missing_destination_fields(self):
        class ExtendedSource(BaseModel):
            name: str
            extra_field: str

        source = ExtendedSource(name="Alice", extra_field="value")
        destination = DestinationModel(name="Bob", age=25)
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Alice"
        assert "extra_field" in unprocessed

    def test_merge_handles_empty_source_attributes(self):
        source = ModelWithAttributes(name="Alice", attributes={})
        destination = ModelWithAttributes(name="Bob", attributes={})
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Alice"
        assert destination.attributes == {}
        assert unprocessed == ["attributes"]

    def test_merge_handles_source_without_attributes_support(self):
        source = SourceModel(name="Alice", age=30)
        destination = DestinationModel(name="Bob", age=25)
        merger = BaseModelMerger()

        unprocessed = merger.merge(source, destination)

        assert destination.name == "Alice"
        assert destination.age == 30
        assert unprocessed == ["city"]


def test_level_comparisons():
    from colander_data_converter.base.common import Level

    low = Level(code="LOW", name="Low", ordering_value=10)
    high = Level(code="HIGH", name="High", ordering_value=20)
    another_low = Level(code="LOW", name="Low", ordering_value=10)

    assert low < high
    assert high > low
    assert low <= another_low
    assert low >= another_low
    assert low == another_low
    assert low != high
    assert str(low) == "Low"


def test_tlp_pap_level_comparisons():
    from colander_data_converter.base.common import TlpPapLevel

    assert TlpPapLevel.RED.value > TlpPapLevel.AMBER.value
    assert TlpPapLevel.AMBER.value > TlpPapLevel.GREEN.value
    assert TlpPapLevel.GREEN.value > TlpPapLevel.WHITE.value
    assert TlpPapLevel.WHITE.value < TlpPapLevel.RED.value
    assert TlpPapLevel.RED == TlpPapLevel.by_name("RED")
    assert str(TlpPapLevel.RED) == "RED"
