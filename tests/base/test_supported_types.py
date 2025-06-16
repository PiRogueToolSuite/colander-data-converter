import pytest
from pydantic import ValidationError

from colander_data_converter.base.models import (
    ArtifactType,
    ArtifactTypes,
    ObservableType,
    ObservableTypes,
    ThreatType,
    ThreatTypes,
    ActorType,
    ActorTypes,
    DeviceType,
    DeviceTypes,
    EventType,
    EventTypes,
    DetectionRuleType,
    DetectionRuleTypes,
    DataFragmentType,
    DataFragmentTypes,
)


class TestArtifactTypes:
    def test_artifact_type_valid_creation(self):
        artifact_type = ArtifactType(
            short_name="REPORT", name="Report", description="A report artifact"
        )
        assert artifact_type.short_name == "REPORT"
        assert artifact_type.name == "Report"
        assert artifact_type.description == "A report artifact"

    def test_artifact_type_invalid_short_name(self):
        with pytest.raises(ValidationError) as exc_info:
            ArtifactType(
                short_name="INVALID_TYPE", name="Invalid", description="Invalid type"
            )
        assert "is not supported" in str(exc_info.value)

    def test_artifact_types_enum_contains_expected_types(self):
        # Test that common artifact types are present in the enum
        expected_types = {"REPORT", "BINARY", "PCAP", "OTHER"}
        enum_types = set(ArtifactTypes.enum._member_names_)
        assert expected_types.issubset(enum_types)

    def test_artifact_types_by_short_name(self):
        # Test finding type by short name
        artifact_type = ArtifactTypes.by_short_name("REPORT")
        assert artifact_type is not None
        assert isinstance(artifact_type, ArtifactType)
        assert artifact_type.short_name == "REPORT"

    def test_artifact_types_by_short_name_invalid(self):
        # Test that invalid short name returns None
        artifact_type = ArtifactTypes.by_short_name("NONEXISTENT")
        assert artifact_type is ArtifactTypes.default

    def test_artifact_types_case_insensitive(self):
        # Test that case is properly handled
        artifact_type = ArtifactTypes.by_short_name("report")
        assert artifact_type is not None
        assert artifact_type.short_name == "REPORT"

    def test_artifact_types_space_handling(self):
        # Test that spaces are properly handled in short names
        artifact_type = ArtifactTypes.by_short_name("network trace")
        assert artifact_type == ArtifactTypes.by_short_name("NETWORK_TRACE")


class TestObservableTypes:
    def test_observable_type_valid_creation(self):
        observable_type = ObservableType(
            short_name="IPV4", name="IP Address", description="An IP address observable"
        )
        assert observable_type.short_name == "IPV4"
        assert observable_type.name == "IP Address"
        assert observable_type.description == "An IP address observable"

    def test_observable_type_invalid_short_name(self):
        with pytest.raises(ValidationError) as exc_info:
            ObservableType(
                short_name="INVALID_TYPE", name="Invalid", description="Invalid type"
            )
        assert "is not supported" in str(exc_info.value)

    def test_observable_types_enum_contains_expected_types(self):
        expected_types = {"IPV4", "DOMAIN", "URL", "EMAIL"}
        enum_types = set(ObservableTypes.enum._member_names_)
        assert expected_types.issubset(enum_types)


class TestThreatTypes:
    def test_threat_type_valid_creation(self):
        threat_type = ThreatType(
            short_name="MALWARE", name="Malware", description="A malware threat"
        )
        assert threat_type.short_name == "MALWARE"
        assert threat_type.name == "Malware"
        assert threat_type.description == "A malware threat"

    def test_threat_type_invalid_short_name(self):
        with pytest.raises(ValidationError) as exc_info:
            ThreatType(
                short_name="INVALID_THREAT", name="Invalid", description="Invalid type"
            )
        assert "is not supported" in str(exc_info.value)

    def test_threat_types_enum_contains_expected_types(self):
        expected_types = {"MALWARE", "TROJAN", "STALKERWARE", "GENERIC"}
        enum_types = set(ThreatTypes.enum._member_names_)
        assert expected_types.issubset(enum_types)


def test_cross_type_validation():
    """Test that types from different categories don't interfere with each other"""
    # Valid types in their respective categories
    artifact = ArtifactType(short_name="REPORT", name="Report", description="A report")
    observable = ObservableType(
        short_name="IPV4", name="IP Address", description="An IP address"
    )
    threat = ThreatType(short_name="MALWARE", name="Malware", description="A malware")

    # Verify that valid types in one category are not valid in others
    with pytest.raises(ValidationError):
        ArtifactType(short_name="IP", name="IP Address", description="Should fail")

    with pytest.raises(ValidationError):
        ObservableType(short_name="REPORT", name="Report", description="Should fail")

    with pytest.raises(ValidationError):
        ThreatType(short_name="IP", name="IP Address", description="Should fail")


def test_all_type_classes_have_default():
    """Test that all type classes have a default value defined"""
    type_classes = [
        ArtifactTypes,
        ObservableTypes,
        ThreatTypes,
        ActorTypes,
        DeviceTypes,
        EventTypes,
        DetectionRuleTypes,
        DataFragmentTypes,
    ]

    for type_class in type_classes:
        assert hasattr(type_class, "default"), (
            f"{type_class.__name__} missing default value"
        )
        assert type_class.default is not None
        assert isinstance(
            type_class.default,
            (
                ArtifactType,
                ObservableType,
                ThreatType,
                ActorType,
                DeviceType,
                EventType,
                DetectionRuleType,
                DataFragmentType,
            ),
        )


def test_type_enums_unique_values():
    """Test that all enum values within each type class are unique"""
    type_classes = [
        ArtifactTypes,
        ObservableTypes,
        ThreatTypes,
        ActorTypes,
        DeviceTypes,
        EventTypes,
        DetectionRuleTypes,
        DataFragmentTypes,
    ]

    for type_class in type_classes:
        enum_values = list(type_class.enum._member_names_)
        unique_values = set(enum_values)
        assert len(enum_values) == len(unique_values), (
            f"Duplicate values found in {type_class.__name__}"
        )


def test_by_short_name_consistency():
    """Test that by_short_name method works consistently across all type classes"""
    type_classes = [
        (ArtifactTypes, "REPORT"),
        (ObservableTypes, "IPV4"),
        (ThreatTypes, "MALWARE"),
        (ActorTypes, "INDIVIDUAL"),
        (DeviceTypes, "LAPTOP"),
        (EventTypes, "ALERT"),
        (DetectionRuleTypes, "YARA"),
        (DataFragmentTypes, "CODE"),
    ]

    for type_class, valid_type in type_classes:
        # Test valid type
        result = type_class.by_short_name(valid_type)
        assert result is not None
        assert result.short_name == valid_type

        # Test invalid type
        assert type_class.by_short_name("NONEXISTENT") is type_class.default

        # Test case insensitivity
        assert type_class.by_short_name(valid_type.lower()) is not None
