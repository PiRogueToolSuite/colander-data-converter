from uuid import uuid4

import pytest
from pydantic import ValidationError

from colander_data_converter.base.models import Artifact, ArtifactType, Device, DeviceType


def test_creates_artifact_with_minimal_fields():
    artifact_type = ArtifactType(id=uuid4(), short_name='PDF', name='PDF document')
    artifact = Artifact(name='sample.pdf', type=artifact_type)
    assert artifact.name == 'sample.pdf'
    assert artifact.type == artifact_type
    assert artifact.size_in_bytes == 0


def test_creates_artifact_with_all_fields():
    artifact_type = ArtifactType(id=uuid4(), short_name='PDF', name='PDF document')
    device_type = DeviceType(id=uuid4(), short_name='LAPTOP', name='Laptop')
    device = Device(name='Analyst Laptop', type=device_type)
    artifact = Artifact(
        name='malware_sample.pdf',
        type=artifact_type,
        extracted_from=device,
        extension='pdf',
        original_name='invoice.pdf',
        mime_type='application/pdf',
        md5='d41d8cd98f00b204e9800998ecf8427e',
        sha1='da39a3ee5e6b4b0d3255bfef95601890afd80709',
        sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        size_in_bytes=12345,
        attributes={'source': 'email'}
    )
    assert artifact.extension == 'pdf'
    assert artifact.size_in_bytes == 12345
    assert artifact.extracted_from == device
    assert artifact.attributes['source'] == 'email'


def test_fails_when_name_is_missing():
    artifact_type = ArtifactType(id=uuid4(), short_name='PDF', name='PDF document')
    with pytest.raises(ValidationError):
        Artifact(type=artifact_type)


def test_fails_when_type_is_missing():
    with pytest.raises(ValidationError):
        Artifact(name='sample.pdf')


def test_fails_when_size_is_negative():
    artifact_type = ArtifactType(id=uuid4(), short_name='PDF', name='PDF document')
    with pytest.raises(ValidationError):
        Artifact(name='sample.pdf', type=artifact_type, size_in_bytes=-1)


def test_allows_optional_fields_to_be_none():
    artifact_type = ArtifactType(id=uuid4(), short_name='PDF', name='PDF document')
    artifact = Artifact(name='sample.pdf', type=artifact_type)
    assert artifact.extracted_from is None
    assert artifact.extension is None
    assert artifact.original_name is None
    assert artifact.mime_type is None
    assert artifact.md5 is None
    assert artifact.sha1 is None
    assert artifact.sha256 is None
    assert artifact.attributes is None
