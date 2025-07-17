import pytest
from pydantic import ValidationError

from colander_data_converter.base.models import (
    Artifact,
    Device,
    ArtifactTypes,
    DeviceTypes,
)


class TestArtifact:
    def test_creates_artifact_with_minimal_fields(self):
        artifact_type = ArtifactTypes.enum.REPORT.value
        artifact = Artifact(name="sample.pdf", type=artifact_type)
        assert artifact.name == "sample.pdf"
        assert artifact.type == artifact_type
        assert artifact.size_in_bytes == 0

    def test_creates_artifact_with_all_fields(self):
        artifact_type = ArtifactTypes.enum.REPORT.value
        device_type = DeviceTypes.enum.LAPTOP.value
        device = Device(name="Analyst Laptop", type=device_type)
        artifact = Artifact(
            name="malware_sample.pdf",
            type=artifact_type,
            extracted_from=device,
            extension="pdf",
            original_name="invoice.pdf",
            mime_type="application/pdf",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            size_in_bytes=12345,
            attributes={"source": "email"},
        )
        assert artifact.extension == "pdf"
        assert artifact.size_in_bytes == 12345
        assert artifact.extracted_from == device
        assert artifact.attributes["source"] == "email"

    def test_fails_when_name_is_missing(self):
        artifact_type = ArtifactTypes.enum.REPORT.value
        with pytest.raises(ValidationError):
            Artifact(type=artifact_type)

    def test_fails_when_type_is_missing(self):
        with pytest.raises(ValidationError):
            Artifact(name="sample.pdf")

    def test_fails_when_size_is_negative(self):
        artifact_type = ArtifactTypes.enum.REPORT.value
        with pytest.raises(ValidationError):
            Artifact(name="sample.pdf", type=artifact_type, size_in_bytes=-1)

    def test_allows_optional_fields_to_be_none(self):
        artifact_type = ArtifactTypes.enum.REPORT.value
        artifact = Artifact(name="sample.pdf", type=artifact_type)
        assert artifact.extracted_from is None
        assert artifact.extension is None
        assert artifact.original_name is None
        assert artifact.mime_type is None
        assert artifact.md5 is None
        assert artifact.sha1 is None
        assert artifact.sha256 is None

    def test_mime_types(self):
        mimetypes = {
            "application/pdf": ArtifactTypes.enum.DOCUMENT.value,
            "audio/ogg": ArtifactTypes.enum.AUDIO.value,
            "application/zip": ArtifactTypes.enum.ARCHIVE.value,
            "application/x-tar": ArtifactTypes.enum.ARCHIVE.value,
            "application/gzip": ArtifactTypes.enum.ARCHIVE.value,
            "application/x-7z-compressed": ArtifactTypes.enum.ARCHIVE.value,
            "application/vnd.rar": ArtifactTypes.enum.ARCHIVE.value,
            "message/rfc822": ArtifactTypes.enum.EMAIL.value,
            "application/vnd.ms-outlook": ArtifactTypes.enum.EMAIL.value,
            "application/vnd.android.package-archive": ArtifactTypes.enum.ANDROID_SAMPLE.value,
            "image/jpeg": ArtifactTypes.enum.IMAGE.value,
            "image/png": ArtifactTypes.enum.IMAGE.value,
            "video/mp4": ArtifactTypes.enum.VIDEO.value,
            "text/html": ArtifactTypes.enum.WEBPAGE.value,
            "application/json": ArtifactTypes.enum.JSON.value,
            "text/plain": ArtifactTypes.enum.TEXT.value,
        }
        for mimetype, expected in mimetypes.items():
            computed = ArtifactTypes.by_mime_type(mimetype)
            assert expected is computed

    def test_unsupported_mime_types_map_to_generic(self):
        # Test that unsupported MIME types map to the GENERIC artifact type
        unsupported_mimetypes = [
            "application/x-unsupported",
            "application/vnd.unknown-format",
            "application/custom",
            "text/x-custom",
            "chemical/x-pdb",
            "application/vnd.lotus-wordpro",
            "model/x3d+xml",
            "application/x-shockwave-flash",
            None,  # Test with None value
            "",  # Test with empty string
        ]

        for mimetype in unsupported_mimetypes:
            computed = ArtifactTypes.by_mime_type(mimetype)
            assert computed is ArtifactTypes.enum.GENERIC.value
