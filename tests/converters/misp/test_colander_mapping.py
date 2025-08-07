import unittest

from colander_data_converter.base.models import Observable, Artifact
from colander_data_converter.base.types.artifact import ArtifactTypes
from colander_data_converter.base.types.observable import ObservableTypes
from colander_data_converter.converters.misp.converter import ColanderToMISPMapper


class TestColanderMapping(unittest.TestCase):
    def test_observable_mapping(self):
        obs_type = ObservableTypes.IPV4.value
        obs = Observable(name="8.8.8.8", type=obs_type, description="Test description")
        mapper = ColanderToMISPMapper()
        attr = mapper.convert_colander_object(obs)
        self.assertIsNotNone(attr)

    def test_observable_mappings(self):
        mapper = ColanderToMISPMapper()
        supported_types = mapper.mapping.super_types_mapping["OBSERVABLE"].get_supported_colander_types()
        for obs_type in ObservableTypes:
            if obs_type.value.short_name not in supported_types:
                continue
            obs = Observable(name="8.8.8.8", type=obs_type.value, description="Test description")
            attr = mapper.convert_colander_object(obs)
            self.assertIsNotNone(attr)

    def test_artifact_mapping(self):
        artifact_type = ArtifactTypes.DOCUMENT.value
        artifact = Artifact(
            name="malware_sample.pdf",
            type=artifact_type,
            extension="pdf",
            original_name="invoice.pdf",
            mime_type="application/pdf",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            size_in_bytes=12345,
            attributes={"source": "email"},
        )
        mapper = ColanderToMISPMapper()
        obj = mapper.convert_colander_object(artifact)
        j = obj.to_json()
        self.assertIsNotNone(obj)
