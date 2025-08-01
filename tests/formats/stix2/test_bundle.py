import json
import unittest
from importlib import resources

from colander_data_converter.converters.stix2.models import Stix2Bundle


class TestBundle(unittest.TestCase):
    def test_load(self):
        resource_package = __name__
        json_file = resources.files(resource_package).joinpath("data").joinpath("stix2_bundle.json")
        with json_file.open() as f:
            raw = json.load(f)
            feed = Stix2Bundle.load(raw).model_dump()
            print(feed)
