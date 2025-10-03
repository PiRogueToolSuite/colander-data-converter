import unittest
from importlib import resources
from io import StringIO

from jinja2 import Template
from pymisp import MISPFeed

from colander_data_converter.converters.misp.converter import MISPConverter
from colander_data_converter.exporters.template import TemplateExporter


class TestTemplateExample(unittest.TestCase):
    def test_suricata_template(self):
        resource_package = __name__

        # Load the template
        template_file = resources.files(resource_package).joinpath("data").joinpath("suricata.j2")
        with template_file.open() as template_file:
            template = Template(source=template_file.read())

        # Load the MISP feed
        misp_json_file = resources.files(resource_package).joinpath("data").joinpath("misp_feed.json")
        misp_feed = MISPFeed()
        with misp_json_file.open() as json_file:
            misp_feed.from_json(json_file.read())

        # Convert it
        converter = MISPConverter()
        feeds = converter.misp_to_colander(misp_feed)

        # Render the template
        template_exporter = TemplateExporter(
            feed=feeds[0],
            template_name="",
            template_search_path="",
            template=template,
        )
        io = StringIO()
        template_exporter.export(io)
        io.seek(0)
        output = io.read()
        pass
