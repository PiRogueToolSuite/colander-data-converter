import json
from importlib import resources
from io import StringIO

from colander_data_converter.base.models import ColanderFeed
from colander_data_converter.exporters.mermaid import MermaidExporter


class TestMermaid:
    def test_render(self):
        resource_package = __name__
        json_file = (
            resources.files(resource_package)
            .joinpath("..")
            .joinpath("base")
            .joinpath("data")
            .joinpath("colander_feed.json")
        )
        with json_file.open() as f:
            raw = json.load(f)
            feed = ColanderFeed.load(raw)
        mermaid = MermaidExporter(feed)
        io = StringIO()
        mermaid.export(io)
        io.seek(0)
        output = io.read()
        assert len(output) > 0
