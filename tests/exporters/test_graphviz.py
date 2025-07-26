import json
from importlib import resources
from io import StringIO

from colander_data_converter.base.models import ColanderFeed
from colander_data_converter.exporters.graphviz import GraphvizExporter


class TestGraphviz:
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
        graphviz = GraphvizExporter(feed)
        io = StringIO()
        graphviz.export(io)
        io.seek(0)
        output = io.read()
        assert len(output) > 0
