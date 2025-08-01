from io import StringIO

from jinja2 import Template

from colander_data_converter.exporters.template import TemplateExporter


class TestTemplate:
    def test_render(self):
        from colander_data_converter.base.models import ColanderFeed, Observable
        from colander_data_converter.base.types.observable import ObservableTypes

        ot = ObservableTypes.IPV4.value
        obs_red = Observable(name="1.1.1.1", type=ot, description="looks legit")
        obs_amber = Observable(name="2.2.2.2", type=ot, description="looks weird")
        obs_green = Observable(name="3.3.3.3", type=ot, description="looks shady")
        obs_white = Observable(name="4.4.4.4", type=ot, description="looks great")
        feed = ColanderFeed(
            entities={
                str(obs_red.id): obs_red,
                str(obs_amber.id): obs_amber,
                str(obs_green.id): obs_green,
                str(obs_white.id): obs_white,
            }
        )
        template = Template(source="{{ feed.id }}")
        template_exporter = TemplateExporter(
            feed=feed,
            template_name="",
            template_search_path="",
            template=template,
        )
        io = StringIO()
        template_exporter.export(io)
        io.seek(0)
        output = io.read()
        assert output == str(feed.id)
