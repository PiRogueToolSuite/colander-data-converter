from io import StringIO

from colander_data_converter.exporters.csv import CsvExporter


class TestCSVExporter:
    def test_export(self):
        from colander_data_converter.base.models import ColanderFeed, Observable, ObservableTypes

        ot = ObservableTypes.enum.IPV4.value
        obs_red = Observable(name="1.1.1.1", type=ot)
        obs_amber = Observable(name="2.2.2.2", type=ot)
        obs_green = Observable(name="3.3.3.3", type=ot)
        obs_white = Observable(name="4.4.4.4", type=ot)
        feed = ColanderFeed(
            entities={
                str(obs_red.id): obs_red,
                str(obs_amber.id): obs_amber,
                str(obs_green.id): obs_green,
                str(obs_white.id): obs_white,
            }
        )
        ce = CsvExporter(feed, Observable)
        tio = StringIO()
        ce.export(tio)
        tio.seek(0)
        a = tio.read()
        assert len(a) > 0
