Convert data
============
.. toctree::
   :maxdepth: 1


Threatr
-------

To convert data from or to :ref:`Threatr format <threatr_data_model>`, use helper methods of :py:class:`~colander_data_converter.converters.threatr.converter.ThreatrConverter`:

* :py:meth:`~colander_data_converter.converters.threatr.converter.ThreatrConverter.threatr_to_colander` to convert to a :ref:`Colander feed <colander_feed_structure>`, it returns an object of type :py:class:`~colander_data_converter.base.models.ColanderFeed`

* :py:meth:`~colander_data_converter.converters.threatr.converter.ThreatrConverter.colander_to_threatr` to convert to a :ref:`Threatr feed <threatr_feed_structure>`, it returns an object of type :py:class:`~colander_data_converter.converters.threatr.models.ThreatrFeed`


Convert from Threatr feed to Colander feed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import json
   from colander_data_converter.converters.threatr.converter import ThreatrConverter
   from colander_data_converter.converters.threatr.models import ThreatrFeed

   with open("path/to/threatr_feed.json", "r") as f:
       raw = json.load(f)
   threatr_feed = ThreatrFeed.load(raw)
   colander_feed = ThreatrConverter.threatr_to_colander(threatr_feed)


Convert from Colander feed to Threatr feed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import json
   from colander_data_converter.base.models import ColanderFeed
   from colander_data_converter.converters.threatr.converter import ThreatrConverter

   with open("path/to/colander_feed.json", "r") as f:
       raw = json.load(f)
   colander_feed = ColanderFeed.load(raw)
   root_entity = colander_feed.entities.get("...uuid4...")
   threatr_feed = ThreatrConverter.colander_to_threatr(colander_feed, root_entity)


Stix2
-------

To convert data from or to Stix2 format, use helper methods of :py:class:`~colander_data_converter.converters.stix2.converter.Stix2Converter`:

* :py:meth:`~colander_data_converter.converters.stix2.converter.Stix2Converter.stix2_to_colander` to convert to a :ref:`Colander feed <colander_feed_structure>`, it returns an object of type :py:class:`~colander_data_converter.base.models.ColanderFeed`

* :py:meth:`~colander_data_converter.converters.stix2.converter.Stix2Converter.colander_to_stix2` to convert to a Stix2 bundle, it returns an object of type :py:class:`~colander_data_converter.converters.stix2.models.Stix2Bundle`


Convert from Stix2 bundle to Colander feed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import json
   from colander_data_converter.converters.stix2.converter import Stix2Converter
   from colander_data_converter.converters.stix2.models import Stix2Bundle

   with open("path/to/stix2_bundle.json", "r") as f:
       raw = json.load(f)
   stix2_bundle = Stix2Bundle.load(raw)
   colander_feed = Stix2Converter.stix2_to_colander(stix2_bundle)


Convert from Colander feed to Stix2 bundle
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import json
   from colander_data_converter.base.models import ColanderFeed
   from colander_data_converter.converters.stix2.converter import Stix2Converter

   with open("path/to/colander_feed.json", "r") as f:
       raw = json.load(f)
   colander_feed = ColanderFeed.load(raw)
   stix2_bundle = Stix2Converter.colander_to_stix2(colander_feed)
