Converting data
===============
.. toctree::
   :maxdepth: 1


Threatr
-------

To convert data from or to :ref:`Threatr format <threatr_data_model>`, use helper methods of :py:class:`~colander_data_converter.formats.threatr.converter.ThreatrConverter`:

* :py:meth:`~colander_data_converter.formats.threatr.converter.ThreatrConverter.to_colander` to convert to a :ref:`Colander feed <colander_feed_structure>`, it returns an object of type :py:class:`~colander_data_converter.base.models.ColanderFeed`

* :py:meth:`~colander_data_converter.formats.threatr.converter.ThreatrConverter.from_colander` to convert to a :ref:`Threatr feed <threatr_feed_structure>`, it returns an object of type :py:class:`~colander_data_converter.formats.threatr.models.ThreatrFeed`


Convert from Threatr feed to Colander feed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import json
   from colander_data_converter.formats.threatr.converter import ThreatrConverter
   from colander_data_converter.formats.threatr.models import ThreatrFeed

   with open("path/to/threatr_feed.json", "r") as f:
       raw = json.load(f)
   threatr_feed = ThreatrFeed.load(raw)
   colander_feed = ThreatrConverter.to_colander(threatr_feed)
   # 'colander_feed' is now a ColanderFeed object


Convert from Colander feed to Threatr feed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import json
   from colander_data_converter.base.models import ColanderFeed
   from colander_data_converter.formats.threatr.converter import ThreatrConverter

   with open("path/to/colander_feed.json", "r") as f:
       raw = json.load(f)
   colander_feed = ColanderFeed.load(raw)
   threatr_feed = ThreatrConverter.from_colander(colander_feed)
   # 'threatr_feed' is now a ThreatrFeed object
