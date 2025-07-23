Loading and exporting data
==========================
.. toctree::
   :maxdepth: 1


Colander
--------

Loading from JSON file
``````````````````````

To load a Colander feed from a JSON file, call the method
:py:meth:`~colander_data_converter.base.models.ColanderFeed.load` of
:py:class:`~colander_data_converter.base.models.ColanderFeed`:

.. code-block:: python

   import json
   from colander_data_converter.base.models import ColanderFeed

   with open("path/to/colander_feed.json", "r") as f:
       raw = json.load(f)
   feed = ColanderFeed.load(raw)
   # 'feed' is now a ColanderFeed object

Exporting to JSON file
``````````````````````
To export a Colander feed to a JSON file, use :py:meth:`~pydantic.BaseModel.main.model_dump` to convert the feed to
a Python :py:class:`dict` and save it into the destination file in JSON format:

.. code-block:: python

   import json

   # 'feed' is a ColanderFeed object
   feed.unlink_references()
   with open("path/to/output_colander_feed.json", "w") as f:
       json.dump(feed.model_dump(), f, indent=2)


Threatr
--------

Loading from JSON file
``````````````````````
To load a Threatr feed from a JSON file, call the method
:py:meth:`~colander_data_converter.formats.threatr.models.ThreatrFeed.load` of
:py:class:`~colander_data_converter.formats.threatr.models.ThreatrFeed`:

.. code-block:: python

   import json
   from colander_data_converter.formats.threatr.models import ThreatrFeed

   with open("path/to/threatr_feed.json", "r") as f:
       raw = json.load(f)
   feed = ThreatrFeed.load(raw)
   # 'feed' is now a ThreatrFeed object

Exporting to JSON file
``````````````````````
To export a Threatr feed to a JSON file, use :py:meth:`~pydantic.BaseModel.main.model_dump` to convert the feed to
a Python :py:class:`dict` and save it into the destination file in JSON format:

.. code-block:: python

   # 'feed' is a ThreatrFeed object
   feed.unlink_references()
   with open("path/to/output_threatr_feed.json", "w") as f:
       f.write(feed.model_dump_json(indent=2))
