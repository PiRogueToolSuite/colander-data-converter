Colander data converter
=======================

The ``colander_data_converter`` Python package provides tools for converting between different cyber threat
intelligence data formats, with a focus on the Colander and STIX2 schemas. Its main purpose is to facilitate
interoperability and data exchange between systems that use different standards for representing entities such
as observables, actors, events, and relationships in threat intelligence feeds.

Colander data format is an opinionated data format focused on normalization and interoperability. It uses strict
type definitions and internal type discriminators for serialization and deserialization. Colander models are designed
to facilitate data exchange, reference resolution, and compatibility with other formats.


Threatr
-------

Threatr is a data format designed for representing cyber threat intelligence entities, relations, and events in a
flexible, weakly typed, graph-oriented structure. It emphasizes direct modeling of threat objects (such as observables,
actors, and events) and their relationships. Threatr feeds typically consist of lists of entities, relations, and
events, with explicit references between objects.



.. toctree::
   :maxdepth: 1

   load_export_data
   convert_data


.. toctree::
   :maxdepth: 1
   :caption: Supported data formats

   data_types/colander
   data_types/threatr
   data_types/stix2

.. toctree::
   :maxdepth: 1
   :caption: API reference

   source/colander_data_converter.base
   source/colander_data_converter.exporters
   source/colander_data_converter.formats
