.. _threatr_data_model:

Threatr
=======
.. toctree::
   :maxdepth: 1

Threatr is a data format designed for representing cyber threat intelligence entities, relations, and events in a
flexible, weakly typed, graph-oriented structure. It emphasizes direct modeling of threat objects (such as observables,
actors, and events) and their relationships. Threatr feeds typically consist of lists of entities, relations, and
events, with explicit references between objects.

.. _threatr_feed_structure:

Threatr feed structure
----------------------

A Threatr feed
(:py:class:`~colander_data_converter.converters.threatr.models.ThreatrFeed`)
is a collection of entities, events, and relations with the following top-level structure:

- ``root_entity``: The main entity of interest in the feed.
- ``entities``: A list of entity objects, each representing an observable, actor, or other threat intelligence object.
- ``relations``: A list of relation objects, each describing a directed relationship between two entities.
- ``events``: A list of event objects, representing actions or occurrences involving entities.



Entities
--------

Entities
(:py:class:`~colander_data_converter.converters.threatr.models.Entity`)
in Threatr are modeled as objects with the following typical attributes:

- ``id``: A unique identifier (often a UUID).
- ``name``: A human-readable name or value.
- ``type``: The specific type of entity (e.g., IPV4, DOMAIN, INDIVIDUAL).
- ``super_type``: The general category of the entity (e.g., Observable, Actor).
- ``attributes``: Dictionary of additional properties.

Events
------

Events
(:py:class:`~colander_data_converter.converters.threatr.models.Event`)
represent actions or occurrences and typically include:

- ``id``: A unique identifier (often a UUID).
- ``name``: A human-readable name or value.
- ``type``: Event type (e.g., ALERT, COMPROMISE).
- ``involved_entity``: Reference to the main entity involved in the event.
- ``attributes``: Dictionary of additional properties.

Relations
---------

Relations
(:py:class:`~colander_data_converter.converters.threatr.models.EntityRelation`)
describe directed links between entities and have these attributes:

- ``id``: A unique identifier (often a UUID).
- ``name``: The type or name of the relation (e.g., "operated by", "related to").
- ``obj_from``: Reference to the source entity.
- ``obj_to``: Reference to the target entity.
- ``attributes``: Dictionary of additional properties.
