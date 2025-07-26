Knowledge graph
===============

.. toctree::
   :maxdepth: 1

Motivations
-----------

Colander represents threat intelligence data as a knowledge graph to model the complex relationships and entities found in cybersecurity. Threat intelligence involves many interconnected objects—such as actors, artifacts, observables, devices, events, and threats—which interact in non-linear and dynamic ways.

A knowledge graph allows Colander to:

- **Capture Relationships:** Entities (nodes) and their relationships (edges) are explicitly modeled, enabling representation of connections such as "actor operates device," "artifact extracted from device," or "observable associated with threat."
- **Enable Rich Queries:** Users can traverse the graph to answer questions like "Which devices were operated by a specific actor?" or "What threats are linked to a particular observable?"
- **Support Reasoning:** The graph structure supports advanced analytics, such as identifying patterns, inferring new relationships, or detecting anomalies.
- **Maintain Context:** By linking entities and events, Colander preserves the context necessary for understanding the significance of threat intelligence data.

Data model
----------

Colander's data model defines entities (e.g., Actor, Artifact, Device, Observable, Threat, Event) as nodes in the graph. Relationships between entities are represented by explicit relation objects (edges), such as `EntityRelation`. Each entity and relation can reference others using unique identifiers, allowing the graph to be constructed, traversed, and analyzed programmatically.

This approach ensures that threat intelligence data is flexible, extensible, and suitable for integration with graph-based analytics and visualization tools.
