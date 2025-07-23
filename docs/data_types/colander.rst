Colander
========
.. toctree::
   :maxdepth: 1

This documentation page provides a comprehensive reference for **Colander data types** - the core entity categories and their specifications within the Colander threat intelligence data model.

Colander organizes threat intelligence data into eight primary entity super types, each representing a distinct category of information relevant to cybersecurity analysis and threat hunting. This reference documents both the data structure and available subtypes for each category.

Overview
--------

Colander supports the following entity types:

* :ref:`Actors <actor_types>` - Individuals, groups, or organizations involved in threat activities
* :ref:`Artifacts <artifact_types>` - Files, documents, binaries, and other data objects
* :ref:`Data Fragments <data_fragment_types>` - Code snippets, text portions, and content fragments
* :ref:`Detection Rules <detection_rule_types>` - Rules and logic for identifying specific threats or patterns
* :ref:`Devices <device_types>` - Physical or virtual systems, hardware, and infrastructure components
* :ref:`Events <event_types>` - Temporal occurrences, alerts, detections, and log entries
* :ref:`Observables <observable_types>` - Detectable entities like IP addresses, domains, file hashes, and URLs
* :ref:`Threats <threat_types>` - Malicious entities such as malware families, campaigns, and attack techniques

Base data model
```````````````

Entity types inherit the ``Entity`` class.

.. autopydantic_model:: colander_data_converter.base.models.Entity
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false

Relations between entities
``````````````````````````

.. autopydantic_model:: colander_data_converter.base.models.EntityRelation
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false

Collection of entities
``````````````````````
A Colander feed represents a collection of entities.

.. autopydantic_model:: colander_data_converter.base.models.ColanderFeed
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false




.. _actor_types:

Actors
------
An actor represents an individual or group involved in an event, activity, or system.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Actor
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false
   :show-inheritance:

.. datatemplate:json:: ../../colander_data_converter/data/actor_types.json
   :template: colander-type.tmpl

.. _artifact_types:

Artifacts
---------
An artifact represents a file or data object, such as a document, image, or binary, within a system.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Artifact
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false
   :show-inheritance:

.. datatemplate:json:: ../../colander_data_converter/data/artifact_types.json
   :template: colander-type.tmpl

.. _data_fragment_types:

Data Fragments
--------------
A data fragment represents a fragment of data, such as a code snippet, text, or other content.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.DataFragment
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false
   :show-inheritance:

.. datatemplate:json:: ../../colander_data_converter/data/data_fragment_types.json
   :template: colander-type.tmpl

.. _detection_rule_types:

Detection Rules
---------------
A detection rule represents a rule used for detecting specific content or logic related to observables.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.DetectionRule
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false
   :show-inheritance:

.. datatemplate:json:: ../../colander_data_converter/data/detection_rule_types.json
   :template: colander-type.tmpl

.. _device_types:

Devices
-------
A device represents a physical or virtual device in a system.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Device
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false
   :show-inheritance:

.. datatemplate:json:: ../../colander_data_converter/data/device_types.json
   :template: colander-type.tmpl

.. _event_types:

Events
------
An event represents an occurrence or activity observed within a system, such as a detection, alert, or log entry.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Event
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false
   :show-inheritance:

.. datatemplate:json:: ../../colander_data_converter/data/event_types.json
   :template: colander-type.tmpl

.. _observable_types:

Observables
-----------
Observable represents an entity such as an IP address that can be observed or detected within a system.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Observable
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false
   :show-inheritance:

.. datatemplate:json:: ../../colander_data_converter/data/observable_types.json
   :template: colander-type.tmpl

.. _threat_types:

Threats
-------
A threat represents a potentially malicious entity, such as a malware family, campaign, or adversary.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Threat
   :no-index:
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: True
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False
   :member-order: alphabetical
   :exclude-members: colander_internal_type
   :field-doc-policy: docstring
   :members: false
   :show-inheritance:

.. datatemplate:json:: ../../colander_data_converter/data/threat_types.json
   :template: colander-type.tmpl
