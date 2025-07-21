Colander
========
.. toctree::
   :maxdepth: 2

.. _actor_types:

Actors
------
An actor represents an individual or group involved in an event, activity, or system.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Actor
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: False
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False

.. datatemplate:json:: ../../colander_data_converter/data/actor_types.json
   :template: colander-type.tmpl

.. _artifact_types:

Artifacts
---------
An artifact represents a file or data object, such as a document, image, or binary, within a system.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Artifact
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: False
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False

.. datatemplate:json:: ../../colander_data_converter/data/artifact_types.json
   :template: colander-type.tmpl

.. _data_fragment_types:

Data Fragments
--------------
A data fragment represents a fragment of data, such as a code snippet, text, or other content.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.DataFragment
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: False
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False

.. datatemplate:json:: ../../colander_data_converter/data/data_fragment_types.json
   :template: colander-type.tmpl

.. _detection_rule_types:

Detection Rules
---------------
A detection rule represents a rule used for detecting specific content or logic related to observables.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.DetectionRule
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: False
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False

.. datatemplate:json:: ../../colander_data_converter/data/detection_rule_types.json
   :template: colander-type.tmpl

.. _device_types:

Devices
-------
A device represents a physical or virtual device in a system.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Device
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: False
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False

.. datatemplate:json:: ../../colander_data_converter/data/device_types.json
   :template: colander-type.tmpl

.. _event_types:

Events
------
An event represents an occurrence or activity observed within a system, such as a detection, alert, or log entry.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Event
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: False
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False

.. datatemplate:json:: ../../colander_data_converter/data/event_types.json
   :template: colander-type.tmpl

.. _observable_types:

Observables
-----------
Observable represents an entity such as an IP address that can be observed or detected within a system.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Observable
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: False
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False

.. datatemplate:json:: ../../colander_data_converter/data/observable_types.json
   :template: colander-type.tmpl

.. _threat_types:

Threats
-------
A threat represents a potentially malicious entity, such as a malware family, campaign, or adversary.

Data model
``````````
.. autopydantic_model:: colander_data_converter.base.models.Threat
   :model-show-json: False
   :model-show-config-summary: False
   :model-show-field-summary: False
   :model-show-validator-summary: False
   :model-show-validator-members: False
   :field-list-validators: False
   :field-show-constraints: False

.. datatemplate:json:: ../../colander_data_converter/data/threat_types.json
   :template: colander-type.tmpl
