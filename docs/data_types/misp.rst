.. _misp_data_model:

.. _MISP: https://www.misp-project.org/
.. _GitHub: https://github.com/PiRogueToolSuite/colander-data-converter

MISP
====
.. toctree::
   :maxdepth: 1


We welcome contributions to expand MISP_ support! Don't hesitate to submit pull requests on GitHub_ ❤️



Entity relations
----------------
Entity relations are converted into MISP :textmonoborder:`relationships`.

.. code-block:: json

    "Event": {  // Corresponds to the Colander Case
        // Colander case UUID
        "uuid": "25b4dae2-0ea7-46f2-9f7a-08ef3a43063e",
        "info": "Name and description of the case",
        "Object": [
            {
                "name" : "person",
                "meta-category" : "misc",
                "uuid" : "c9d6f815-c319-478d-b8bc-50f9f46290c5",
                "Attribute" : [{
                  "object_relation" : "full-name",
                  "value" : "CellRebel",
                }],
                "Relationship" : [{
                  "related_object_uuid" : "f2e67c94-5e35-4cbd-b7b9-88b818c8acec",
                  "object_uuid" : "49d1b77e-765e-4cd1-858b-e2a8d7aa23de",
                  "relationship_type" : "acquired"
                }]
            }
        ]
    }


Actors
------
Actors are converted into MISP objects of type :textmonoborder:`person` or :textmonoborder:`organization`.

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/actor_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: actor

.. code-block:: json

    "Event": {  // Corresponds to the Colander Case
        // Colander case UUID
        "uuid": "25b4dae2-0ea7-46f2-9f7a-08ef3a43063e",
        "info": "Name and description of the case",
        "Object": [
            {
                "name" : "person",
                "meta-category" : "misc",
                "uuid" : "c9d6f815-c319-478d-b8bc-50f9f46290c5",
                "Attribute" : [
                {
                  "object_relation" : "function",
                  "value" : "unknown type of threat actor",
                }, {
                  "object_relation" : "full-name",
                  "value" : "CellRebel",
                }
            ]
        ]
    }


Artifacts
---------
Artifacts are converted into MISP objects of type :textmonoborder:`file`:

.. code-block:: json

    "Event": {  // Corresponds to the Colander Case
        // Colander case UUID
        "uuid": "25b4dae2-0ea7-46f2-9f7a-08ef3a43063e",
        "info": "Name and description of the case",
        "Object": [
            {
                "name" : "file",
                // Colander artifact UUID
                "uuid" : "5a30624e-4985-4551-a3d2-6aa34a8343d1",
                "Attribute" : [
                    {
                        // Colander artifact name
                        "object_relation" : "filename",
                        "value" : "malware_sample.pdf",
                    }, {
                        // Colander artifact mime_type
                        "object_relation" : "mimetype",
                        "value" : "application/pdf",
                    }, {
                        // Colander artifact sha1
                        "object_relation" : "sha1",
                        "value" : "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    }
                ]
            }
        ]
    }

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/artifact_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: artifact


Data Fragments
--------------
Data Fragments are converted into MISP objects of type :textmonoborder:`colander-data-fragment`.

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/data_fragment_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: data_fragment


Detection Rules
---------------
Detection rules are converted into MISP objects of type :textmonoborder:`yara` or :textmonoborder:`suricata`:

.. code-block:: json

    "Event": {  // Corresponds to the Colander Case
        // Colander case UUID
        "uuid": "25b4dae2-0ea7-46f2-9f7a-08ef3a43063e",
        "info": "Name and description of the case",
        "Object": [
            {
                "name" : "yara",
                "yara-rule-name" : "Test Yara rules"
                // Colander detection rule UUID
                "uuid" : "df627dd0-ee7b-4516-bf9d-8cc51f9ea1fc",
                "Attribute" : [ {
                    "object_relation" : "yara",
                    "value" : "rule YaraTest {}",
                } ],
            }
        ]
    }

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/detection_rule_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: detection_rule


Devices
-------
Artifacts are converted into MISP objects of type :textmonoborder:`device`.

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/device_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: device


Events
------
Events are converted into MISP objects of type :textmonoborder:`colander-event`.

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/event_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: event


Observables
-----------
Observables are converted into :textmonoborder:`attribute` of a MISP event:

.. code-block:: json

    "Event": {  // Corresponds to the Colander Case
        // Colander case UUID
        "uuid": "25b4dae2-0ea7-46f2-9f7a-08ef3a43063e",
        "info": "Name and description of the case",
        "Attribute": [
            {  // Corresponds to the first observable
                "type": "url",
                // Colander observable UUID
                "uuid": "478fbf8b-1e3c-47e9-97a6-7620d27ef6a4",
                "comment": "Test comment",
                "value": "https://pts-project.org/",
            },
            {  // Corresponds to the second observable
                "type": "domain",
                // Colander observable UUID
                "uuid": "50d7e69c-d625-4aa7-9cfb-4cfb136af59f",
                "comment": "Test comment",
                "value": "pts-project.org",
            },
        ]
    }

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/observable_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: observable


Threats
-------
Events are converted into MISP objects of type :textmonoborder:`misp-tag`.

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/threat_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: threat

.. code-block:: json

    "Event": {  // Corresponds to the Colander Case
        // Colander case UUID
        "uuid": "25b4dae2-0ea7-46f2-9f7a-08ef3a43063e",
        "info": "Name and description of the case",
        "Attribute": [
            {  // Corresponds to the observable
                "type": "domain",
                // Colander observable UUID
                "uuid": "50d7e69c-d625-4aa7-9cfb-4cfb136af59f",
                "comment": "Test comment",
                "value": "pts-project.org",
                "Tag" : [ {
                  "name" : "colander:threat:information-stealer"
                } ],
            },
        ]
    }
