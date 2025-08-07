.. _misp_data_model:

.. _MISP: https://www.misp-project.org/
.. _GitHub: https://github.com/PiRogueToolSuite/colander-data-converter

MISP
====
.. toctree::
   :maxdepth: 1


We welcome contributions to expand MISP_ support! Don't hesitate to submit pull requests on GitHub_ ❤️


Artifacts
---------
Artifacts are converted into MISP objects of type :textmonoborder:`file`:

.. code-block:: json

    "Event": {  // Corresponds to the Colander Case
        "id": "1234",
        // Colander case UUID
        "uuid": "25b4dae2-0ea7-46f2-9f7a-08ef3a43063e",
        "timestamp": "1753798687",
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
Check :ref:`the list of supported types <artifact_types>`.

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/artifact_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: artifact

Devices
-------
Check :ref:`the list of supported types <device_types>`.

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/device_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: device

Observables
-----------
Observables are converted into attributes of a MISP event:

.. code-block:: json

    "Event": {  // Corresponds to the Colander Case
        "id": "1234",
        // Colander case UUID
        "uuid": "25b4dae2-0ea7-46f2-9f7a-08ef3a43063e",
        "timestamp": "1753798687",
        "info": "Name and description of the case",
        "Attribute": [
            {  // Corresponds to the first observable
                "id": "5678",
                "type": "url",
                // Colander observable UUID
                "uuid": "478fbf8b-1e3c-47e9-97a6-7620d27ef6a4",
                "timestamp": "1753798687",
                "comment": "Test comment",
                "value": "https://pts-project.org/",
            },
            {  // Corresponds to the second observable
                "id": "8901",
                "type": "domain",
                // Colander observable UUID
                "uuid": "50d7e69c-d625-4aa7-9cfb-4cfb136af59f",
                "timestamp": "1753798687",
                "comment": "Test comment",
                "value": "pts-project.org",
            },
        ]
    }


Check :ref:`the list of supported types <observable_types>`.

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/observable_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: observable
