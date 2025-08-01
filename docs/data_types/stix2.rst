.. _stix2_data_model:

.. _STIX2: https://oasis-open.github.io/cti-documentation/stix/intro
.. _GitHub: https://github.com/PiRogueToolSuite/colander-data-converter

STIX2
=====
.. toctree::
   :maxdepth: 1

.. warning::
    This converter provides **limited STIX2 support** with the following constraints:

    **Unsupported features:**

    - STIX2 patterns are not parsed
    - Only a subset of STIX2 object types are supported

    **Supported STIX2 object types:**

    - ``file``
    - ``identity``
    - ``indicator``
    - ``infrastructure``
    - ``malware``
    - ``threat-actor``

    We welcome contributions to expand STIX2_ support! Don't hesitate to submit pull requests on GitHub_ ❤️


Actors
------

.. datatemplate:json:: ../../colander_data_converter/converters/stix2/data/stix2_colander_mapping.json
   :template: stix2-type.tmpl
   :data_type: actor

Artifacts
---------

.. datatemplate:json:: ../../colander_data_converter/converters/stix2/data/stix2_colander_mapping.json
   :template: stix2-type.tmpl
   :data_type: artifact

Devices
-------

.. datatemplate:json:: ../../colander_data_converter/converters/stix2/data/stix2_colander_mapping.json
   :template: stix2-type.tmpl
   :data_type: device

Observables
-----------

.. datatemplate:json:: ../../colander_data_converter/converters/stix2/data/stix2_colander_mapping.json
   :template: stix2-type.tmpl
   :data_type: observable

Threats
-------

.. datatemplate:json:: ../../colander_data_converter/converters/stix2/data/stix2_colander_mapping.json
   :template: stix2-type.tmpl
   :data_type: threat
