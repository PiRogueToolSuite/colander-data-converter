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
Check :ref:`the list of supported types <observable_types>`.

.. datatemplate:json:: ../../colander_data_converter/converters/misp/data/observable_misp_mapping.json
   :template: misp-type.tmpl
   :data_type: observable
