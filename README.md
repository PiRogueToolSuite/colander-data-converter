<div align="center">
<img width="60px" src="https://pts-project.org/android-chrome-512x512.png">
<h1>colander-data-converter</h1>
<p>
A set of helpers to manipulate Colander data.
</p>
<p>
License: GPLv3
</p>
<p>
<a href="https://pts-project.org">Website</a> |
<a href="https://pts-project.org/colander-data-converter/">Documentation</a> |
<a href="https://discord.gg/qGX73GYNdp">Support</a>
</p>
</div>

> ⚠️ *This project is currently under active development and is not suitable for production use. Breaking changes may occur without notice. A stable release will be published to PyPI once development stabilizes.*

The `colander_data_converter` Python package provides tools for converting between different cyber threat intelligence data formats, with a focus on the Colander, MISP and STIX2 schemas. Its main purpose is to facilitate interoperability and data exchange between systems that use different standards for representing entities such as observables, actors, events, and relationships in threat intelligence feeds.

![](https://github.com/PiRogueToolSuite/colander-data-converter/raw/main/docs/_static/img/conversions.png)

Colander data format is an opinionated data format focused on usability and interoperability. It uses strict type definitions and internal type discriminators for serialization and deserialization.

## Requirements
`colander_data_converter` requires Python 3.12 or higher.

## Installation
**Once released**, install with:
```
_pip install colander_data_converter
```

## Issues & Contributing
Raise an issue, submit a PR on the [GitHub project](https://github.com/PiRogueToolSuite/colander-data-converter) or feel free to join our [Discord server](https://discord.gg/qGX73GYNdp).

## Development

1. Install Python 3.12 or higher.
2. Install [uv](https://docs.astral.sh/uv/).
3. Clone the project repository:

```
git clone https://github.com/PiRogueToolSuite/colander-data-converter
cd colander-data-converter
uv sync
```

Before submitting a PR, execute run the test suite and the pre-commit checks:
```
tox run
tox run -e docs
```
