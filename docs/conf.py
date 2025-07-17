# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "Colander data converter"
copyright = "2025, Defensive Lab Agency - Esther Onfroy"
author = "Esther Onfroy"

autodoc_pydantic_model_show_json = True
autodoc_pydantic_model_show_validator_summary = True
autodoc_pydantic_settings_show_json = False

extensions = [
    "sphinx.ext.autodoc",
    "sphinx-pydantic",
    "sphinx.ext.coverage",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.githubpages",
    "sphinxcontrib.autodoc_pydantic",
    "sphinxcontrib.datatemplates",
]

templates_path = ["_templates"]
html_static_path = ["_static"]
html_theme = "sphinx_rtd_theme"
html_logo = "_static/pts_logo.png"

exclude_patterns = []

apidoc_modules = [
    {
        "path": "colander_data_converter",
        "destination": "docs/source/",
        "exclude_patterns": ["**/test*", "**/docs/"],
        "max_depth": 4,
        "follow_links": False,
        "separate_modules": True,
        "include_private": False,
        "no_headings": False,
        "module_first": False,
        "implicit_namespaces": False,
        "automodule_options": {"members", "show-inheritance", "undoc-members"},
    },
]

intersphinx_mapping = {
    "pydantic": ("https://docs.pydantic.dev/latest", None),
}
