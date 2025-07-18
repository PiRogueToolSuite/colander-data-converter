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
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented_params"
autoclass_content = "class"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autodoc.typehints",
    "sphinx_copybutton",
    "sphinx_rtd_theme",
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
html_theme_options = {
    "logo_only": False,
    "prev_next_buttons_location": "bottom",
    "style_external_links": False,
    "vcs_pageview_mode": "",
    "flyout_display": "hidden",
    "collapse_navigation": True,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "titles_only": False,
}

exclude_patterns = []

autosummary_generate = True

intersphinx_mapping = {
    "pydantic": ("https://docs.pydantic.dev/latest", None),
    "python": ("https://docs.python.org/", None),
}
