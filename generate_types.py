import json
from pathlib import Path

import jinja2


def generate_type_enum(type_name: str):
    types_py = Path(__file__).parent / "colander_data_converter" / "base" / "types" / f"{type_name}.py"
    types_tpl = Path(__file__).parent / "code_templates" / f"{type_name}_types.jinja2"
    doc_tpl = Path(__file__).parent / "code_templates" / "type_doc.jinja2"
    doc_rst = Path(__file__).parent / "docs" / "source" / f"colander_data_converter.base.types.{type_name}.rst"
    types_json = Path(__file__).parent / "colander_data_converter" / "data" / "types" / f"{type_name}_types.json"

    types = json.load(types_json.open())
    code_template_source = types_tpl.open().read()
    code_template = jinja2.Template(code_template_source)
    doc_template_source = doc_tpl.open().read()
    doc_template = jinja2.Template(doc_template_source)

    # Generate code
    py_code = code_template.render(types=types)
    with types_py.open("w") as f:
        f.write(py_code)

    # Generate doc
    doc = doc_template.render(name=type_name)
    with doc_rst.open("w") as f:
        f.write(doc)


if __name__ == "__main__":
    types = [
        "actor",
        "artifact",
        "data_fragment",
        "detection_rule",
        "device",
        "event",
        "observable",
        "threat",
    ]
    for t in types:
        generate_type_enum(t)
