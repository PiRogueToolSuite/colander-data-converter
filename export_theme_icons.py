import json


# Source: https://icon-sets.iconify.design/tabler/
def export_theme_icons():
    stroke = 2
    size = 36
    with open("colander_data_converter/data/themes/default.json", "r") as json_file:
        theme = json.load(json_file)
    for name, elt in theme["types"].items():
        with open(f"docs/_static/icons/{name}.svg", "w") as svg_file:
            svg = elt["svg_icon"]
            color = elt["fg_color"]
            svg = svg.replace('stroke-width="2"', f'stroke-width="{stroke}"')
            svg = svg.replace('width="24" height="24"', f'width="{size}" height="{size}"')
            svg = svg.replace("currentColor", color)
            svg_file.write(svg)


if __name__ == "__main__":
    export_theme_icons()
