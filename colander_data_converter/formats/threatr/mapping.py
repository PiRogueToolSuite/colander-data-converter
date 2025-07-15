import json
from importlib import resources
from typing import Dict, Any, List

resource_package = __name__


class ThreatrMappingLoader:
    """
    Loads and provides access to the Threatr to Colander mapping data.
    """

    def __init__(self):
        """
        Initialize the mapping loader.
        """
        # Load the mapping data
        self.mapping_data = self._load_mapping_data()

    @staticmethod
    def _load_mapping_data() -> List[Dict[str, Any]]:
        """
        Load the mapping data from the JSON file.

        Returns:
            List[Dict[str, Any]]: The mapping data.
        """
        json_file = resources.files(resource_package).joinpath("data").joinpath("threatr_colander_mapping.json")
        try:
            with json_file.open() as f:
                return json.load(f).get("mapping")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise ValueError(f"Failed to load mapping data: {e}")


class ThreatrMapper:
    """
    Base class for mapping between Threatr and Colander data using the mapping file.
    """

    def __init__(self):
        """
        Initialize the mapper.
        """
        self.mapping_loader = ThreatrMappingLoader()
