from typing import Dict, Any, Optional, TYPE_CHECKING

from colander_data_converter.base.common import Singleton
from colander_data_converter.base.models import ColanderFeed

# Avoid circular imports
if TYPE_CHECKING:
    pass


class Stix2Repository(object, metaclass=Singleton):
    """
    Singleton repository for managing and storing STIX2 objects.

    This class provides centralized storage and reference management for all STIX2 objects,
    supporting conversion to and from Colander data.
    """

    stix2_objects: Dict[str, Dict[str, Any]]

    def __init__(self):
        """
        Initializes the repository with an empty dictionary for STIX2 objects.
        """
        self.stix2_objects = {}

    def add_object(self, stix2_object: Dict[str, Any]) -> None:
        """
        Adds a STIX2 object to the repository.

        Args:
            stix2_object (Dict[str, Any]): The STIX2 object to add.
        """
        if "id" in stix2_object:
            self.stix2_objects[stix2_object["id"]] = stix2_object

    def get_object(self, object_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a STIX2 object from the repository by its ID.

        Args:
            object_id (str): The ID of the STIX2 object to retrieve.

        Returns:
            Optional[Dict[str, Any]]: The STIX2 object if found, None otherwise.
        """
        return self.stix2_objects.get(object_id)

    def clear(self) -> None:
        """
        Clears all STIX2 objects from the repository.
        """
        self.stix2_objects.clear()


class Stix2Converter:
    """
    Converter for STIX2 data to Colander data and vice versa.
    Uses the mapping file to convert between formats.
    """

    @staticmethod
    def stix2_to_colander(stix2_data: Dict[str, Any]) -> ColanderFeed:
        """
        Converts STIX2 data to Colander data using the mapping file.

        Args:
            stix2_data (Dict[str, Any]): The STIX2 data to convert.

        Returns:
            ColanderFeed: The converted Colander data.
        """
        # Import here to avoid circular imports
        from colander_data_converter.formats.stix2.converter import Stix2ToColanderMapper

        mapper = Stix2ToColanderMapper()
        return mapper.convert(stix2_data)

    @staticmethod
    def colander_to_stix2(colander_feed: ColanderFeed) -> Dict[str, Any]:
        """
        Converts Colander data to STIX2 data using the mapping file.

        Args:
            colander_feed (ColanderFeed): The Colander data to convert.

        Returns:
            Dict[str, Any]: The converted STIX2 data.
        """
        # Import here to avoid circular imports
        from colander_data_converter.formats.stix2.converter import ColanderToStix2Mapper

        mapper = ColanderToStix2Mapper()
        return mapper.convert(colander_feed)
