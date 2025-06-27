"""
Utility functions for STIX2 to Colander conversion and vice versa.
"""

from typing import Dict, Any, Optional
from uuid import uuid4, UUID


def extract_uuid_from_stix2_id(stix2_id: str) -> UUID:
    """
    Extract a UUID from a STIX2 ID.

    Args:
        stix2_id (str): The STIX2 ID to extract the UUID from.

    Returns:
        UUID: The extracted UUID, or a new UUID if extraction fails.

    Examples:
        >>> # Valid STIX2 ID with UUID
        >>> stix_id = "indicator--44af6c9f-4bbc-4984-a74b-1404d1ac07ea"
        >>> uuid_obj = extract_uuid_from_stix2_id(stix_id)
        >>> str(uuid_obj)
        '44af6c9f-4bbc-4984-a74b-1404d1ac07ea'

        >>> # Invalid STIX2 ID format (no delimiter)
        >>> stix_id = "indicator-invalid-format"
        >>> uuid_obj = extract_uuid_from_stix2_id(stix_id)
        >>> isinstance(uuid_obj, UUID)  # Returns a new random UUID
        True

        >>> # Invalid UUID part
        >>> stix_id = "indicator--not-a-valid-uuid"
        >>> uuid_obj = extract_uuid_from_stix2_id(stix_id)
        >>> isinstance(uuid_obj, UUID)  # Returns a new random UUID
        True
    """
    try:
        if stix2_id and "--" in stix2_id:
            # Extract the part after the "--" delimiter
            uuid_part = stix2_id.split("--", 1)[1]
            # Try to create a UUID from the extracted part
            return UUID(uuid_part)
    except (ValueError, IndexError):
        # If anything goes wrong, return a new UUID
        pass

    return uuid4()


def extract_stix2_pattern_name(stix2_pattern: str) -> Optional[str]:
    """
    Extracts the name from a STIX 2 pattern string.

    Parameters:
        stix2_pattern (str): The STIX 2 pattern string to extract the name from (e.g. "[ipv4-addr:value = '{value}']").

    Returns:
        Optional[str]: The extracted name or None if no name is found (e.g. "ipv4-addr:value").

    Examples:
        >>> pattern = "[ipv4-addr:value = '192.168.1.1']"
        >>> extract_stix2_pattern_name(pattern)
        'ipv4-addr:value'

        >>> pattern = "[file:hashes.'SHA-256' = '123abc']"
        >>> extract_stix2_pattern_name(pattern)
        "file:hashes.'SHA-256'"
    """
    _to_replace = [
        ("[", ""),
        ("]", ""),
    ]
    if "=" not in stix2_pattern:
        return ""
    _stix2_pattern = stix2_pattern
    for _replace in _to_replace:
        _stix2_pattern = _stix2_pattern.replace(_replace[0], _replace[1])
    return _stix2_pattern.split("=")[0].strip()


def get_nested_value(obj: Dict[str, Any], path: str) -> Any:
    """
    Get a value from a nested dictionary using a dot-separated path.

    Args:
        obj (Dict[str, Any]): The dictionary to get the value from.
        path (str): The dot-separated path to the value.

    Returns:
        Any: The value at the specified path, or None if not found.

    Examples:
        >>> data = {
        ...     "user": {
        ...         "profile": {
        ...             "name": "John",
        ...             "age": 30
        ...         },
        ...         "settings": {
        ...             "theme": "dark"
        ...         }
        ...     }
        ... }
        >>> get_nested_value(data, "user.profile.name")
        'John'
        >>> get_nested_value(data, "user.settings.theme")
        'dark'
    """
    if not path:
        return None

    parts = path.split(".")
    current = obj

    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None

    return current


def set_nested_value(obj: Dict[str, Any], path: str, value: Any) -> None:
    """
    Set a value in a nested dictionary using a dot-separated path.

    Args:
        obj (Dict[str, Any]): The dictionary to set the value in.
        path (str): The dot-separated path to the value.
        value (Any): The value to set.

    Examples:
        >>> data = {}
        >>> set_nested_value(data, "user.profile.name", "John")
        >>> data
        {'user': {'profile': {'name': 'John'}}}

        >>> # Update existing nested value
        >>> data = {'user': {'settings': {'theme': 'light'}}}
        >>> set_nested_value(data, "user.settings.theme", "dark")
        >>> data
        {'user': {'settings': {'theme': 'dark'}}}

        >>> # Add new nested path to existing structure
        >>> set_nested_value(data, "user.profile.age", 30)
        >>> data
        {'user': {'settings': {'theme': 'dark'}, 'profile': {'age': 30}}}

        >>> # Empty path does nothing
        >>> original = {'a': 1}
        >>> set_nested_value(original, "", "value")
        >>> original
        {'a': 1}
    """
    if not path:
        return

    parts = path.split(".")
    current = obj

    # Navigate to the parent of the final part
    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        current = current[part]

    # Set the value at the final part
    current[parts[-1]] = value
