"""
Registry of supported VPAP source systems.

The ingestion layer receives the source system explicitly.
It must never attempt to guess the source from the raw data.
"""

from collections.abc import Callable
from importlib import import_module
from typing import Any

from vpap.domain.finding import Finding


# Defines a type alias for mapper functions.
# This type hint specifies that a mapper is a callable that takes a dictionary (representing a raw source record) and returns a `Finding` object.
# A mapper receives one raw source record and returns the canonical VPAP Finding.
Mapper = Callable[[dict[str, Any]], Finding]


# This dictionary serves as the central registry for all supported source systems.
# It maps a source system identifier (e.g., "WIZ") to its configuration details.
# Each entry specifies the type of source (e.g., "file"), the full import path to its corresponding mapper function, and its schema version.
SOURCE_REGISTRY: dict[str, dict[str, Any]] = {
    "WIZ": {
        "type": "file",
        "mapper": "vpap.connectors.wiz_mapper.map_wiz_record_to_finding",
        "schema_version": "v1",
    },
}


# This function retrieves the configuration details for a specified source system.
# It ensures that only registered source systems are processed, preventing unexpected behavior from unknown inputs.
def get_source_config(source_system: str) -> dict[str, Any]:
    """
    Return the configuration for an explicitly supplied source system.

    The source system must be explicitly provided by the caller.
    This function never attempts to infer it from the source data.

    Raises:
        ValueError: If the source system is not registered.
    """

    # Normalizes the input source system name to uppercase.
    # This ensures that the lookup in SOURCE_REGISTRY is case-insensitive.
    source_key = source_system.upper()

    # Checks if the normalized source key exists in the SOURCE_REGISTRY.
    # If not, it raises a ValueError, indicating that the system does not support the requested source and lists the available ones.
    if source_key not in SOURCE_REGISTRY:
        raise ValueError(
            f"Unsupported source system: {source_system!r}. "
            f"Supported sources: {', '.join(SOURCE_REGISTRY)}"
        )

    # Returns the configuration dictionary associated with the valid source key.
    return SOURCE_REGISTRY[source_key]


# This function dynamically loads a Python function given its full import path as a string.
# This allows the system to load mapper functions at runtime based on configuration, making the architecture flexible and extensible without hardcoding dependencies.
def load_mapper(mapper_path: str) -> Mapper:
    """
    Load a mapper function from its fully qualified import path.

    Example:
        "vpap.connectors.wiz_mapper.map_wiz_record_to_finding"

    Raises:
        ValueError: If the mapper path is malformed.
        AttributeError: If the mapper function does not exist.
    """

    # Attempts to split the mapper_path into its module name and function name.
    # It uses rsplit('.', 1) to handle cases where module names might contain dots.
    # If the path format is incorrect (e.g., no dots), it catches the ValueError.
    try:
        module_name, function_name = mapper_path.rsplit(".", 1)
    except ValueError as exc:
        raise ValueError(
            f"Invalid mapper path: {mapper_path!r}"
        ) from exc
    
    # Dynamically imports the module specified by module_name.
    # This uses Python's importlib to load the module object.
    module = import_module(module_name)
    # Retrieves the function object from the imported module using its name.
    # If the function does not exist in the module, getattr will raise an AttributeError.
    mapper = getattr(module, function_name)

    # Verifies that the retrieved object is indeed a callable function.
    # If it's not, it raises a TypeError, indicating a misconfiguration.
    if not callable(mapper):
        raise TypeError(
            f"Configured mapper is not callable: {mapper_path!r}"
        )

    return mapper