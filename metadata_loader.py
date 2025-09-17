import json
import logging
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)


class MetadataLoader:
    def __init__(self):
        self.metadata_store = {}

    def load_metadata_file(self, file_path: str) -> bool:
        """Load a single metadata file"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)

            # Extract AAGUID as the key
            aaguid = metadata.get("aaguid")
            if aaguid:
                self.metadata_store[aaguid] = metadata
                logger.info(f"Loaded metadata for AAGUID: {aaguid}")
                return True
            else:
                logger.warning(f"No AAGUID found in metadata file: {file_path}")
                return False

        except FileNotFoundError:
            logger.error(f"Metadata file not found: {file_path}")
            return False
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in metadata file {file_path}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error loading metadata file {file_path}: {e}")
            return False

    def load_metadata_directory(self, directory_path: str) -> int:
        """Load all JSON metadata files from a directory"""
        loaded_count = 0
        if not os.path.exists(directory_path):
            logger.warning(f"Metadata directory not found: {directory_path}")
            return loaded_count

        for filename in os.listdir(directory_path):
            if filename.endswith(".json"):
                file_path = os.path.join(directory_path, filename)
                if self.load_metadata_file(file_path):
                    loaded_count += 1

        logger.info(f"Loaded {loaded_count} metadata files from {directory_path}")
        return loaded_count

    def get_metadata(self, aaguid: str) -> Dict[str, Any]:
        """Get metadata for a specific AAGUID"""
        return self.metadata_store.get(aaguid)

    def get_all_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Get all loaded metadata"""
        return self.metadata_store.copy()
