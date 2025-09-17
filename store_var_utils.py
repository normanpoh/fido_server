import os

import h5py
import json
import numpy as np
from typing import Any, Dict

import pandas as pd
from logging_utils import logging_info
from json_utils import json_flatten
import time


def save_variable(h5file: h5py.File, namespace: str, name: str, value: Any) -> None:
    """Automatically infer and save variable type to HDF5 under a specified namespace."""
    # Create namespace if it doesn't exist
    group = h5file.require_group(namespace)

    # Check if the dataset already exists
    if name in group:
        # print(f"Warning: Dataset '{name}' already exists in namespace '{namespace}'. Overwriting.")
        del group[name]

    if isinstance(value, (list, tuple)):
        if all(isinstance(x, str) for x in value):
            group.create_dataset(
                name, data=np.array(value, dtype=h5py.string_dtype(encoding="utf-8"))
            )
        else:
            group.create_dataset(name, data=np.array(value))
    elif isinstance(value, dict):
        # Convert dictionary to JSON and save it
        json_str = json.dumps(value)
        group.create_dataset(name, data=json_str.encode("utf-8"))
    elif isinstance(value, str):
        # Save string directly
        group.create_dataset(name, data=value.encode("utf-8"))
    elif isinstance(value, (np.ndarray)):
        group.create_dataset(name, data=value)
    elif isinstance(value, (int, float, bool)):
        group.create_dataset(name, data=np.array(value))
    else:
        raise ValueError(f"Unsupported data type: {type(value)} for variable: {name}")


def load_variable(h5file: h5py.File, namespace: str, name: str) -> Any:
    """Load variable from HDF5 under a specified namespace, inferring its type."""
    data = h5file[namespace][name][()]

    if isinstance(data, bytes):
        # Attempt to decode bytes to JSON
        try:
            json_str = data.decode("utf-8")
            return json.loads(json_str)
        except json.JSONDecodeError:
            # Return as string if it's not valid JSON
            return json_str
    elif isinstance(data, np.ndarray):
        # Check if the dtype is object (which may contain string data)
        if data.dtype == h5py.string_dtype(encoding="utf-8"):
            # Decode the array of strings from bytes to normal strings
            return [d.decode("utf-8") for d in data]
        return data
    else:
        # Return other types as is
        return data


def save_data(filename: str, namespace: str, **kwargs: Any) -> None:
    """Save multiple variables under a specified namespace."""
    print(f"Saving namespace '{namespace}'")
    with open_h5(filename, "a") as h5file:  # Open in append mode
        for name, value in kwargs.items():
            save_variable(h5file, namespace, name, value)


def retrieve_data(filename: str, namespace: str) -> Dict[str, Any]:
    """Retrieve all variables from a specified namespace."""
    data_dict = {}
    with h5py.File(filename, "r") as h5file:
        for name in h5file[namespace].keys():
            data_dict[name] = load_variable(h5file, namespace, name)
    return data_dict


def retrieve_all_namespaces(filename: str) -> Dict[str, Dict[str, Any]]:
    """Retrieve all variables from all namespaces in the HDF5 file."""
    all_data = {}
    with h5py.File(filename, "r") as h5file:
        for namespace in h5file.keys():
            data_dict = {}
            for name in h5file[namespace].keys():
                data_dict[name] = load_variable(h5file, namespace, name)
            all_data[namespace] = data_dict
    return all_data


def restore_to_globals(data_dict: Dict[str, Any]) -> None:
    """Restore variables in data_dict to the global namespace."""
    for name, value in data_dict.items():
        globals()[name] = value


def open_h5(hdf_file_path, mode="a") -> h5py.File:
    if not os.path.exists(hdf_file_path):
        store = pd.HDFStore(hdf_file_path, mode="w", complevel=9, complib="blosc:zstd")
        store.close()

    # The change below allows simultaneous access to the HDF5 file,
    # provided that the file is closed immediately when not in use.
    store = None
    while True:
        try:
            store = h5py.File(hdf_file_path, mode)
            break
        except OSError:
            logging_info(
                f"Failed to open HDF5 file: {hdf_file_path}. Retrying after sleeping for 1 second"
            )
            time.sleep(1)
            logging_info("Retrying...")
            continue
    assert store is not None, f"Failed to open HDF5 file: {hdf_file_path}"
    return store


class HDF5DictStore:
    def __init__(
        self,
        hdf_file_path: str,  # = config["hdf_file_path"][config["env_default"]],
        namespace: str = "locals",
        verbose: bool = False,
    ) -> None:
        self.filename = hdf_file_path
        logging_info(f"hdf_file_path: {self.filename}", verbose=verbose)
        self.namespace = namespace
        self.store = open_h5(hdf_file_path, "a")
        return

    def namespace_exists(self, namespace: str) -> bool:
        return namespace in self.store.keys()

    def list(self, namespace: str | None = None) -> list:
        if namespace is None:
            namespace = self.namespace

        if namespace in self.store:
            return list(self.store[namespace].keys())
        else:
            return []

    def delete_variable(self, name: str, namespace: str = None) -> None:
        if namespace is None:
            namespace = self.namespace

        if name in self.list(namespace):
            del self.store[namespace][name]
            logging_info(f"> Deleted variable: {name} in namespace: {namespace}")
        else:
            logging_info(f"> Variable: {name} does not exist in namespace: {namespace}")

        return

    def update_variable(
        self,
        name: str,
        value: dict,
        namespace: str | None = None,
        verbose: bool = True,
        value_is_dict: bool = True,
    ) -> None:
        if namespace is None:
            namespace = self.namespace

        if name not in self.store[namespace]:
            self.save_variable(name, value, namespace)
        else:
            logging_info(
                f"> Updating variable: {name} in namespace: {namespace}",
                verbose=verbose,
            )
            updated_value = self.load_variable(name, namespace)
            if value_is_dict:
                assert isinstance(
                    value, dict
                ), "The input value must be Python dictionary"
                updated_value.update(value)
            else:
                updated_value = value
            self.save_variable(name, updated_value, namespace)

        return

    def save_variable(
        self, name: str, value: Any, namespace: str | None = None
    ) -> None:
        if namespace is None:
            namespace = self.namespace
        save_variable(self.store, namespace, name, value)
        return

    def load_variable(self, name: str, namespace: str | None = None) -> Any:
        if namespace is None:
            namespace = self.namespace

        if name in self.list(namespace):
            return load_variable(self.store, namespace, name)
        else:
            return None

    def load_all_variables(self, namespace: str | None = None) -> dict:
        if namespace is None:
            namespace = self.namespace

        dict_out = {}
        for name in self.list(namespace):
            dict_out[name] = load_variable(self.store, namespace, name)

        return dict_out

    def close(self, verbose: bool = False) -> None:
        logging_info(f"Closing HDF5 file: {self.filename}", verbose)
        self.store.close()
        return

    def export_all_variables(self, namespace: str | None = None) -> pd.DataFrame | None:
        if namespace is None:
            namespace = self.namespace

        session_id_list = self.list(namespace)
        if len(session_id_list) > 0:
            list_ = []
            session_dict = self.load_all_variables(namespace)
            for session_id in session_id_list:
                list_.append(json_flatten(session_dict[session_id]))

            df = pd.DataFrame(list_)
            return df
        else:
            logging_info(f"The namespace {namespace} does not exist")
            return


def save_dict_to_h5(dict_name: str, name: str, value: any, hdf_file_path: str):
    h5 = HDF5DictStore(hdf_file_path=hdf_file_path)
    dict_ = h5.load_variable(dict_name)
    if dict_ is None:
        dict_ = {name: value}
    else:
        dict_.update({name: value})
    h5.save_variable(dict_name, dict_)
    h5.close()


########################################################################################################################
# Test functions


def test_store_var_utils(output: str):
    filename = f"{output}/test_data_store.h5"
    namespace = "my_namespace"  # Specify the namespace

    # Example variables to save
    fruits = ["apple", "banana", "cherry"]
    numbers = [1, 2, 3, 4, 5]
    json_data = {"name": "Alice", "age": 25, "city": "Wonderland"}  # JSON object
    pi = 3.14159
    is_raining = False

    # Step 1: Save data using the variable names directly under a specified namespace
    save_data(
        filename,
        namespace,
        fruits=fruits,
        numbers=numbers,
        json_data=json_data,
        pi=pi,
        is_raining=is_raining,
    )

    print(f"Data saved to {filename} under namespace '{namespace}'")

    # Step 2: Retrieve data from the specified namespace
    retrieved_data = retrieve_data(filename, namespace)

    print("\nRetrieved Data:")
    for name, value in retrieved_data.items():
        print(f"{name}: {value}")

    # Step 3: Restore to globals
    restore_to_globals(retrieved_data)

    print("\nVariables restored to globals:")
    for name in retrieved_data.keys():
        print(f"{name}: {globals()[name]}")


def test_hdf5store(output: str):
    h5 = HDF5DictStore(hdf_file_path=f"{output}/test.h5")
    h5.save_variable("test", [1, 2, 3])
    h5.save_variable("test_dict", {"value": [1, 2, 3]})
    h5.update_variable(name="test_dict", value={"toto": 3})
    json_data = {"name": "Alice", "age": 25, "city": "Wonderland"}  # JSON object
    h5.save_variable("my", json_data)
    assert all(h5.load_variable("test") == np.array([1, 2, 3]))
    assert h5.load_variable("my") == json_data
    assert h5.load_variable("test_dict") == {"value": [1, 2, 3], "toto": 3}
    assert h5.list() == ["my", "test", "test_dict"]
    h5.close()
    return


########################################################################################################################
# Convenience functions for storing and retrieving variables from HDF5 files


def read(var_name: str, hdf_file_path: str, namespace="locals") -> dict | None:
    h5 = HDF5DictStore(hdf_file_path)
    token_ = h5.load_variable(var_name, namespace=namespace)
    h5.close()
    return token_


def write(var_name: str, value: dict, hdf_file_path: str, namespace="locals") -> None:
    h5 = HDF5DictStore(hdf_file_path=hdf_file_path)
    h5.save_variable(var_name, value, namespace=namespace)
    h5.close()
    return


def list_all(hdf_file_path: str, namespace="locals") -> dict:
    h5 = HDF5DictStore(hdf_file_path=hdf_file_path)
    var_dict = h5.load_all_variables(namespace=namespace)
    h5.close()
    return var_dict
