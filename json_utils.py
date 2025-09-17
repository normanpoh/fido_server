import json
import os
from typing import Any
import pandas as pd
import numpy as np
from logging_utils import logging_info


class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return json.JSONEncoder.default(self, obj)


def convert_scalar_dict_to_basic_type(response_dict, verbose: bool = True) -> dict:
    keys_to_delete = []
    for k, v in response_dict.items():
        if v is None:
            keys_to_delete.append(k)
            continue
        if isinstance(v, str):
            response_dict[k] = str(v)
        elif isinstance(v, int) or isinstance(v, np.int32) or isinstance(v, np.int64):
            response_dict[k] = int(v)
        elif (
            isinstance(v, float)
            or isinstance(v, np.float32)
            or isinstance(v, np.float64)
        ):
            response_dict[k] = float(v)
        elif isinstance(v, bool) or isinstance(v, np.bool_):
            response_dict[k] = bool(v)
        else:
            raise ValueError(f"Unknown type {type(v)} for key {k}")

    if len(keys_to_delete) > 0:
        logging_info(
            f"Deleting keys {keys_to_delete} because each one is None", verbose=verbose
        )

        for k in keys_to_delete:
            del response_dict[k]

    assert all(
        [
            isinstance(k, str)
            or isinstance(k, float)
            or isinstance(k, int)
            or isinstance(k, bool)
            for k in response_dict.values()
        ]
    ), "The values of response_dict must be a scalar value of type str, float, or int"

    return response_dict


def json_flatten(dict_: dict, prefix: str = None) -> dict:
    """
    Recursively flatten an input dictionary. E.g., a dictionary with values who are a dictionary will be flattened to
    (key, value) wherein the value can be a list of features a scalar value but cannot be a dictionary because the
    dictionary would have been recursively flattened.

    :param max_level:
    :param dict_: input dictionary
    :param prefix: prefix to the key in the dictionary (supply None only)
    :return: A flattened dictionary

    # Example 1:
    # Input
        flatten_dict({
        "key0": "value0",
        "key1": {
            "key2": "value2",
            "key3": {"key4": "value4"}
            }
        })
    # Output:
        {'key0': 'value0', 'key1.key2': 'value2', 'key1.key3.key4': 'value4'}

    # Example 2:
    # Input
        flatten_dict(
            {"key0": "value0",
             "key1":
                 {"key2": "value2",
                  "list": [{"list1": "value4"}, {"list2": "value5"}]
                  }
             }
        )
    # Output:
    {
        'key0': 'value0',
        'key1.key2': 'value2',
        'key1.list[0].list1': 'value4',
        'key1.list[1].list2': 'value5'
    }
    """
    prefix_is_None = True if prefix is None else False

    if prefix_is_None:
        prefix = "temp"
    dict_out = json_flatten_obj(dict_, prefix)
    if prefix_is_None:
        return json_remove_prefix_dict(dict_out)
    else:
        return dict_out


def json_flatten_obj(obj_: Any, prefix: str) -> dict:
    dict_out = {}
    if isinstance(obj_, list):
        dict_out.update(json_flatten_list(obj_, prefix))
    elif isinstance(obj_, dict):
        dict_out.update(json_flatten_dict(obj_, prefix))
    else:
        dict_out = {prefix: obj_}
    return dict_out


def json_flatten_dict(dict_: dict, prefix: str) -> dict:
    dict_out = {}
    for k, v in dict_.items():
        dict_out_ = json_flatten_obj(v, f"{prefix}.{k}" if prefix else k)
        dict_out.update(dict_out_)
    return dict_out


def json_flatten_list(list_: list, prefix: str) -> dict:
    dict_out = {}
    for i_, item_ in enumerate(list_):
        dict_out_ = json_flatten_obj(item_, f"{prefix}[{i_}]")
        dict_out.update(dict_out_)
    return dict_out


def json_remove_prefix_dict(dict_: dict) -> dict:
    dict_out = {}
    for k, v in dict_.items():
        key_ = ".".join(k.split(".")[1:])
        dict_out[key_] = v
    return dict_out


def json_prefix_dict(dict_: dict, prefix: str) -> dict:
    dict_out = {}
    for k, v in dict_.items():
        dict_out[f"{prefix}.{k}"] = v
    return dict_out


def json_parse_filelist(json_filelist: list) -> pd.DataFrame:
    df_json = pd.DataFrame(json_filelist)
    df_json.columns = ["filepath"]
    df_json["basename"] = [
        os.path.basename(x).split(".")[0] for x in df_json["filepath"]
    ]

    df_result_list = []

    for i, row in df_json.iterrows():
        with open(row["filepath"]) as f:
            data = json.load(f)
            parsed_dict = row.to_dict()
            parsed_dict.update(json_flatten(data))
            df_result_list.append(parsed_dict)

    df_result = pd.DataFrame(df_result_list)
    return df_result
