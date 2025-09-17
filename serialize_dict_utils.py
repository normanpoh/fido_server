import base64
import re
import zlib
import pickle


def is_base64(input_string: str) -> bool:
    """
    Check if the input string is a valid base64-encoded string.
    """
    if not isinstance(input_string, str) or len(input_string) == 0:
        return False
    # Base64 strings must have a length that is a multiple of 4
    if len(input_string) % 4 != 0:
        return False
    base64_pattern = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
    if not base64_pattern.fullmatch(input_string):
        return False
    try:
        # Try decoding to ensure it's valid base64
        base64.b64decode(input_string, validate=True)
        return True
    except Exception:
        return False


def encode_compact_dict_pickle(mydict) -> str:
    compressed_data = zlib.compress(pickle.dumps(mydict))
    base64_encoded_data = base64.b64encode(compressed_data).decode("utf-8")
    return base64_encoded_data


def decode_compact_dict_pickle(base64_encoded_data: str) -> dict:
    assert is_base64(
        base64_encoded_data
    ), "base64_encoded_data should be in base64 format"
    try:
        compressed_data = base64.b64decode(base64_encoded_data)
        packed_data = zlib.decompress(compressed_data)
        my_dict = pickle.loads(packed_data)
    except Exception as e:
        raise ValueError(
            f"Failed to decode base64_encoded_data in decode_compact_dict(): {e}"
        )
    return my_dict


def test_encode_compact_dict():
    # Test
    test_dict = {"a": 1, "b": [1, 2, 3], "c": {"d": "hello"}}
    encoded = encode_compact_dict_pickle(test_dict)
    decoded = decode_compact_dict_pickle(encoded)
    print("Original:", test_dict)
    print("Decoded:", decoded)
    assert decoded == test_dict, "Round-trip encode/decode failed!"
    print("Test passed!")
