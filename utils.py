import base64
import json


def json_dumps_bytes(dictionary: dict) -> bytes:
    def convert_bytes(obj):
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()
        if isinstance(obj, dict):
            return {k: convert_bytes(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [convert_bytes(elem) for elem in obj]
        return obj

    converted_dict = convert_bytes(dictionary)
    return json.dumps(converted_dict).encode()
