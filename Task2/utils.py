import json
import os


def load_db(FILE_NAME):
    if not os.path.exists(FILE_NAME):
        return []
    try:
        with open(FILE_NAME, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def save_to_db(FILE_NAME, FILE_DATA):
    with open(FILE_NAME, "w", encoding="utf-8") as f:
        json.dump(FILE_DATA, f, indent=4)
