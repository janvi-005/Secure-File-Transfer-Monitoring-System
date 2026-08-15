import hashlib
import json
import os
from pathlib import Path
from datetime import datetime
from config import HASH_DB, HASH_ALGORITHM


class HashManager:
    def __init__(self):
        self.hash_db_path = HASH_DB
        self.hashes = self._load_hashes()

    def _load_hashes(self):
        if self.hash_db_path.exists():
            try:
                with open(self.hash_db_path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_hashes(self):
        self.hash_db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.hash_db_path, "w") as f:
            json.dump(self.hashes, f, indent=2)

    def compute_file_hash(self, file_path, algorithm=None):
        algorithm = algorithm or HASH_ALGORITHM
        try:
            hasher = hashlib.new(algorithm)
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, OSError) as e:
            return None

    def store_file_hash(self, file_path, algorithm=None):
        file_path = str(file_path)
        file_hash = self.compute_file_hash(file_path, algorithm)
        if file_hash:
            self.hashes[file_path] = {
                "hash": file_hash,
                "algorithm": algorithm or HASH_ALGORITHM,
                "timestamp": datetime.now().isoformat(),
                "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            }
            self._save_hashes()
            return file_hash
        return None

    def verify_file_integrity(self, file_path, expected_hash=None):
        file_path = str(file_path)

        if expected_hash is None and file_path in self.hashes:
            expected_hash = self.hashes[file_path]["hash"]

        if expected_hash is None:
            return {"status": "unknown", "message": "No stored hash found"}

        current_hash = self.compute_file_hash(file_path)
        if current_hash is None:
            return {"status": "error", "message": "Could not compute file hash"}

        if current_hash == expected_hash:
            return {"status": "verified", "message": "File integrity verified"}
        else:
            return {
                "status": "tampered",
                "message": "File has been modified",
                "expected": expected_hash,
                "actual": current_hash,
            }

    def remove_file_hash(self, file_path):
        file_path = str(file_path)
        if file_path in self.hashes:
            del self.hashes[file_path]
            self._save_hashes()
            return True
        return False

    def get_file_info(self, file_path):
        file_path = str(file_path)
        return self.hashes.get(file_path, None)

    def get_all_hashes(self):
        return self.hashes.copy()

    def get_stored_files(self):
        return list(self.hashes.keys())

    def cleanup_missing_files(self):
        removed = []
        for file_path in list(self.hashes.keys()):
            if not os.path.exists(file_path):
                del self.hashes[file_path]
                removed.append(file_path)
        if removed:
            self._save_hashes()
        return removed
