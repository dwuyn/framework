import pickle
import os
from langgraph.checkpoint.memory import MemorySaver

def _to_dict(d):
    if isinstance(d, dict):
        return {k: _to_dict(v) for k, v in d.items()}
    return d

def _from_dict(d, target_dict):
    for k, v in d.items():
        if isinstance(v, dict):
            _from_dict(v, target_dict[k])
        else:
            target_dict[k] = v

class _DiskBackedSaver(MemorySaver):
    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    data = pickle.load(f)
                if "storage" in data:
                    _from_dict(data["storage"], self.storage)
                if "writes" in data:
                    _from_dict(data["writes"], self.writes)
                if "blobs" in data and hasattr(self, "blobs"):
                    _from_dict(data["blobs"], self.blobs)
                print(f"Restored from {path}")
            except Exception as exc:
                print(f"Could not load checkpoint: {exc}")

    def put(self, config, checkpoint, metadata, new_versions):
        result = super().put(config, checkpoint, metadata, new_versions)
        try:
            data = {
                "storage": _to_dict(self.storage),
                "writes": _to_dict(self.writes),
            }
            if hasattr(self, "blobs"):
                data["blobs"] = _to_dict(self.blobs)
            with open(self._path, "wb") as f:
                pickle.dump(data, f)
            print("Checkpoint saved")
        except Exception as exc:
            print(f"Could not save checkpoint: {exc}")
        return result

if __name__ == "__main__":
    config = {"configurable": {"thread_id": "test", "checkpoint_ns": ""}}
    saver = _DiskBackedSaver("data/test_cp.pkl")
    saver.put(config, {"ts": "123", "id": "1", "channel_values": {"msg": "hello"}}, {}, {"ts": "123"})
    print(saver.storage)

    saver2 = _DiskBackedSaver("data/test_cp.pkl")
    print(saver2.storage)
