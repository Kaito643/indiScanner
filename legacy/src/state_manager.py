import json
import os
from threading import Lock

class StateManager:
    def __init__(self, state_file="state.json"):
        self.state_file = state_file
        self.lock = Lock()
        self.state = self.load_state()

    def load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}

    def save_state(self):
        with self.lock:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(self.state, f, indent=4)

    def get_state(self, group_name: str, source_name: str) -> dict:
        """
        Retrieves the state for a specific ransomware group and source.
        Returns an empty dict if no state exists.
        """
        group_state = self.state.get(group_name, {})
        return group_state.get(source_name, {})

    def update_state(self, group_name: str, source_name: str, data: dict):
        """
        Updates the state for a specific ransomware group and source.
        Merges with existing data.
        """
        if group_name not in self.state:
            self.state[group_name] = {}
        
        if source_name not in self.state[group_name]:
            self.state[group_name][source_name] = {}

        self.state[group_name][source_name].update(data)
        self.save_state()

    def mark_completed(self, group_name: str, source_name: str):
        self.update_state(group_name, source_name, {"completed": True})

    def is_completed(self, group_name: str, source_name: str) -> bool:
        return self.get_state(group_name, source_name).get("completed", False)
