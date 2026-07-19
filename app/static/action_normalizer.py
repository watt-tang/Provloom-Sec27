from __future__ import annotations

from app.static.action_schema import ACTION_TYPES, StaticAction


VERB_MAP = {
    "fetch": "DOWNLOAD",
    "retrieve": "DOWNLOAD",
    "download": "DOWNLOAD",
    "send": "SEND",
    "post": "SEND",
    "transmit": "SEND",
    "upload": "UPLOAD",
    "run": "EXECUTE",
    "execute": "EXECUTE",
    "launch": "EXECUTE",
    "invoke": "EXECUTE",
    "store": "WRITE",
    "save": "WRITE",
    "write": "WRITE",
    "read": "READ",
    "load": "READ",
    "inspect": "READ",
}


class ActionNormalizer:
    def normalize(self, actions: list[StaticAction]) -> list[StaticAction]:
        for action in actions:
            raw = action.raw_verb.lower().strip()
            if action.action_type not in ACTION_TYPES:
                action.action_type = VERB_MAP.get(raw, "UNKNOWN_SECURITY_ACTION")
                action.normalization_method = "verb_map_fallback"
            elif raw in VERB_MAP and VERB_MAP[raw] != action.action_type:
                action.metadata["pre_normalized_action_type"] = action.action_type
                action.action_type = VERB_MAP[raw]
                action.normalization_method = "verb_map"
        return actions
