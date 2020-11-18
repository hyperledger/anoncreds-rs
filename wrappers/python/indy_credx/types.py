from typing import Sequence

from . import bindings


class Schema(bindings.IndyObject):
    @classmethod
    def create(
        self,
        origin_did: str,
        name: str,
        version: str,
        attr_names: Sequence[str],
        seq_no: int = None,
    ) -> "Schema":
        return Schema(
            bindings.create_schema(origin_did, name, version, attr_names, seq_no)
        )
