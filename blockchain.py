import json
from hashlib import sha256
from typing import Callable, Dict

from cryptography.hazmat.primitives.asymmetric import ed25519

BLOCKCHAIN_POOL_LIMIT = 3


class Blockchain:
    def __init__(self):
        self.chain = []
        self.chain.append(self.create_new_block([]))
        self.pool = []
        self.on_new_block = None
        self.sender_nonce_map: Dict[str, int] = {}

    @property
    def last_block(self):
        return self.chain[-1]

    @property
    def index(self):
        return len(self.chain)

    def set_on_new_block(self, on_new_block: Callable[[dict], None]):
        self.on_new_block = on_new_block

    def calculate_hash(self, block: dict):
        block_str = json.dumps(block, sort_keys=True)
        block_string = block_str.encode()
        raw_hash = sha256(block_string)
        hex_hash = raw_hash.hexdigest()
        return hex_hash

    def create_new_block(self, transactions, previous_hash=None):
        if len(self.chain) == 0:
            previous_hash = None
        else:
            previous_hash = previous_hash or self.last_block["current_hash"]
        block = {
            "index": self.index,
            "transactions": transactions,
            "previous_hash": previous_hash,
        }
        block["current_hash"] = self.calculate_hash(block)
        return block

    def append_new_block(self, block):
        self.pool = [
            t
            for t in self.pool
            if self.validate_transaction(t) and t not in block["transactions"]
        ]
        for sender in [t["sender"] for t in block["transactions"]]:
            if sender not in self.sender_nonce_map:
                self.sender_nonce_map[sender] = 1
            else:
                self.sender_nonce_map[sender] += 1
        self.chain.append(block)
        self.on_new_block(block)

    def validate_transaction(self, transaction: dict) -> bool:
        try:
            if len(self.pool) + 1 > BLOCKCHAIN_POOL_LIMIT:
                # print("if len(self.pool) + 1 > BLOCKCHAIN_POOL_LIMIT:")
                return False
            if len(transaction) != 4:
                return False
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(transaction["sender"])
            )
            if len(transaction["message"]) > 70 or not transaction["message"].isalnum():
                return False
            public_key.verify(
                bytes.fromhex(transaction["signature"]), transaction["message"].encode()
            )
            if transaction["sender"] not in self.sender_nonce_map:
                self.sender_nonce_map[transaction["sender"]] = 0
            if transaction["nonce"] != self.sender_nonce_map[transaction["sender"]]:
                return False

            return True
        except Exception:
            return False
