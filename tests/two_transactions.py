import json
import sys
import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

# Add parent dir to sys.path

sys.path.append(str(Path.cwd()))

from node import RemoteNode, ServerRunner, make_transaction

# create nodes
runners = [ServerRunner("localhost", 9000 + i, f=1) for i in range(4)]

# start accepting incoming connections
for runner in runners:
    runner.start()

# connect other nodes
for i, runner in enumerate(runners):
    for j in range(4):
        if i != j:
            runner.append(RemoteNode("localhost", 9000 + j))

# create clients to send transactions
clients = [RemoteNode("localhost", 9000 + i) for i in range(4)]

# create a transaction
private_key1 = ed25519.Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex("6dee02b55d8914c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7aa")
)
transaction1 = make_transaction("hello", private_key1, 0)
private_key2 = ed25519.Ed25519PrivateKey.from_private_bytes(
    bytes.fromhex("543e02b55d8914c145568cb3f3b84586dea2a85910f5b062d7f3f29ddcb4c7bb")
)
transaction2 = make_transaction("world", private_key2, 0)

# set block callback
lock = threading.Lock()
cond = threading.Condition(lock)
blocks = []


def on_new_block(block):
    with lock:
        blocks.append(block)
        cond.notify()


for runner in runners:
    runner.blockchain.set_on_new_block(on_new_block)

# send the transaction
assert clients[0].transaction(transaction1) is True
assert clients[1].transaction(transaction2) is True

# wait for the block from all nodes
with lock:
    cond.wait_for(lambda: len(blocks) == 2 * len(runners))

# check that the transaction is committed
# assert all(block["transactions"][0] == transaction1 for block in blocks)
# assert all(block["transactions"][0] == transaction2 for block in blocks)

# stop the nodes
for runner in runners:
    runner.stop()
