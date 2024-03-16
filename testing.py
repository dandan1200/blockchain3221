from node import *
import threading

# private key for transactions
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex('5a4e02655d8214c145568cb3f3b84586ead2a85910f5b062d7f3f29ddcb4c7aa'))

# create nodes
runners = [ServerRunner('10.48.65.59', 9000, f=0)]

# 10.19.227.141

# start accepting incoming connections
for runner in runners:
    runner.start()

runners[0].append(RemoteNode('10.48.65.35', 9000))

# connect other nodes
# for i, runner in enumerate(runners):
#     for j in range(4):
#         if i != j:
#             runner.append(RemoteNode('localhost', 9000 + j))

# create clients to send transactions
clients = [RemoteNode('10.48.65.59', 9000)]

# create a transaction
transaction = make_transaction('hellofromdaniel', private_key, 0)

#transaction2 = make_transaction('howareyou', private_key, 1)

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
assert(clients[0].transaction(transaction) == True)

# runners[2].stop()
# runners.pop(2)

# wait for the block from all nodes
while True:
    with lock:
        cond.wait_for(lambda: len(blocks) == len(runners))

# check that the transaction is committed
# assert(all([block['transactions'][0] == transaction for block in blocks]))

# blocks = []

# assert(clients[1].transaction(transaction2) == True)

# # wait for the block from all nodes
# with lock:
#     cond.wait_for(lambda: len(blocks) == len(runners))

# # check that the transaction is committed
# assert(all([block['transactions'][0] == transaction2 for block in blocks]))

# stop the nodes
for runner in runners:
    runner.stop()