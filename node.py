import json
import socket
from datetime import datetime
from pathlib import Path
from threading import Lock, Thread
from time import sleep
from typing import Dict, List

from cryptography.hazmat.primitives.asymmetric import ed25519

from blockchain import Blockchain
from network import recv_prefixed, send_prefixed
from utils import json_dumps_bytes

lock = Lock()


def make_transaction(
    message: str, private_key: ed25519.Ed25519PrivateKey, nonce: int
) -> dict:
    sender = private_key.public_key().public_bytes_raw().hex()  # type: ignore
    signature = private_key.sign(message.encode()).hex()
    return {
        "sender": sender,
        "message": message,
        "signature": signature,
        "nonce": nonce,
    }


class RemoteNode:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    def transaction(self, transaction: dict) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.connect((self.host, self.port))
                send_prefixed(
                    sock,
                    json_dumps_bytes({"type": "transaction", "payload": transaction}),
                )
                return True
            except RuntimeError as e:
                print(f"RemoteNode transaction error: {e}")
                return False


class ServerRunner:
    def __init__(self, host: str, port: int, f: int) -> None:
        self.blockchain = Blockchain()
        self.host = host
        self.port = port
        self.f = f
        self.proposed_blocks: List = []

        self.connections: List[RemoteNode] = []
        self._block_proposals_received: Dict[RemoteNode, bool] = {}
        self.block_proposals_sent = 0

        self.server_thread = None
        self.execute_consensus_thread = None

        self.execute_consensus = False
        self.shutdown = False

        logs_folder = Path("logs")
        if not logs_folder.exists():
            logs_folder.mkdir()
        self.log_file = logs_folder / f"{port}_log.txt"
        with open(self.log_file, "w", encoding="utf-8"):
            pass

    def log(self, message):
        formatted_message = f"[{datetime.now():%F %T} | {self.port}] {message}\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(formatted_message)
        print(formatted_message)

    @property
    def block_proposals_received(self):
        return {
            k: v
            for k, v in self._block_proposals_received.items()
            if k in self.connections
        }

    @block_proposals_received.setter
    def block_proposals_received(self, value):
        self._block_proposals_received = value

    def consensus_protocol_event_loop(self):
        while not self.shutdown:
            if not self.execute_consensus:
                continue
            self.block_proposals_received = {k: False for k in self.connections}
            self.execute_consensus_protocol()
            self.execute_consensus = len(self.blockchain.pool) > 0

    def execute_consensus_protocol(self):
        self.log("Starting consensus protocol")
        sleep(2.5)
        with lock:
            new_block = self.blockchain.create_new_block(self.blockchain.pool)
            self.proposed_blocks.append(new_block)
            values_request = {"type": "values", "payload": self.blockchain.index}
        self.log(
            "Created proposed block for consensus protocol\n"
            + json.dumps(new_block, indent=2)
        )
        unsuccessful_sends = []
        for node in self.connections:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                succesful = False
                for _ in range(2):
                    try:
                        sock.connect((node.host, node.port))
                        send_prefixed(sock, json_dumps_bytes(values_request))
                        values_response = json.loads(recv_prefixed(sock))
                        existing_hashes = {
                            block["current_hash"] for block in self.proposed_blocks
                        }
                        self.proposed_blocks += [
                            block
                            for block in values_response
                            if block["current_hash"] not in existing_hashes
                        ]
                        succesful = True
                        self._block_proposals_received[node] = True
                        break
                    except (BlockingIOError, ConnectionResetError, socket.timeout):
                        sleep(1)  # Sleep for 1 second and try again
                    except ConnectionRefusedError:
                        break  # Stop trying if the connection is refused
                if not succesful:
                    unsuccessful_sends.append(node)
                    self.log(
                        f"Unable to reach node running at {(node.host, node.port)}. "
                        "Node will be removed from list of connections."
                    )
        self.connections = [
            node for node in self.connections if node not in unsuccessful_sends
        ]
        while not self.shutdown:
            any_blocks_non_empty = any(
                len(block["transactions"]) > 0 for block in self.proposed_blocks
            )
            if all(self.block_proposals_received.values()) and any_blocks_non_empty:
                # Decide on the minimum block (by lexicographically lowest transaction hash)
                decided_block = min(
                    (
                        block
                        for block in self.proposed_blocks
                        if len(block["transactions"]) > 0
                    ),
                    key=lambda b: b["current_hash"],
                )
                self.log("Decided on block, adding to blockchain:\n" + json.dumps(decided_block, indent=2))
                # Update the blockchain
                with lock:
                    self.blockchain.append_new_block(decided_block)
                self.log("Waiting for other nodes...")
                while self.block_proposals_sent != len(self.connections):
                    pass
                self.log("Consensus reached between all nodes")
                # Clear the list of proposed blocks
                self.proposed_blocks.clear()
                self.block_proposals_sent = 0
                break

    def run_server(self):
        self.log("Starting server...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(self.f + 1)

            while self.server_thread is not None:
                conn, addr = server.accept()
                try:
                    msg = recv_prefixed(conn)
                    self.log(f"Message received from {addr}")
                    if msg == b"shutdown":
                        self.shutdown = True
                        self.log("Shutdown instruction received")
                        break
                    msg = json.loads(msg)
                    msg_type = msg.get("type")
                    if msg_type == "transaction":
                        if self.blockchain.validate_transaction(msg["payload"]):
                            self.blockchain.pool.append(msg["payload"])
                            self.log(
                                "Transaction added to pool:\n"
                                + json.dumps(msg["payload"], indent=2)
                            )
                            send_prefixed(conn, b"accepted")
                            self.execute_consensus = True
                            self.log(
                                "Received transaction:\n"
                                + json.dumps(msg["payload"], indent=2)
                            )
                            continue
                        
                        self.log(
                                "Transaction rejected, not added to pool:\n"
                                + json.dumps(msg["payload"], indent=2)
                            )
                        send_prefixed(conn, b"rejected")
                    elif msg_type == "values":
                        send_prefixed(
                            conn,
                            json_dumps_bytes(self.proposed_blocks),
                        )
                        self.log(
                            "Received values request. Sending response:\n"
                            + json.dumps(self.proposed_blocks, indent=2)
                        )
                        self.block_proposals_sent += 1
                        self.execute_consensus = True
                    else:
                        self.log(f"Unexpected message received: {msg}")
                except Exception as e:
                    self.log(f"ServerRunner server error:\n{e.with_traceback()}")
                finally:
                    conn.close()

    def start(self):
        if self.server_thread is not None:
            return
        self.server_thread = Thread(target=self.run_server)
        self.server_thread.start()
        self.execute_consensus_thread = Thread(
            target=self.consensus_protocol_event_loop
        )
        self.execute_consensus_thread.start()

    def stop(self):
        if self.server_thread is None:
            return

        self.server_thread = None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            send_prefixed(sock, b"shutdown")

    def append(self, remote_node: RemoteNode):
        self.connections.append(remote_node)
