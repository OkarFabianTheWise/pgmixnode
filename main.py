from fastapi import Request
from fastapi.responses import JSONResponse
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import (
    pki_entry,
    Nenc,
    rand_subset,
    create_forward_message,
    PFdecode,
    Relay_flag,
    Dest_flag,
    receive_forward,
)
from sphinxmix.SphinxNode import sphinx_process
import argparse, uvicorn, os, asyncio
from fastappi_app import app

class Mixnet:
    """
    Mixnet implements secure and anonymous message transmission across 
    multiple nodes, ensuring privacy through cryptographic techniques.
    """

    def __init__(self, num_nodes=10):
        """
        Initialize the mixnet with nodes and their public-private keys.

        Args:
            num_nodes (int): The number of nodes in the mixnet.
        """
        try:
            self.params = SphinxParams()
            self.pkiPriv = {}  # Private keys of nodes
            self.pkiPub = {}   # Public keys of nodes
            self._initialize_nodes(num_nodes)
        except Exception as e:
            raise RuntimeError(f"Error initializing Mixnet: {e}")

    def _initialize_nodes(self, num_nodes):
        """
        Generate public-private key pairs for the mixnet nodes.

        Args:
            num_nodes (int): The number of nodes to initialize.

        Raises:
            Exception: If key generation fails.
        """
        try:
            for i in range(num_nodes):
                nid = i  # Node ID
                secret_key = self.params.group.gensecret()  # Generate private key
                public_key = self.params.group.expon(self.params.group.g, [secret_key])  # Derive public key
                self.pkiPriv[nid] = pki_entry(nid, secret_key, public_key)
                self.pkiPub[nid] = pki_entry(nid, None, public_key)
        except Exception as e:
            raise Exception(f"Error initializing nodes: {e}")

    async def send_message(self, message, dest):
        """
        Send a message through the mixnet.

        Args:
            message (str): The message to send.
            dest (str): The destination node identifier.

        Returns:
            str: The received message at the destination.

        Raises:
            Exception: If message sending or processing fails.
        """
        try:
            # Step 1: Choose random nodes for the message's path
            use_nodes = rand_subset(self.pkiPub.keys(), 5)

            # VC Explanation: Picking random nodes is like choosing an unpredictable route 
            # through multiple cities to avoid being followed.

            nodes_routing = list(map(Nenc, use_nodes))
            keys_nodes = [self.pkiPub[n].y for n in use_nodes]

            # VC Explanation: Nodes' public keys are like locks. Only the nodes can unlock 
            # them with their private keys, ensuring secure communication.

            # Step 2: Create the Sphinx packet
            header, delta = create_forward_message(
                self.params, nodes_routing, keys_nodes, dest.encode(), message.encode()
            )
            print(f"Message created for destination '{dest}'.")

            # Step 3: Process the message through the mixnet
            return await self._process_message(header, delta, use_nodes)
        except Exception as e:
            raise Exception(f"Error sending message: {e}")

    async def _process_message(self, header, delta, use_nodes):
        """
        Process the message through the mixnet nodes.

        Args:
            header: The Sphinx packet header.
            delta: The encrypted message payload.
            use_nodes (list): The list of nodes on the message path.

        Returns:
            str: The decrypted message at the destination.

        Raises:
            Exception: If message processing fails.
        """
        try:
            x = self.pkiPriv[use_nodes[0]].x  # Start with the first node's private key

            while True:
                # Process the message at the current mix node
                ret = sphinx_process(self.params, x, header, delta)
                tag, info, (header, delta), mac_key = ret
                routing = PFdecode(self.params, info)

                if routing[0] == Relay_flag:
                    # Relay to the next mix node
                    flag, addr = routing
                    x = self.pkiPriv[addr].x
                elif routing[0] == Dest_flag:
                    # Message reached the destination
                    dest, received_message = receive_forward(self.params, mac_key, delta)
                    print(f"Message received at destination '{dest.decode()}': {received_message.decode()}")
                    return received_message.decode()
        except Exception as e:
            raise Exception(f"Error processing message: {e}")

    async def explain_vc(self):
        """
        Provide a simple explanation for non-technical individuals (e.g., VCs).

        Key Concepts:
        1. **Anonymity**: Messages are sent through a random path of "couriers" (nodes), 
           and no courier knows the full path, only the next hop.
        2. **Encryption**: Messages are like nested envelopes; each node only opens its 
           envelope to learn where to pass the message next.
        3. **Security**: Public keys are like locks that only specific nodes can open with 
           their private keys, ensuring privacy and integrity.
        """
        print(self.explain_vc.__doc__)

    # async def receive_message(self, message, key):
    #     """Stub for handling received messages."""
    #     pass

@app.get("/mix")
async def mix_incoming_messages(request: Request):
    try:
        data = await request.json()
        message = data.get('message')

        mixnet = Mixnet()

        # async define the message and destination
        destination = "destination_node"

        # Send the message through the mixnet
        received_message = await mixnet.send_message(message, destination)

        if received_message:
            return JSONResponse({"data": received_message}, status_code=200)
        else:
            return JSONResponse({"data": "Failed to mix message!"}, status_code=200)
    except Exception as e:
        return JSONResponse({"data": e}, status_code=200)

# Fallback route for GET requests
@app.get('/')
async def fall_back_on_get_err():
    return "", 200

# Fallback route for POST requests
@app.post('/')
async def fall_back_on_post_err():
    return "", 200

# Route to handle favicon requests
@app.get("/favicon.ico")
async def favicon():
    return JSONResponse({"data": "invalid endpoint"}, status_code=200)

async def main():
    config = uvicorn.Config("fast_api_app:app", host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

async def couple():
    try:
        print("coupling")
        await asyncio.gather(main())
    except Exception as x:
        print("couple err:", x)

if __name__ == '__main__':
    asyncio.run(couple())

