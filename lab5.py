'''
Seattle University CPSC - 5200 Distributed Systems FQ2024
Author: Aarti Dashore
SU ID: 4216460
Version: V.0.0.1
'''
import socket
import struct
import hashlib
import time
import random
import traceback

MAGIC = b'\xf9\xbe\xb4\xd9'

# Bitcoin message format
VERSION = b'version'
VERACK = b'verack'
GETBLOCKS = b'getblocks'
INV = b'inv'
GETBLOCK = b'getblock'


class BitcoinMessage:
    def __init__(self, command, payload=b''):
        self.magic = MAGIC
        if isinstance(command, str):  # Check if command is a regular string
            command = command.encode('utf-8')  # Convert to bytes using UTF-8 encoding
        self.command = command + b'\x00' * (12 - len(command))  # Pad with bytes to make the command 12 bytes long
        self.payload = payload
        self.payload_size = len(payload)
        self.checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]  # Double SHA256 checksum

    def create_message(self):
        # Structure the message: Magic + Command + Payload Size + Checksum + Payload
        header = self.magic + self.command + struct.pack('<L', self.payload_size) + self.checksum
        return header + self.payload

    def print_message(self, action):
        try:
            # Convert message to hex format
            message = self.create_message()
            hex_message = message.hex()
            print(f"{action} MESSAGE")
            print(f"({len(message)}) {hex_message}")
            print("  HEADER")
            print("  --------------------------------------------------------")
            
            # Ensure the message is at least 24 bytes long (for magic, command, payload size, and checksum)
            if len(message) < 24:
                print("Error: Message too short to unpack properly.")
                return
            
            # Parse and display the header
            magic = message[:4]
            command = message[4:16].strip(b'\x00')  # Strip null bytes properly
            command = command.decode('utf-8', errors='ignore')  # Ignore errors in case of invalid bytes
            
            # Check that there is enough length to unpack payload size and checksum
            if len(message) >= 24:
                payload_size = struct.unpack('<L', message[16:20])[0]
            else:
                print("Error: Payload size field is missing or incomplete.")
                return
            
            checksum = message[20:24].hex()
            
            print(f"    {magic.hex()}                         magic")
            print(f"    {command.ljust(24)}         command: {command}")
            print(f"    {payload_size:08x}                         payload size: {payload_size}")
            print(f"    {checksum}                         checksum (verified)")

            # If the command is 'version', parse and display the version-specific fields
            if command == 'version':
                self.parse_version(message)
            elif command == 'verack':
                print("  RECEIVED VERACK")
                print("  --------------------------------------------------------")
                print(f"    No payload for verack")
            elif command == 'inv':
                self.parse_inv(message)
            elif command == 'getblocks':
                print("Received Getblocks message")
            
        except Exception as e:
            print(f"Error printing message: {str(e)}")
    
    def parse_version(self, message):
        try:
            # Parse the version-specific data from the message
            version_data = message[24:]  # Version-specific data starts after the header (24 bytes)
            
            if len(version_data) < 56:  # Check if version data is too short
                print("Error: Incomplete version message data")
                return
            
            version = struct.unpack('<L', version_data[:4])[0]
            services = struct.unpack('<Q', version_data[4:12])[0]
            timestamp = struct.unpack('<Q', version_data[12:20])[0]
            addr_recv = version_data[20:34]
            addr_recv_ip = '.'.join(str(x) for x in addr_recv[:4])
            addr_recv_port = struct.unpack('<H', addr_recv[4:6])[0]
            addr_from = version_data[34:48]
            addr_from_ip = '.'.join(str(x) for x in addr_from[:4])
            addr_from_port = struct.unpack('<H', addr_from[4:6])[0]
            nonce = version_data[48:56]
            user_agent_size = version_data[56]
            user_agent = version_data[57:57 + user_agent_size].decode('utf-8', errors='ignore')
            start_height = struct.unpack('<L', version_data[57 + user_agent_size:61 + user_agent_size])[0]
            relay = bool(version_data[61 + user_agent_size])
            
            # Print Version Information
            print(f"  VERSION")
            print(f"  --------------------------------------------------------")
            print(f"    {version:08x}                         version {version}")
            print(f"    {services:016x}                         my services")
            print(f"    {timestamp}                         epoch time {time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(timestamp))}")
            print(f"    {services:016x}                     your services")
            print(f"    {''.join([f'{x:02x}' for x in addr_recv])} your host {addr_recv_ip}")
            print(f"    {addr_recv_port:04x}                         your port {addr_recv_port}")
            print(f"    {''.join([f'{x:02x}' for x in addr_from])} my host {addr_from_ip}")
            print(f"    {addr_from_port:04x}                         my port {addr_from_port}")
            print(f"    {nonce.hex()}                         nonce")
            print(f"    {user_agent_size}                               user agent size {user_agent_size}")
            print(f"    {user_agent}                         user agent '{user_agent}'")
            print(f"    {start_height}                         start height {start_height}")
            print(f"    {relay}                               relay {relay}")
            
        except Exception as e:
            print(f"Error parsing version message: {str(e)}")

    def parse_inv(self, message):
        # Parse the 'inv' message, which contains the inventory of items (block hashes)
        try:
            payload = message[24:]
            count = struct.unpack('<L', payload[:4])[0]  # Number of inventory items
            print(f"  RECEIVED INV MESSAGE")
            print(f"  --------------------------------------------------------")
            print(f"    {count} inventory items")

            inventory = payload[4:]
            for i in range(count):
                inv_type = struct.unpack('<L', inventory[:4])[0]
                inv_hash = inventory[4:36].hex()
                print(f"    {inv_type} {inv_hash}")
                inventory = inventory[36:]
                # We need to handle the block hashes later to request blocks
                if inv_type == 1:  # Block type
                    self.request_block_data(inv_hash)

        except Exception as e:
            print(f"Error parsing inv message: {str(e)}")
    
    def request_block_data(self, block_hash):
        # Send a getblock message to request the block by its hash
        getblock_message = BitcoinMessage(
            GETBLOCK, 
            struct.pack('<L', 1) + b'\x01' + bytes.fromhex(block_hash)
        )
        self.send_message(getblock_message)
    
    def handle_block_data(self, block_data):
        # Parse the block data and check for the transaction related to SU_ID
        block_hash = block_data[:32].hex()  # Block hash in block data
        print(f"Received block data for {block_hash}")
        # We should parse and process the block's transactions here 
        transactions = block_data[32:]  # The rest is transaction data 
        print(f"Transactions in block {block_hash}:")
        
        while len(transactions) >= 32:  # Transaction hash length
            tx_hash = transactions[:32].hex()
            print(f"  {tx_hash}")
            transactions = transactions[32:]

    def send_message(self, message):
        #Sending a message
        print(f"Sending message: {message.command.strip(b'\x00').decode()}")  
        message.print_message("sending")

    def receive_message(self, raw_message):
        # This function simulates receiving a message and parsing it.
        try:
            # Convert raw message into a BitcoinMessage object for printing
            magic = raw_message[:4]
            command = raw_message[4:16].strip(b'\x00').decode('utf-8', errors='ignore')
            payload_size = struct.unpack('<L', raw_message[16:20])[0]
            checksum = raw_message[20:24].hex()
            print(f"received MESSAGE")
            print(f"({len(raw_message)}) {raw_message.hex()}")
            print(f"  HEADER")
            print(f"  --------------------------------------------------------")
            print(f"    {magic.hex()}                         magic")
            print(f"    {command.ljust(24)}         command: {command}")
            print(f"    {payload_size:08x}                         payload size: {payload_size}")
            print(f"    {checksum}                         checksum (verified)")

            # If the command is 'version', parse and display the version-specific fields
            if command == 'version':
                message = BitcoinMessage(command, raw_message[24:])  # create BitcoinMessage for parsing
                message.parse_version(raw_message)
                
            elif command == 'getblocks':
                print("Received Getblocks message")
            
            elif command == 'inv':
                message = BitcoinMessage(command, raw_message[24:])  # create BitcoinMessage for parsing
                message.parse_inv(raw_message)
            
            elif command == 'getblock':
                self.handle_block_data(raw_message[24:])  # Handle block data

            return {'magic': magic, 'command': command, 'payload_size': payload_size, 'checksum': checksum}
        except Exception as e:
            print(f"Error receiving message: {str(e)}")
            return {"error": str(e)}


class BitcoinPeer:
    def __init__(self, ip='31.47.202.112', port=8333):
        self.ip = ip
        self.port = port
        self.sock = None

    def connect(self):
        """Establish a connection to the Bitcoin peer."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.ip, self.port))
            print(f"Connected to {self.ip}:{self.port}")
        except Exception as e:
            print(f"Error connecting to peer {self.ip}:{self.port} - {str(e)}")

    def send_message(self, message):
        """Send a message to the connected peer."""
        try:
            full_message = message.create_message()  # Create the full message
            self.sock.sendall(full_message)
            print(f"Sent message: {message.command.strip(b'\x00').decode()}")  # Debug print
            message.print_message("sending")
        except Exception as e:
            print(f"Error sending message: {str(e)}")
    
    def receive_message(self):
        """Receive a message from the connected peer."""
        try:
            raw_message = self.sock.recv(1024)  # Receiving 1024 bytes
            if not raw_message:
                print("No data received from peer.")
                return None
            print(f"Received raw message: {raw_message.hex()}")
            message = BitcoinMessage(raw_message[4:16].strip(b'\x00').decode(), raw_message[24:])
            message.print_message("received")
            return message
        except Exception as e:
            print(f"Error receiving message: {str(e)}")
            return None
        
    def close(self):
        """Close the socket connection."""
        try:
            self.sock.close()
            print(f"Connection closed with {self.ip}:{self.port}")
        except Exception as e:
            print(f"Error closing connection: {str(e)}")


# Define some utility functions
def calculate_block_hash_from_suid(suid):
    # Block number corresponding to your SU ID modulo 10,000
    block_number = suid % 10000
    # Simulate getting the hash for that block (typically you would query the node)
    block_hash = hashlib.sha256(str(block_number).encode()).hexdigest()
    return block_hash


def recalculate_merkle_root(transactions):
    # Placeholder function to recalculate the Merkle root
    tx_hashes = [hashlib.sha256(tx.encode()).hexdigest() for tx in transactions]
    while len(tx_hashes) > 1:
        temp_hashes = []
        for i in range(0, len(tx_hashes), 2):
            combined = tx_hashes[i] + tx_hashes[i + 1] if i + 1 < len(tx_hashes) else tx_hashes[i] + tx_hashes[i]
            temp_hashes.append(hashlib.sha256(combined.encode()).hexdigest())
        tx_hashes = temp_hashes
    return tx_hashes[0]


def manipulate_transaction(block, transaction_index):
    # Specific transaction’s output by changing its output address.
    transactions = block['transactions']
    original_tx = transactions[transaction_index]
    modified_tx = original_tx.replace("output_account", "modified_account")
    transactions[transaction_index] = modified_tx
    
    # Recalculate Merkle root after modification
    new_merkle_root = recalculate_merkle_root(transactions)
    
    # Update the block with the new Merkle root and block hash
    block['transactions'] = transactions
    block['merkle_root'] = new_merkle_root
    block['block_hash'] = hashlib.sha256(new_merkle_root.encode()).hexdigest()
    return block



def get_block_from_network(block_hash):
    block = {
        'hash': block_hash,
        'merkle_root': 'original_merkle_root',
        'transactions': ['tx1_output_account', 'tx2_output_account'],
        'block_hash': hashlib.sha256('original_merkle_root'.encode()).hexdigest()
    }
    return block


# Define your block structure and utility functions
class Block:
    def __init__(self, block_hash, merkle_root, transactions):
        self.block_hash = block_hash
        self.merkle_root = merkle_root
        self.transactions = transactions

    def calculate_merkle_root(self):
        """
        Recalculates the Merkle root of the current block's transactions.
        """
        # Assuming transactions are represented as their transaction hashes.
        tx_hashes = [tx.txid for tx in self.transactions]  # Replace txid with actual transaction hashes
        return self._compute_merkle_root(tx_hashes)

    @staticmethod
    def _compute_merkle_root(tx_hashes):
        """
        Compute the Merkle root from transaction hashes.
        """
        while len(tx_hashes) > 1:
            if len(tx_hashes) % 2 == 1:
                tx_hashes.append(tx_hashes[-1])  # Duplicate last element if odd number of transactions
            tx_hashes = [hashlib.sha256(hashlib.sha256(tx_hashes[i].encode('utf-8') + tx_hashes[i + 1].encode('utf-8')).digest()).digest() 
                         for i in range(0, len(tx_hashes), 2)]
        return tx_hashes[0].hex()  # Convert the final Merkle root to hex

    def update_transaction_output(self, tx_index, new_output):
        """
        Update a specific transaction's output and modify the block accordingly.
        """
        if 0 <= tx_index < len(self.transactions):
            tx = self.transactions[tx_index]
            tx.update_output(new_output)
            self.merkle_root = self.calculate_merkle_root()
            self.block_hash = self.compute_block_hash()
        else:
            raise IndexError("Transaction index out of range")

    def compute_block_hash(self):
        """
        Recalculate the block hash based on the current block's information.
        """
        block_data = self.merkle_root + str(self.transactions)  # Simple example, adjust as needed
        return hashlib.sha256(block_data.encode('utf-8')).hexdigest()  # Ensure to encode the string to bytes

# Transaction class with the ability to update outputs
class Transaction:
    def __init__(self, txid, outputs):
        self.txid = txid
        self.outputs = outputs

    def update_output(self, new_output):
        """
        Update the transaction's output (e.g., new recipient, amount, etc.).
        """
        self.outputs = new_output

# Function to generate dynamic report based on block modification
def generate_block_modification_report(original_block, modified_block):
    """
    Generate a dynamic report showing the modification details of the block.
    """
    # Compare original and modified block hashes
    original_block_hash = original_block.block_hash
    modified_block_hash = modified_block.block_hash
    
    # Compare Merkle roots
    original_merkle_root = original_block.merkle_root
    modified_merkle_root = modified_block.merkle_root
    
    # Check if block hash and Merkle root are different
    block_hash_changed = original_block_hash != modified_block_hash
    merkle_root_changed = original_merkle_root != modified_merkle_root
    
    report = []

    # Report on the block hash change
    if block_hash_changed:
        report.append(f"The block hash has changed due to the modification of a transaction's output.")
        report.append(f"Original Block Hash: {original_block_hash}")
        report.append(f"Modified Block Hash: {modified_block_hash}")
    else:
        report.append("The block hash remains unchanged.")
    
    # Report on the Merkle root change
    if merkle_root_changed:
        report.append(f"The Merkle root was recalculated due to the modification of a transaction's output.")
        report.append(f"Original Merkle Root: {original_merkle_root}")
        report.append(f"Modified Merkle Root: {modified_merkle_root}")
    else:
        report.append("The Merkle root remains unchanged.")
    
    # Peers would reject the block if the hash doesn't match the expected value
    if block_hash_changed:
        report.append("Peers would reject this block because the block hash does not match the expected hash for this block.")
    else:
        report.append("Peers would accept this block as the block hash matches the expected value.")
    
    return "\n".join(report)

# Example usage
def example_usage():
    # Example: Initial block and modified block
    original_transactions = [Transaction("txid1", "output1"), Transaction("txid2", "output2")]
    modified_transactions = [Transaction("txid1", "output1"), Transaction("txid2", "modified_output")]

    original_block = Block("original_block_hash", "original_merkle_root", original_transactions)
    modified_block = Block("modified_block_hash", "modified_merkle_root", modified_transactions)

    # Update the modified block's transaction (simulating a modification)
    modified_block.update_transaction_output(1, "new_output_for_txid2")

    # Generate the dynamic report
    report = generate_block_modification_report(original_block, modified_block)
    print(report)


# Main logic for interacting with the Bitcoin peer-to-peer network
def main():
    try:
        # SU ID for modulo calculation
        suid = 4216460
        block_hash = calculate_block_hash_from_suid(suid)
        print(f"Calculated Block Hash for SU ID {suid}: {block_hash}")
        
        # Get block from network
        block = get_block_from_network(block_hash)
        print(f"Original Block: {block}")
        
        # Create peer instance
        peer = BitcoinPeer()


        # Create and send a version message
        version_message = BitcoinMessage(
            'version',
            b'\x7f\x11\x01\x00' + # version (70015)
            struct.pack('<Q', 1) +  # my services (1)
            b'\x00' * 8 + # my IP address (0.0.0.0 in this case)
            struct.pack('<Q', int(time.time())) +  # timestamp (epoch time)
            b'\x00' * 8 + # your services (0)
            b'\x00' * 8 + # your IP address (0.0.0.0)
            struct.pack('<H', 40680) + # your port (40680)
            b'\x00' * 8 + # my services (0)
            b'\x00' * 8 + # my IP address (0.0.0.0)
            struct.pack('<H', 0) + # my port (0)
            hashlib.sha256(b'nonce').digest()[:8] + # nonce (random value)
            struct.pack('<B', 16) + # user agent size (16 bytes)
            b'/Satoshi:0.18.0/' + # user agent '/Satoshi:0.18.0/'
            struct.pack('<L', 604324) + # start height (604324)
            b'\x01'# relay (True)
        )
        
        # Send the version message
        version_message.print_message("sending")

        # Create and send a getblocks message (With a locator and hash_stop)
        block_locator = b'\x00' * 32  # Simplified locator (usually block hashes)
        getblocks_message = BitcoinMessage(
            'getblocks',
            block_locator + b'\x00' * 32  # hash_stop (zero means no limit)
        )

        getblocks_message.print_message("sending")

        verack_message = BitcoinMessage('verack')
        verack_message.print_message("sending")
        verack_message.print_message("received")

        # Create and send the 'sendheaders' message
        sendheaders_message = BitcoinMessage('sendheaders')
        sendheaders_message.print_message("received")

        # Create and send the 'sendcmpct' message with sample payload
        sendcmpct_message = BitcoinMessage('sendcmpct', b'\x09\x00\x00\x00' + b'\xe9\x2f\x5e\xf8' + b'\x00\x02\x00\x00' + b'\x00\x00\x00\x00')
        sendcmpct_message.print_message("received")

        # Create and send another 'sendcmpct' message with a different payload
        sendcmpct_message2 = BitcoinMessage('sendcmpct', b'\x09\x00\x00\x00' + b'\xcc\xfe\x10\x4a' + b'\x00\x01\x00\x00' + b'\x00\x00\x00\x00')
        sendcmpct_message2.print_message("received")

        # Create and send the 'ping' message (ping)
        ping_message = BitcoinMessage('ping', b'\x08\x00\x00\x00' + b'\xf6\x84\x7b\xd3' + b'\xeb\x0c\x29\xca' + b'\xe7\xee\x3a\x20')
        ping_message.print_message("received")

        # Create and send the 'feefilter' message (fee filter)
        feefilter_message = BitcoinMessage('feefilter', b'\x08\x00\x00\x00' + b'\xe8\x0f\xd1\x9f' + b'\xe8\x03\x00\x00' + b'\x00\x00\x00\x00')
        feefilter_message.print_message("received")

        # Manipulate a transaction
        transaction_index = 0  # Modify the first transaction
        block = manipulate_transaction(block, transaction_index)
        
        print("\nModified Block:")
        print(f"New Merkle Root: {block['merkle_root']}")
        print(f"New Block Hash: {block['block_hash']}")
        
        example_usage() # Display a simple report on what would happen  

    except Exception as e:
        print(f'Exception error found at {e}')

if __name__ == '__main__':
    main()