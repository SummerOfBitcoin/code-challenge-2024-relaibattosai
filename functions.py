import pandas as pd
import os
import json
import hashlib
import base58
import bech32
import bech32m
import time
import struct
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der

def read_transactions():
    """
    Reads transaction data from files in the 'mempool' directory and returns a list of transactions.

    Each transaction is loaded from a separate JSON file located in the 'mempool' directory.
    
    Returns:
    list: A list of dictionaries, where each dictionary represents a transaction.
          Each transaction dictionary contains the transaction data loaded from the corresponding JSON file.
    """
    transactions = []
    # Iterate over files in the 'mempool' directory
    for filename in os.listdir('mempool'):
        # Open each file and load transaction data from JSON
        with open(os.path.join('mempool', filename), 'r') as file:
            transaction = json.load(file)
            # Append transaction data to the list of transactions
            transactions.append(transaction)
    return transactions

def hash_public_key(public_key_str, type=None):
    """
    Hashes a public key string using SHA-256 and RIPEMD-160 algorithms.

    Args:
    public_key_str (str): The public key string in hexadecimal format.
    type (str, optional): The type of hash to compute. If None, both SHA-256 and RIPEMD-160 hashes are computed.
                          If set to 'sha256', only the SHA-256 hash is computed.

    Returns:
    str: The hashed public key string in hexadecimal format.

    Raises:
    ValueError: If the provided type is invalid.
    """
    # Convert the public key string to bytes
    public_key_bytes = bytes.fromhex(public_key_str)
    
    # First, perform SHA256 hash on the public key
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    
    # Check if type is specified
    if type:
        return sha256_hash.hex()
    
    # If type is None, perform RIPEMD160 hash on the SHA256 hash
    else:
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest() 
        return ripemd160_hash.hex()

def convert_to_hex(data):
    """
    Converts a list of numbers to a hexadecimal string.

    Args:
    data (list): A list of integers representing byte values.

    Returns:
    str: The hexadecimal string representing the bytes data.

    Example:
    >>> convert_to_hex([72, 101, 108, 108, 111])
    '48656c6c6f'
    """
    # Convert the list of numbers to a bytes object
    bytes_data = bytes(data)
    
    # Convert the bytes to a hexadecimal string
    hex_string = bytes_data.hex()
    
    return hex_string

def decode_bech32(address, address_type):
    """
    Decodes a Bech32 or Bech32m encoded address.

    Args:
    address (str): The Bech32 or Bech32m encoded address.
    address_type (str): The type of address encoding. It should be either 'v1_p2tr' for Bech32m or any other value for Bech32.

    Returns:
    tuple: A tuple containing the human-readable part (HRP) and the data part of the decoded address.

    Example:
    >>> decode_bech32('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'v1_p2tr')
    ('bc', '751e76e8199196d454941c45d1b3a323f1433bd6')

    Note:
    - If the address_type is 'v1_p2tr', Bech32m decoding is used.
    - If the address_type is not 'v1_p2tr', Bech32 decoding is used.
    """
    if address_type != 'v1_p2tr':     
        hrp, data = bech32.decode('bc', address)
    else:
        hrp, data = bech32m.decode('bc', address)
    return hrp, convert_to_hex(data)

def remove_base58check(address):
    """
    Removes Base58check encoding from a given address and returns the hexadecimal representation of the data.

    Args:
    address (str): The Base58check encoded address.

    Returns:
    str: The hexadecimal string representing the data after removing Base58check encoding.

    Note:
    - Base58check encoding typically includes a checksum appended to the end of the data.
    - This function decodes the Base58check encoded address, removes the last 4 bytes (checksum), and converts the result to a hexadecimal string.
    """
    # Decode the Base58 encoded address
    decoded_address = base58.b58decode(address)
    
    # Remove the last 4 bytes (checksum)
    address_without_checksum = decoded_address[:-4]
    
    # Convert the result back to bytes
    address_bytes = bytes(address_without_checksum)
    
    # Convert bytes to hexadecimal string
    hex_string = address_bytes.hex()
    
    return hex_string
    
def compute_script_length(script_hex):
    """
    Computes the length of a script in hexadecimal format.

    Args:
    script_hex (str): The hexadecimal representation of the script.

    Returns:
    str: The length of the script in hexadecimal format.

    Note:
    - The function removes any leading "OP_" prefixes if present in the script_hex.
    - It then converts the hexadecimal script to bytes and calculates the length of the bytes.
    - The length of the script is returned as a hexadecimal string.
    """
    # Remove any leading "OP_" prefixes if present
    script_hex = script_hex.replace("OP_", "")
    # Convert the hexadecimal script to bytes
    script_bytes = bytes.fromhex(script_hex)
    # The length of the script is the length of the bytes
    script_length = len(script_bytes)
    return hex(script_length)

def compute_transaction_hash(version, input_count, previous_transaction_hash, previous_transaction_index, script_sig_length, script_sig, sequence, output_count, output, locktime):
    """
    Computes the hash of a transaction based on its components.

    Args:
    version (int): The version of the transaction.
    input_count (int): The number of inputs in the transaction.
    previous_transaction_hash (str): The hash of the previous transaction in little-endian hexadecimal format.
    previous_transaction_index (int): The index of the previous transaction output.
    script_sig_length (int): The length of the input script in bytes.
    script_sig (str): The input script in hexadecimal format.
    sequence (int): The sequence number of the input.
    output_count (int): The number of outputs in the transaction.
    output (str): The concatenated outputs of the transaction in hexadecimal format.
    locktime (int): The locktime of the transaction.

    Returns:
    str: The hash of the transaction in hexadecimal format.

    Note:
    - The function computes the transaction hash by concatenating the transaction components in little-endian hexadecimal format.
    - It then double SHA256 hashes the concatenated transaction to produce the transaction hash.
    """
    # Convert version, input_count, output_count, sequence, and locktime to little-endian hexadecimal strings
    version_hex = version.to_bytes(4, byteorder='little').hex()
    input_count_hex = input_count.to_bytes(1, byteorder='little').hex()
    output_count_hex = output_count.to_bytes(1, byteorder='little').hex()
    sequence_hex = sequence.to_bytes(4, byteorder='little').hex()
    locktime_hex = locktime.to_bytes(4, byteorder='little').hex()

    # Reverse the byte order of the previous transaction hash
    previous_transaction_hash_reversed = bytes.fromhex(previous_transaction_hash)[::-1].hex()

    # Convert previous_transaction_index and script_sig_length to little-endian hexadecimal strings
    previous_transaction_index_hex = previous_transaction_index.to_bytes(4, byteorder='little').hex()
    # script_sig_length_hex = script_sig_length.to_bytes(1, byteorder='little').hex()

    # Concatenate the transaction components
    tx_hex = (
        version_hex +
        input_count_hex +
        previous_transaction_hash_reversed +
        previous_transaction_index_hex +
        script_sig_length +
        script_sig +
        sequence_hex +
        output_count_hex +
        output +
        locktime_hex
    )

    # Append the SIGHASH_ALL value (1) for Bitcoin transactions
    sighash_hex = "{:08x}".format(0x01000000)
    tx_hex += sighash_hex

    # Double SHA256 hash the concatenated transaction
    tx_hash = hashlib.sha256(bytes.fromhex(tx_hex)).digest()

    # Return the transaction hash in hexadecimal format
    return tx_hash.hex()

def hash256(hex_str):
    binary = bytes.fromhex(hex_str)
    hash1 = hashlib.sha256(binary).digest()
    hash2 = hashlib.sha256(hash1).digest()
    result = hash2.hex()
    return result

def merkleroot(txids):
    """
    Computes the merkle root hash of a list of transaction IDs (TXIDs).

    Parameters:
        txids (list): A list of hexadecimal strings representing transaction IDs (TXIDs).

    Returns:
        str: The merkle root hash as a hexadecimal string.

    Notes:
        - The function uses recursive binary hashing to compute the merkle root hash.
        - If the length of the list is 1 (i.e., only one hash result left), the function returns the hash.
        - Otherwise, it splits the list of hashes into pairs, concatenates each pair, hashes the concatenation,
          and appends the result to a new list.
        - It then recursively calls itself with the new list of hashed pairs until only one hash remains.
    """
    # Exit Condition: Stop recursion when we have one hash result left
    if len(txids) == 1:
        # Convert the result to a string and return it
        return txids[0]

    # Keep an array of results
    result = []

    # 1. Split up array of hashes into pairs
    for i in range(0, len(txids), 2):
        one = txids[i]
        two = txids[i + 1] if i + 1 < len(txids) else one

        # 2a. Concatenate each pair
        concat = one + two

        # 3. Hash the concatenated pair and add to results array
        result.append(hash256(concat))

    # Recursion: Do the same thing again for these results
    return merkleroot(result)

def calculate_bits_from_target(target_difficulty_hex):
    """
    Calculates the bits value from the target difficulty.

    Args:
        target_difficulty_hex (str): The target difficulty in hexadecimal format.

    Returns:
        str: The bits value as a hexadecimal string.
    """
    # Convert the target difficulty to an integer
    target_difficulty = int(target_difficulty_hex, 16)

    # Calculate the exponent
    exponent = 3 + (len(target_difficulty_hex) - 2) // 2

    # Calculate the coefficient
    coefficient = target_difficulty // (2 ** (8 * (exponent - 3)))

    # Combine the exponent and coefficient to create the bits value
    bits_value = (exponent << 24) + coefficient

    return hex(bits_value)  # Output the bits value as a hexadecimal string


def construct_block_header_df(STXO, difficulty_target_hex):
    """
    Constructs a DataFrame containing information necessary in a block header.

    Args:
        STXO (DataFrame): DataFrame containing transaction information.
        difficulty_target_hex (str): Difficulty target in hexadecimal format.

    Returns:
        DataFrame: DataFrame containing block header information.
    """
    # Convert the difficulty target from hexadecimal to an integer
    difficulty_target = int(difficulty_target_hex, 16)

    # Initialize an empty list to store block header information
    block_header_info = []

    # Get the current time
    current_time = int(time.time())

    # Iterate through each row in STXO DataFrame
    for i, row in STXO.iterrows():
        # Initialize the previous block hash as all zeros for the first row
        previous_block_hash = '0' * 64 if i == 0 else block_header_info[-1]['block_hash']


        # Initialize nonce
        nonce = 0

        # Mine the block by incrementing nonce until the hash is below the difficulty target
        while True:
            # Construct the block header dictionary
            block_header = {
                'block_id': row['block_id'],
                'version': row['version'],
                'previous_block_hash': previous_block_hash,
                'merkle_root': row['merkle root'],
                'current_time': current_time,
                'bits': '22000000',  # Assuming a fixed difficulty for demonstration
                'nonce': nonce
            }

            # Calculate the block hash by double hashing all block header info
            block_header_str = f"{block_header['version']}{block_header['previous_block_hash']}" \
                               f"{block_header['merkle_root']}{block_header['current_time']}" \
                               f"{block_header['bits']}{block_header['nonce']}"
            block_hash = hashlib.sha256(hashlib.sha256(block_header_str.encode()).digest()).hexdigest()

            # Check if the block hash is below the difficulty target
            if int(block_hash, 16) < difficulty_target:
                break  # Exit the loop if the hash is below the target

            # Increment nonce for the next iteration
            nonce += 1

        # Add the block hash to the block header dictionary
        block_header['block_hash'] = block_hash

        # Append the block header dictionary to the list
        block_header_info.append(block_header)

    # Convert the list of dictionaries to a DataFrame
    block_header_df = pd.DataFrame(block_header_info)

    return block_header_df

def field(data, size):
    """
    Convert a number to a hexadecimal string and ensure it fits into a field of a specific size.

    Args:
        data (int): The number to be converted to hexadecimal.
        size (int): The size of the field in bytes.

    Returns:
        str: The hexadecimal string representing the data, padded with zeros if necessary to fit the specified size.
    """
    hex_data = hex(data)[2:].rjust(size * 2, '0')
    return hex_data

def reversebytes(data):
    return ''.join(reversed([data[i:i+2] for i in range(0, len(data), 2)]))

def construct_coinbase_tx(height, block_reward,version):
    """
    Construct a coinbase transaction for a given block height and block reward.

    Args:
        height (int): The height of the block.
        block_reward (int): The reward for mining the block.

    Returns:
        dict: A dictionary representing the coinbase transaction.
    """
    coinbase_tx = {
        "version": version,
        "inputcount": int("01")+1,
        "inputs": [
            {
                "txid": "0" * 64,
                "vout": "ffffffff",
                "scriptsigsize": "08",
                "scriptsig": field(height, 4),
                "block_reward": block_reward,
                "sequence": "ffffffff",
                "coinbase": True
            }
        ]
    }
    return coinbase_tx

def construct_block_header(block_header_info):
    """
    Construct the block header based on block header information.

    Args:
        block_header_info (dict): Dictionary containing block header information.

    Returns:
        str: Serialized block header.
    """
    header = reversebytes(field(block_header_info['version'], 4)) \
             + reversebytes(block_header_info['previous_block_hash']) \
             + reversebytes(block_header_info['merkle_root']) \
             + reversebytes(field(block_header_info['current_time'], 4)) \
             + reversebytes(block_header_info['bits']) \
             + reversebytes(field(block_header_info['nonce'], 4))
    return header

def mine_blocks(STXO, UTXO, block_header_df, subsidy, output_file):
    """
    Mine blocks based on transaction and block header information and write to an output file.

    Args:
        STXO (DataFrame): DataFrame containing spent transaction outputs.
        UTXO (DataFrame): DataFrame containing unspent transaction outputs.
        block_header_df (DataFrame): DataFrame containing block header information.
        subsidy (float): Block subsidy.
        output_file (str): Path to the output file.

    Returns:
        None
    """
    with open(output_file, 'w') as f:
        for _, block_header_info in block_header_df.iterrows():
            block_id = block_header_info['block_id']
            height = 840565  # Current block height
            block_header = construct_block_header(block_header_info)
            
            # Construct the transaction list from STXO and UTXO DataFrames
            transaction_list = []
            
            # Construct coinbase, input and output transactions
            for _, stxo_row in STXO[STXO['block_id'] == block_id].iterrows():
                version = stxo_row['version']
                block_fee = stxo_row['difference']
                block_reward = subsidy + block_fee
                coinbase_tx = construct_coinbase_tx(height, block_reward,version)
                vin = {"vin": {
                    "txid": stxo_row['txid'],
                    "vout": stxo_row['input index'],
                    "prevout": {'scriptpubkey': stxo_row['scriptpubkey'],
                                'scriptpubkey_address': stxo_row['scriptpubkey_address'],
                                'value': stxo_row['value']},
                    "scriptsig": stxo_row['scriptsig'],
                    "sequence": stxo_row['sequence'],
                    "witness": stxo_row['witness']
                }}
                transaction_list.append(vin)
            
            # Add UTXO transactions to the transaction list
            for _, utxo_row in UTXO[UTXO['block_id'] == block_id].iterrows():
                vout = {"vout": {
                    "scriptpubkey": utxo_row['scriptpubkey'],
                    "scriptpubkey_address": utxo_row['scriptpubkey_address'],
                    "value": utxo_row['value']
                }}
                transaction_list.append(vout)

            # Construct the block
            block = {
                "block_header": block_header,
                "locktime": 0,
                "coinbase_transaction": coinbase_tx,
                "transaction_list": transaction_list,
            }

            # Write the block to output file
            f.write(json.dumps(block, indent=2))
            f.write('\n\n')

def process_transactions(transactions):
    """
    Process transactions data and generate DataFrames for spent and unspent transaction outputs (STXO and UTXO).

    Args:
    transactions (list): A list of transactions.

    Returns:
    pd.DataFrame: DataFrame containing spent transaction outputs (STXO).
    pd.DataFrame: DataFrame containing unspent transaction outputs (UTXO).
    """
    STXO = pd.DataFrame(columns=['block_id', 'version', 'locktime', 'input_count', 'txid', 'input index', 'scriptpubkey', 'scriptpubkey_asm', 'scriptpubkey_type',
                                  'scriptpubkey_address', 'value', 'scriptsig', 'scriptsig_asm', 'witness', 'is_coinbase', 'sequence'])
    UTXO = pd.DataFrame(columns=['scriptpubkey', 'scriptpubkey_asm', 'scriptpubkey_type', 'scriptpubkey_address', 'value'])

    dfs = []
    dfs_ = []

    # Iterate through blocks
    for block_id, block in enumerate(transactions):
        version = block['version']
        locktime = block['locktime']

        # Iterate through transactions in the block
        for transaction in block['vin']:
            try:
                # Access input transaction information
                input_count = len(block['vin'])
                txid = transaction['txid']
                input_index = transaction['vout']
                scriptpubkey = transaction['prevout']['scriptpubkey']
                scriptpubkey_asm = transaction['prevout']['scriptpubkey_asm']
                scriptpubkey_type = transaction['prevout']['scriptpubkey_type']
                scriptpubkey_address = transaction['prevout']['scriptpubkey_address']
                value = transaction['prevout']['value']
                scriptsig = transaction['scriptsig']
                scriptsig_asm = transaction['scriptsig_asm']
                witness = transaction['witness']
                is_coinbase = transaction['is_coinbase']
                sequence = transaction['sequence']
            except KeyError:
                input_count = len(block['vin'])
                txid = transaction['txid']
                input_index = transaction['vout']
                scriptpubkey = transaction['prevout']['scriptpubkey']
                scriptpubkey_asm = transaction['prevout']['scriptpubkey_asm']
                scriptpubkey_type = transaction['prevout']['scriptpubkey_type']
                scriptpubkey_address = transaction['prevout']['scriptpubkey_address']
                value = transaction['prevout']['value']
                scriptsig = transaction['scriptsig']
                scriptsig_asm = transaction['scriptsig_asm']
                witness = ''
                is_coinbase = transaction['is_coinbase']
                sequence = transaction['sequence']

            # Create DataFrame for current transaction
            df = pd.DataFrame({
                'block_id': [block_id],
                'input_count': input_count,
                'txid': [txid],
                'version': [version],
                'locktime': [locktime],
                'input index': [input_index],
                'scriptpubkey': [scriptpubkey],
                'scriptpubkey_asm': [scriptpubkey_asm],
                'scriptpubkey_type': [scriptpubkey_type],
                'scriptpubkey_address': [scriptpubkey_address],
                'value': [value],
                'scriptsig': [scriptsig],
                'scriptsig_asm': [scriptsig_asm],
                'witness': [witness],
                'is_coinbase': [is_coinbase],
                'sequence': [sequence]
            })

            # Append DataFrame to list
            dfs.append(df)

        for transaction in block['vout']:
            try:
                # Access output transaction information
                scriptpubkey = transaction['scriptpubkey']
                scriptpubkey_asm = transaction['scriptpubkey_asm']
                scriptpubkey_type = transaction['scriptpubkey_type']
                scriptpubkey_address = transaction['scriptpubkey_address']
                value = transaction['value']
            except:
                scriptpubkey_asm = transaction['scriptpubkey_asm']
                scriptpubkey_type = transaction['scriptpubkey_type']
                scriptpubkey_address = ''
                value = transaction['value']

            # Create DataFrame for current transaction output
            df_ = pd.DataFrame({
                'block_id': [block_id],
                'scriptpubkey': [scriptpubkey],
                'scriptpubkey_asm': [scriptpubkey_asm],
                'scriptpubkey_type': [scriptpubkey_type],
                'scriptpubkey_address': [scriptpubkey_address],
                'value': [value]
            })

            # Append DataFrame to list
            dfs_.append(df_)

    # Concatenate DataFrames for spent and unspent transaction outputs
    STXO = pd.concat(dfs, ignore_index=True)
    UTXO = pd.concat(dfs_, ignore_index=True)

    return STXO, UTXO
