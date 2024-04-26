import pandas as pd
from functions import *

opcodes = {
    # Arithmetic
    "OP_0": "00",
    "OP_1": "51",
    "OP_2": "52",
    "OP_3": "53",
    "OP_4": "54",
    "OP_5": "55",
    "OP_6": "56",
    "OP_7": "57",
    "OP_8": "58",
    "OP_9": "59",
    "OP_10": "5a",
    "OP_11": "5b",
    "OP_12": "5c",
    "OP_13": "5d",
    "OP_14": "5e",
    "OP_15": "5f",
    "OP_16": "60",

    # Flow control
    "OP_IF": "63",
    "OP_NOTIF": "64",
    "OP_ELSE": "67",
    "OP_ENDIF": "68",
    "OP_VERIFY": "69",
    "OP_RETURN": "6a",

    # Stack
    "OP_TOALTSTACK": "6b",
    "OP_FROMALTSTACK": "6c",
    "OP_IFDUP": "73",
    "OP_DEPTH": "74",
    "OP_DROP": "75",
    "OP_DUP": "76",
    "OP_NIP": "77",
    "OP_OVER": "78",
    "OP_PICK": "79",
    "OP_ROLL": "7a",
    "OP_ROT": "7b",
    "OP_SWAP": "7c",
    "OP_TUCK": "7d",
    "OP_2DROP": "6d",
    "OP_2DUP": "6e",
    "OP_3DUP": "6f",
    "OP_2OVER": "70",
    "OP_2ROT": "71",
    "OP_2SWAP": "72",

    # Splice
    "OP_CAT": "7e",
    "OP_SUBSTR": "7f",
    "OP_LEFT": "80",
    "OP_RIGHT": "81",
    "OP_SIZE": "82",

    # Bitwise logic
    "OP_INVERT": "83",
    "OP_AND": "84",
    "OP_OR": "85",
    "OP_XOR": "86",
    "OP_EQUAL": "87",
    "OP_EQUALVERIFY": "88",

    # Numeric
    "OP_1ADD": "8b",
    "OP_1SUB": "8c",
    "OP_NEGATE": "8f",
    "OP_ABS": "90",
    "OP_NOT": "91",
    "OP_0NOTEQUAL": "92",
    "OP_ADD": "93",
    "OP_SUB": "94",
    "OP_MUL": "95",
    "OP_DIV": "96",
    "OP_MOD": "97",
    "OP_LSHIFT": "98",
    "OP_RSHIFT": "99",
    "OP_BOOLAND": "9a",
    "OP_BOOLOR": "9b",
    "OP_NUMEQUAL": "9c",
    "OP_NUMEQUALVERIFY": "9d",
    "OP_NUMNOTEQUAL": "9e",
    "OP_LESSTHAN": "9f",
    "OP_GREATERTHAN": "a0",
    "OP_LESSTHANOREQUAL": "a1",
    "OP_GREATERTHANOREQUAL": "a2",
    "OP_MIN": "a3",
    "OP_MAX": "a4",
    "OP_WITHIN": "a5",

    # Crypto
    "OP_RIPEMD160": "a6",
    "OP_SHA1": "a7",
    "OP_SHA256": "a8",
    "OP_HASH160": "a9",
    "OP_HASH256": "aa",
    "OP_CODESEPARATOR": "ab",
    "OP_CHECKSIG": "ac",
    "OP_CHECKSIGVERIFY": "ad",
    "OP_CHECKMULTISIG": "ae",
    "OP_CHECKMULTISIGVERIFY": "af",

    # Expansion
    "OP_NOP1": "b0",
    "OP_CHECKLOCKTIMEVERIFY": "b1",
    "OP_CHECKSEQUENCEVERIFY": "b2",
    "OP_NOP4": "b3",
    "OP_NOP5": "b4",
    "OP_NOP6": "b5",
    "OP_NOP7": "b6",
    "OP_NOP8": "b7",
    "OP_NOP9": "b8",
    "OP_NOP10": "b9"
}

# Add the ones commonly used in transaction types
transaction_opcodes = {
    "OP_DUP": opcodes["OP_DUP"],
    "OP_HASH160": opcodes["OP_HASH160"],
    "OP_EQUALVERIFY": opcodes["OP_EQUALVERIFY"],
    "OP_CHECKSIG": opcodes["OP_CHECKSIG"],
    "OP_EQUAL": opcodes["OP_EQUAL"],
    "OP_0": opcodes["OP_0"],
    "OP_PUSHBYTES_20": "14",  # Length of the following data
    "OP_PUSHBYTES_32": "20",
    "OP_PUSHBYTES_3": "03",
    "OP_PUSHBYTES_33":"21",
    "OP_PUSHBYTES_65":"65",
    "OP_PUSHBYTES_11" : '0b',
    "OP_PUSHNUM_1":'51',
     "OP_PUSHNUM_3":"53" # Length of the following data
}

opcodes.update(transaction_opcodes)


print("-------------------------------All functions processed nicely----------------------------")

transactions = read_transactions()

STXO, UTXO = process_transactions(transactions=transactions)

print("Transaction processed successfully")

op_return_indices = UTXO[UTXO['scriptpubkey_type'] == 'op_return'].index.to_list() #op_return transactions are invalid
unknown_indices = UTXO[UTXO['scriptpubkey_type'] == 'unknown'].index.to_list() #unknown indices are multisig and the handling is not focused on in this script

indices_to_drop = op_return_indices + unknown_indices
UTXO = UTXO.drop(indices_to_drop).reset_index()

print("Op_return type and unknown type removed successfully")

STXO = STXO.drop_duplicates(subset='txid',keep='first').reset_index().drop('index',axis=1) #dropping duplicate inputs and keeping only the first

print("Duplicates transaction dropped successfully")

#grouping the sum of money spent by block in input and output and then joining the two dataframe by the block id
input_output = pd.merge(STXO.groupby(by='block_id')['value'].sum(),UTXO.groupby(by='block_id')['value'].sum(),on='block_id',how='inner').rename(columns={'value_x':'input','value_y':'output'}).reset_index()
input_output['difference'] = input_output['input'] - input_output['output'] #creating a difference column which is difference of the total input and total output

print("Difference (in input values and output values) calculated successfully")
#remove blocks where the value difference is equal to 0 (no fees) and less than 0 (overspend) since invalid trans makes the block invalid
index_to_remove = []
for i,v in STXO.iterrows():
    if v['block_id'] in input_output[input_output['difference']<=0]['block_id'].to_list():
        index_to_remove.append(i)

STXO = STXO.drop(index_to_remove).reset_index().drop('index',axis=1)
STXO = pd.merge(input_output[['block_id','difference']],STXO,on='block_id',how='right')

index_to_remove = []
for i,v in UTXO.iterrows():
    if v['block_id'] in input_output[input_output['difference']<=0]['block_id'].to_list():
        index_to_remove.append(i)
UTXO = UTXO.drop(index_to_remove).reset_index().drop('index',axis=1)

# Group the values in the unspent transaction records by the user address
value_by_add = UTXO.groupby(by='scriptpubkey_address')['value'].agg(list).reset_index()

# Iterate through spent transaction outputs (STXO)
for i, v in STXO.iterrows():
    # Retrieve the list of values associated with the current address
    value_series = value_by_add[value_by_add['scriptpubkey_address'] == v['scriptpubkey_address']]['value']    
    try:
        # Get the index of the address in the grouped DataFrame
        value_index = value_by_add[value_by_add['scriptpubkey_address'] == v['scriptpubkey_address']].index[0]
    except IndexError:
        # Handle the case where the address is not found
        pass    
    if not value_series.empty:  # Check if the series is not empty
        value_list = value_series.iloc[0]
        if v['value'] in value_list:
            # If the value being spent is found in the list, mark it as checked and update the list
            STXO.loc[i, 'First check'] = 1
            value_list.remove(v['value'])
            value_by_add.at[value_index, 'value'] = value_list
        else:
            # If the value being spent is not found in the list, mark it as unchecked
            STXO.loc[i, 'First check'] = 0
    else:
        # If the address is not found, mark it as unchecked
        STXO.loc[i, 'First check'] = 0

print("First check successful. Blocks where no history of their inputs are found are dropped")

invalid_block = list(set(STXO[STXO['First check']==0]['block_id'])) #remove blocks that have a 0 in their first check
STXO = STXO.drop(STXO[STXO['First check'] == 0].index)
STXO = STXO.reset_index().drop('index',axis=1)

index_to_remove = []
for i,v in UTXO.iterrows():
    if v['block_id'] in invalid_block:
        index_to_remove.append(i)
UTXO = UTXO.drop(index_to_remove).reset_index().drop('index',axis=1) 

for i,v in STXO.iterrows():
    # Split the scriptPubKey assembly code into individual commands
    commands = v['scriptpubkey_asm'].split(' ')
    script_ = ''
    for cmd in commands:
        try:
            # Attempt to translate opcode commands into numerical values
            script_ += opcodes[cmd]
        except KeyError:
            # If opcode translation fails, use the command as is
            script_ += cmd
    
    # Compute the length of the resulting script
    script_ = compute_script_length(script_) + script_
    STXO.loc[i,'script_'] = script_
    
    # Perform different validation checks based on the scriptPubKey type
    if v['scriptpubkey_type'] == 'p2pkh':
        # Extract hashed key, compressed public key, and signature information
        STXO.loc[i,'hashed key'] = remove_base58check(v['scriptpubkey_address'])
        STXO.loc[i, 'compressed public key'] = v['scriptsig'][-66:]
        STXO.loc[i, 'signature'] = v['scriptsig'][:-66]
        try:
            # Check if the hashed address matches the expected value
            hashed_add = v['scriptpubkey_asm'].split(' ')[3]
            if hashed_add == v['hashed key'][2:]:
                STXO.loc[i, 'Second check'] = 1
            else:
                STXO.loc[i, 'Second check'] = 0
        except:
            pass
    elif v['scriptpubkey_type'] == 'p2sh':
        # Extract hashed key, compressed public key, and signature information for P2SH scripts
        STXO.loc[i,'hashed key'] = remove_base58check(v['scriptpubkey_address'])
        for j in v['witness']:
            if len(j) == 66:
                STXO.loc[i, 'compressed public key'] = j
            elif len(j)==142 or len(j)==144:
                STXO.loc[i, 'signature'] = j
        try:
            hashed_add = v['scriptpubkey_asm'].split(' ')[2]
            if hashed_add == v['hashed key'][2:]:
                STXO.loc[i, 'Second check'] = 1
            else:
                STXO.loc[i, 'Second check'] = 0
        except:
            pass
    elif v['scriptpubkey_type'] == 'v0_p2wpkh':
        # Extract hashed key, compressed public key, and signature information for P2WPKH scripts
        if len(v['scriptpubkey'][4:]) == 40:
            STXO.loc[i,'hashed key'] = decode_bech32(v['scriptpubkey_address'],'other')[1]
            if len(v['witness']) == 2:
                for j in v['witness']:
                    if len(j) == 66:
                        STXO.loc[i,'compressed public key'] = j
                    elif len(j) == 142 or len(j)==144:
                        STXO.loc[i,'signature'] = j
            else:
                STXO.loc[i,'Third check'] = 'Unvalidated'
            try:
                hashed_add = v['scriptpubkey_asm'].split(' ')[2]
                if hashed_add == v['hashed key']:
                    STXO.loc[i, 'Second check'] = 1
                else:
                    STXO.loc[i, 'Second check'] = 0
            except:
                pass
        else:
            STXO.loc[i,'Third check'] = 'Unvalidated'
    elif v['scriptpubkey_type'] =='v0_p2wsh' :
        # Extract hashed key, compressed public key, and signature information for P2WSH scripts
        if len(v['scriptpubkey'][4:]) == 64:
            STXO.loc[i,'hashed key'] = decode_bech32(v['scriptpubkey_address'],'other')[1]
            STXO.loc[i, 'compressed public key'] = v['witness'][-1]
            STXO.at[i, 'signature'] = v['witness'][1:3]
            try:
                hashed_add = v['scriptpubkey_asm'].split(' ')[2]
                if hashed_add == v['hashed key']:
                    STXO.loc[i, 'Second check'] = 1
                else:
                    STXO.loc[i, 'Second check'] = 0
            except:
                pass
        else:
            STXO.loc[i,'Second check'] = 'Unvalidated'
    elif v['scriptpubkey_type'] == 'v1_p2tr':
        # Extract hashed key and perform validation checks for Taproot (v1_p2tr) scripts
        STXO.loc[i,'hashed key'] = decode_bech32(v['scriptpubkey_address'],'v1_p2tr')[1]
        try:
            hashed_add = v['scriptpubkey_asm'].split(' ')[2]
            if hashed_add == v['hashed key']:
                STXO.loc[i, 'Second check'] = 1
            else:
                STXO.loc[i, 'Second check'] = 0
        except:
            pass

print("Second check successful: Verifying that the decoded version of the address is the same as the public hash. Checking op codes to convert scriptpubkey_asm to the script needed (to) create digest. Extracting compressed public key and signature. Verifying correct lengths where necessary")
#remove blocks that has their sequence number on 0xFFFFFFFF and their locktime hasn't reach 
invalid_blocks = list((STXO[(STXO['locktime'] > 840565) & (STXO['sequence'] == 4294967295)]['block_id']))
STXO.drop(STXO[(STXO['locktime'] > 840565) & (STXO['sequence'] == 4294967295)].index, inplace=True)
for i in invalid_blocks:
    UTXO.drop(UTXO[UTXO['block_id'] == i].index, inplace=True)

STXO = STXO.reset_index(drop=True)
UTXO = UTXO.reset_index(drop=True)

# op_codes = {'OP_0':'00','0P_1':'51','OP_2-OP_16':'52-60',''}
# A dictionary mapping operation codes to their hexadecimal representation.

tx_hash = pd.DataFrame(columns=['blockid', 'version', 'input_count', 'sequence', 'locktime', 'prev_trans_hash',
                                'prev_trans_index', 'script_sig_length', 'script_sig', 'output_count',
                                'output_value', 'output_scriptlen', 'outputscriptpubkey'])
# Initialize an empty DataFrame to store transaction hashes.

dfs = []
# A list to hold DataFrames for each transaction.

for i, v in STXO.iterrows():
    # Iterate over rows in the STXO DataFrame.
    
    block_id = v['block_id']
    version = v['version']
    input_count = v['input_count']
    sequence = v['sequence']
    locktime = v['locktime']
    prev_trans_index = v['input index']
    prev_trans_hash = v['txid']
    script_sig_length = v['script_'][2:4]
    script_sig = v['script_'][4:]
    output_count = len(UTXO[UTXO['block_id'] == v['block_id']])
    # Extract relevant information from the STXO DataFrame.
    
    output_values = []
    output_script_len = []
    output_script_pubkey = []
    # Initialize lists to store output values, script lengths, and script public keys.
    
    for m, n in UTXO[UTXO['block_id'] == v['block_id']].iterrows():
        # Iterate over rows in the UTXO DataFrame for the current block.
        
        output_values.append(n['value'])
        # Append output value to the list.
        
        commands = n['scriptpubkey_asm'].split(' ')
        script_ = ''
        for cmd in commands:
            try:
                script_ += opcodes[cmd]
            except KeyError:
                script_ += cmd
        # Generate script assembly for the current output.
        
        output_script_len.append(compute_script_length(script_))
        output_script_pubkey.append(script_)
        # Append script length and script public key to their respective lists.
        
    # Create a DataFrame for the current transaction.
    temp = pd.DataFrame({
        'block_id': [block_id],
        'version': [version],
        'input_count': [input_count],
        'sequence': [sequence],
        'locktime': [locktime],
        'prev_trans_hash': [prev_trans_hash],
        'prev_trans_index': [prev_trans_index],
        'script_sig_length': [script_sig_length],
        'script_sig': [script_sig],
        'output_count': [output_count],
        'output_values': [output_values],  # Store the list of output values
        'output_script_length': [output_script_len],  # Store the list of output script lengths
        'output_script_pubkey': [output_script_pubkey]  # Store the list of output script public keys
    })
    dfs.append(temp)
    # Append the DataFrame to the list of DataFrames.

# Concatenate all DataFrames to create the transaction hash DataFrame.
tx_hash = pd.concat(dfs, ignore_index=True)
print("Transaction hash created successfully")
for i, v in tx_hash.iterrows():
    # Iterate over rows in the tx_hash DataFrame.

    version = int(v['version'])
    sequence = int(v['sequence'])
    input_count = int(v['input_count'])
    previous_transaction_hash = v['prev_trans_hash']
    previous_transaction_index = int(v['prev_trans_index'])
    script_sig_length = v['script_sig_length']
    script_sig = v['script_sig']
    output_count = int(v['output_count'])
    output_ = ''

    if output_count > 1:
        # If there are multiple outputs in the transaction.
        for value, script_length, output_script_pubkey in zip(v['output_values'],
                                                              v['output_script_length'],
                                                              v['output_script_pubkey']):
            value_hex = value.to_bytes(8, byteorder='little').hex()
            script_length = int(script_length, 16)  # Convert script length to integer from hexadecimal
            output_ += value_hex + script_length.to_bytes(2, byteorder='little').hex() + output_script_pubkey

    elif output_count == 1:
        # If there is only one output in the transaction.
        value_hex = v['output_values'][0].to_bytes(8, byteorder='little').hex()
        script_length = int(v['output_script_length'][0], 16)  # Convert script length to integer from hexadecimal
        output_script_pubkey = v['output_script_pubkey'][0]
        output_ += value_hex + script_length.to_bytes(2, byteorder='little').hex() + output_script_pubkey

    # Compute the transaction hash digest using the provided function.
    tx_hash.at[i, 'digest'] = compute_transaction_hash(version, input_count, previous_transaction_hash,
                                                        previous_transaction_index, script_sig_length,
                                                        script_sig, sequence, output_count, output_, locktime)

print('Digest created successfully')
merkle_df = STXO.groupby('block_id')['txid'].agg(list).reset_index() #gets all transaction id in each block in a list

for i,v in merkle_df.iterrows():
    txids = ["".join(reversed([x[i:i+2] for i in range(0, len(x), 2)])) for x in v['txid']]
    merkle_df.loc[i,'merkle root'] = merkleroot(txids)

# merge with corresponding inputs
STXO = pd.merge(STXO,merkle_df[['block_id','merkle root']],on='block_id',how='left')

print("Merkle root calculated successfully")
print('Done calculating bits:' + calculate_bits_from_target('0000ffff00000000000000000000000000000000000000000000000000000000'))
#print(STXO.columns)
print("Note that finding the right block hash below the target for all rows might take about 30 mins. Please wait.")

block_header_df = construct_block_header_df(STXO,'0000ffff00000000000000000000000000000000000000000000000000000000')

print('Candidate block created')

block_reward = 304967308  # block reward 3.125btc
output_file = 'output.txt'

mine_blocks(STXO, UTXO, block_header_df, block_reward, output_file)

print('--------------------------------------Output file generated successfully---------------------------------------')














