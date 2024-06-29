from mnemonic import Mnemonic
import hashlib
import base58
import requests
import time
import os
import json
import concurrent.futures

print("""
 _____                                _                    _ _     _                      _           \r
|     |___ ___ ___    ___ ___ _ _ ___| |_ ___    _ _ _ ___| | |___| |_    ___ ___ ___ ___| |_ ___ ___ \r
|  |  |- _| -_|   |  |  _|  _| | | . |  _| . |  | | | | .'| | | -_|  _|  |  _|  _| .'|  _| '_| -_|  _|\r
|__  _|___|___|_|_|  |___|_| |_  |  _|_| |___|  |_____|__,|_|_|___|_|    |___|_| |__,|___|_,_|___|_|  \r
   |__|                      |___|_|                                                                  \r""")

input("Press Enter to start program ...")

# variables can be modified in the settings.json file
with open(r"settings.json", 'r') as f:
    config = json.load(f)    

checked = config['checked']
speed = config["speed"]
x = config["x"] # every x mnemonics it verifies max:100 recomended:50
num_threads = config.get("num_threads", 10)  # Default to 10 threads if not specified

def saveconfig(config, checked, speed):
    config["checked"] = checked
    config["speed"] = speed
    json.dump(config, open('settings.json', 'w'))
    # print("saved checked")

def public_key_to_address(public_key):
    sha = hashlib.sha256()
    sha.update(public_key.encode())
    public_key_hash = sha.digest()

    rip = hashlib.new('ripemd160')
    rip.update(public_key_hash)
    key_hash = rip.digest()

    modified_key_hash = b'\x00' + key_hash

    sha_2 = hashlib.sha256()
    sha_2.update(modified_key_hash)

    sha_3 = hashlib.sha256()
    sha_3.update(sha_2.digest())

    checksum = sha_3.hexdigest()[:8]
    byte_25_address = modified_key_hash + bytes.fromhex(checksum)
    address = base58.b58encode(byte_25_address).decode('utf-8')

    return address

def request(stringaddress, listaddresses, mnemonics):
    try: 
        data = requests.get(f'https://blockchain.info/balance?active={stringaddress}').json()
        for i in range(len(listaddresses)):
            balance = data[listaddresses[i]]['final_balance'] / 100000000  # convert satoshi to BTC
            if balance > 0:
                print(f'Balance: {balance} BTC')
                print(mnemonics[i])
                with open('wallets.txt', 'a') as file:
                    file.write("wallet : " + mnemonics[i] + "\n")
    except Exception as e:
        print(f"Error: {e}. Restarting in 5 seconds...")
        time.sleep(5)
        request(stringaddress, listaddresses, mnemonics)

def get_address_info_chunk(chunk):
    addresses, mnemonics = chunk
    stringaddress = '|'.join(addresses)
    request(stringaddress, addresses, mnemonics)

def get_address_info(addresses, mnemonics):
    # Ensure chunk_size is at least 1
    chunk_size = max(1, len(addresses) // num_threads)
    chunks = [(addresses[i:i + chunk_size], mnemonics[i:i + chunk_size]) for i in range(0, len(addresses), chunk_size)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        executor.map(get_address_info_chunk, chunks)

while True:
    mnemonics = []
    addresses = []
    while checked < ((checked // x) + ((checked % x != 0) * 1)) * x: 
        mnemo = Mnemonic("english").generate(strength=128)
        print("wallet checked ", checked, " : ", mnemo)

        private_key = Mnemonic.to_seed(mnemo, passphrase='')
        public_key = Mnemonic.to_hd_master_key(private_key)
        address = public_key_to_address(public_key)

        addresses.append(address)
        mnemonics.append(mnemo)
        time.sleep(speed)
        checked += 1

    saveconfig(config, checked, speed)
    checked += 1
    get_address_info(addresses, mnemonics)
