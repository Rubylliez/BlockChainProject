import hashlib

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_key_pair():
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def encrypt(message, public_key):
    e, n = public_key
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message

def decrypt(encrypted_message, private_key):
    d, n = private_key
    decrypted_message = ''.join([chr(pow(char, d, n) % 256) for char in encrypted_message])
    return decrypted_message

def sign_message(message, private_key):
    hashed_message = hashlib.sha256(message.encode()).hexdigest()
    d, n = private_key
    signature = [pow(ord(char), d, n) for char in hashed_message]
    return signature

def verify_signature(message, signature, public_key):
    hashed_message = hashlib.sha256(message.encode()).hexdigest()
    e, n = public_key
    decrypted_signature = [pow(char, e, n) for char in signature]
    return hashed_message == ''.join([chr(char) for char in decrypted_signature])

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.create_block(previous_hash='1')

    def create_block(self, previous_hash=None):
        previous_hash = previous_hash or self.hash_block(self.last_block)
        block = {
            'index': len(self.chain) + 1,
            'transactions': self.current_transactions,
            'previous_hash': previous_hash,
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def create_transaction(self, sender, recipient, amount, public_key, private_key):
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        }
        signature = sign_message(str(transaction), private_key)
        self.current_transactions.append({
            'transaction': transaction,
            'signature': signature,
            'public_key': public_key,
        })
        return self.last_block['index'] + 1

    def hash_block(self, block):
        block_string = ''.join([str(value) for value in block]).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None

    def validate_transaction(self, transaction):
        if not verify_signature(str(transaction['transaction']),
                                transaction['signature'],
                                transaction['public_key']):
            print(f"Transaction signature is not valid.")
            return False
        return True

    def validate_chain(self):
        for i in range(1, len(self.chain)):
            if not self.validate_block(self.chain[i]):
                print(f"Block {i} is not valid.")
                return False
        return True

    def validate_block(self, block):
        if block['previous_hash'] != self.hash_block(self.chain[-1]):
            print(f"Block {block['index']} hash is not valid.")
            return False
        for transaction in block['transactions']:
            if not self.validate_transaction(transaction):
                print(f"Transaction in block {block['index']} is not valid.")
                return False
        return True

class BlockchainCLI:
    def __init__(self, blockchain):
        self.blockchain = blockchain

    def run(self):
        while True:
            print("\nBlockchain CLI Menu:")
            print("1. Add Transaction")
            print("2. Mine Block")
            print("3. Display Blockchain")
            print("4. Validate Blockchain")
            print("5. Exit")

            choice = input("Enter your choice: ")
            if choice == "1":
                self.add_transaction()
            elif choice == "2":
                self.mine_block()
            elif choice == "3":
                self.display_blockchain()
            elif choice == "4":
                self.validate_blockchain()
            elif choice == "5":
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please enter a valid option.")

    def add_transaction(self):
        sender = input("Enter sender: ")
        recipient = input("Enter recipient: ")
        amount = float(input("Enter amount: "))
        sender_public_key, sender_private_key = generate_key_pair()
        self.blockchain.create_transaction(sender, recipient, amount, sender_public_key, sender_private_key)
        print("Transaction added successfully.")

    def mine_block(self):
        if not self.blockchain.current_transactions:
            print("No transactions to mine.")
        else:
            self.blockchain.create_block()
            print("Block mined successfully.")

    def display_blockchain(self):
        for block in self.blockchain.chain:
            print(f"Block {block['index']} with hash: {block['previous_hash']}")

    def validate_blockchain(self):
        if self.blockchain.validate_chain():
            print("Blockchain is valid.")
        else:
            print("Blockchain is not valid.")


blockchain = Blockchain()
cli = BlockchainCLI(blockchain)
cli.run()