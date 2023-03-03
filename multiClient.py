import socket, select
import binascii
import sqlite3
import sys
import traceback
import random
import re
from _thread import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from math import gcd


# https://www.geeksforgeeks.org/find-the-number-of-primitive-roots-modulo-prime/
def findPrimitiveRoot(p):
    result = 1
    for i in range(2, p, 1):
        if (gcd(i, p) == 1):
            return i


# https://www.delftstack.com/howto/python/python-generate-prime-number/
def primesInRange(x, y):
    prime_list = []
    for n in range(x, y):
        isPrime = True
        for num in range(2, n):
            if n % num == 0:
                isPrime = False
        if isPrime:
            prime_list.append(n)
    return prime_list


def search_for_pair_in_database(device_id, card_id):
    # connect with database
    # conn = sqlite3.connect(r"C:\Users\Dora\Desktop\Start Diplomatiki\DoorLock.db")
    conn = sqlite3.connect(r"DoorLock.db")
    print("pair: ", device_id, "-", card_id)

    cur = conn.cursor()
    cur.execute("SELECT DoorID FROM `User` WHERE ID = ?", [card_id])

    result = cur.fetchone()

    if (result == None):
        text = b'0'  # disallow
        print("PAIR DOES NOT EXISTS.")
        out = aes_encryption(aes_key, text)
        return out
    else:
        for row in result:
            if (row == device_id):
                text = b'1'  # allow
                print("PAIR EXISTS.")
                out = aes_encryption(aes_key, text)
                return out


def search_for_device_id_in_database(device_id):
    # connect with database
    conn = sqlite3.connect(r"DoorLock.db")

    cur = conn.cursor()

    cur.execute("SELECT ID FROM `Door` WHERE ID = ?", [device_id])

    result = cur.fetchone()
    if (result == None):
        text = b'0'  # "Unknown device."
        out = aes_encryption(aes_key, text)
        return out
    else:
        for row in result:
            if (row == device_id):
                text = b'1'  # known device id
                out = aes_encryption(aes_key, text)
                return out


def aes_encryption(aes_key, text):
    len_of_text = len(text)

    bytes_val = len_of_text.to_bytes(1, 'big')
    # print(bytes_val)

    if (len(text) < 16):
        text = text.ljust(16, b'0')
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0e"
    aes = AES.new(aes_key, AES.MODE_CBC, iv)  # Create an aes object
    # AES. MODE_ The CBC representation pattern is the CBC pattern
    en_text = aes.encrypt(text)
    # print("Ciphertext:", en_text)  # Encrypted plaintext, bytes type
    # print(en_text.hex())
    return en_text


def aes_decryption(aes_key, encrypted_data):
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0e"
    aes = AES.new(aes_key, AES.MODE_CBC, iv)  # Decryption in CBC mode requires re creating an aes object
    den_text = aes.decrypt(encrypted_data)
    print("Plaintext:", den_text.hex())
    output = den_text.hex()
    return output


def generate_rsa_keys():
    new_key = RSA.generate(1024)

    private_key = new_key.exportKey("PEM")
    public_key = new_key.publickey().exportKey("PEM")
    print(public_key)

    fd = open("private_key.pem", "wb")
    fd.write(private_key)
    fd.close()

    fd = open("public_key.pem", "wb")
    fd.write(public_key)
    fd.close()
    return public_key


def stringToBytes(s):
    b = bytearray()
    b = bytearray()
    b.extend(map(ord, s))
    return b


def diffHellmanFormula(p, g, private_number):
    g_powered = pow(g, private_number)
    calculated_number = g_powered % p
    return calculated_number


def numberAsBytes(num):
    return num.to_bytes(4, 'big')






def multi_threaded_client(connection):
    global aes_key, P, G, A, secret_key_bytes


    while True:
        data = connection.recv(2048)
        # print("len of data:", len(data))
        dataAsHex = data.hex()
        request = data[0:1].decode("utf-8")

        if request == "*":
            key_exchange_method = int(input("Choose key exchange method. Press 1 for Diffie Hellman and 0 for RSA:"))
            print("message is:", data[0:1].decode("utf-8"))
            print(key_exchange_method, type(key_exchange_method))
            connection.send(numberAsBytes(key_exchange_method))

        elif request == "!":
            print("message is:", data.decode("utf-8"))
            public_key = generate_rsa_keys()
            connection.send(public_key)

        elif request == "^":
            print("------------------------------------------------------------")
            print("Encrypted AES key", data[0:1].decode("utf-8") + dataAsHex[2:len(dataAsHex)])
            key = RSA.import_key(open('private_key.pem').read())
            r = Random.new().read(128)
            cipher = PKCS1_v1_5.new(key)
            aes_key = cipher.decrypt(data[1:len(data)], r)
            print("----AES KEY----")
            print(aes_key.hex())
            print("------------------------------------------------------------")
        elif request == "P":
            private_number = random.randint(0, 20)
            print(private_number)
            prime_list = primesInRange(5, 250)
            P = random.choice(prime_list)
            print("privateNumber is: ", private_number)
            print("P is: ", P)
            connection.send(numberAsBytes(P))
        elif request == "G":
            G = findPrimitiveRoot(P - 1)
            print("G is: ", G)
            connection.send(numberAsBytes(G))
        elif request == "&":
            decodedData = data.decode("utf-8")
            cropped_data = decodedData[1:len(decodedData)]
            cropped_data = cropped_data.strip()
            cropped_data = cropped_data + ""
            cropped_data = re.sub("[^0-9]", "", cropped_data)
            A = int(float(cropped_data))
            print("A is: ", A)

        elif request == "B":
            B = diffHellmanFormula(P, G, private_number)
            print("B is: ", B)
            connection.send(numberAsBytes(B))
            secret_key = diffHellmanFormula(P, A, private_number)
            aes_key = secret_key.to_bytes(32, 'big')
            print("---SECRET KEY----")
            print(secret_key)
            print("----AES KEY in hex---- ")
            print(aes_key.hex())
            # print(aes_key_hex)

            print("------------------------------------------------------------")
            # encrypted = aes_encryption(secret_key_bytes, "hello")
            # print("ENCRTPYRTTED:  ")
            # print(encrypted)
            # aes_decryption(secret_key_bytes,encrypted)

        elif request == "#":
            print("Encrypted Device ID:", data[0:1].decode("utf-8") + dataAsHex[2:len(dataAsHex)])
            device_id = dataAsHex[2:len(dataAsHex)]

            device_id = aes_decryption(aes_key, data[1:len(data)])
            access_message = search_for_device_id_in_database(device_id)
            connection.send(access_message)

        elif request == "@":
            print("Encrypted Card ID:", data[0:1].decode("utf-8") + dataAsHex[2:len(dataAsHex)])

            card_id = aes_decryption(aes_key, data[1:len(data)])
            print(card_id[:8])
            access_message = search_for_pair_in_database(device_id, card_id[0:8])
            connection.send(access_message)
        else:
            connection.send(stringToBytes("SORRY"))
    connection.close()

def main():
    ServerSideSocket = socket.socket()
    host = '127.0.0.1'
    port = 8080
    ThreadCount = 0
    try:
        ServerSideSocket.bind(("0.0.0.0", port))
    except socket.error as e:
        print(str(e))
    print('Socket is listening..')
    ServerSideSocket.listen(5)

    while True:
        Client, address = ServerSideSocket.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(multi_threaded_client, (Client, ))
        ThreadCount += 1
        print('Thread Number: ' + str(ThreadCount))
    ServerSideSocket.close()




if __name__ == "__main__":
    main()