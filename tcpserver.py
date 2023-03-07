# Socket server in python using select function


import socket, select
import binascii
import sqlite3
import sys
import traceback
import random
import re
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


def main():

    global aes_key, P, G, A, secret_key_bytes
    # RSA KEYS
    public_key = generate_rsa_keys()
    #private number for DH algorithm
    private_number=random.randint(0,20)
    print(private_number)

    socket_list = []  # list of socket clients
    RECV_BUFFER = 4096  # Advisable to keep it as an exponent of 2
    PORT = 8080
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #server.bind(("0.0.0.0", PORT))
    server.listen(1)
    # Add server socket to the list of readable connections
    socket_list.append(server)
    print("Chat server started on port:" + str(PORT))
    key_exchange_method = int(input("Choose key exchange method. Press 1 for Diffie Hellman and 0 for RSA:"))

    while 1:
        # Get the list sockets which are ready to be read through select
        readable_sockets, writable_sockets, exceptional_sockets = select.select(socket_list, [], [])

        for s in readable_sockets:
            if s == server:
                # Handle the case in which there is a new connection recieved through server_socket
                sockfd, addr = server.accept()
                print("SOCKET FD:", sockfd)
                socket_list.append(sockfd)
                print("Client (%s, %s) connected" % addr)

            # Some incoming message from a client
            else:
                try:
                    data = s.recv(RECV_BUFFER)
                    # print("len of data:", len(data))
                    dataAsHex = data.hex()
                    request = data[0:1].decode("utf-8")

                    if request == "*":
                        print("message is:", data[0:1].decode("utf-8"))
                        print(key_exchange_method,type(key_exchange_method))
                        sockfd.send(numberAsBytes(key_exchange_method))

                    elif request == "!":
                        print("message is:", data.decode("utf-8"))
                        sockfd.send(public_key)

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
                        prime_list = primesInRange(5, 250)
                        P = random.choice(prime_list)
                        print("privateNumber is: ", private_number)
                        print("P is: ", P)
                        sockfd.send(numberAsBytes(P))
                    elif request == "G":
                        G = findPrimitiveRoot(P - 1)
                        print("G is: ", G)
                        sockfd.send(numberAsBytes(G))
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
                        sockfd.send(numberAsBytes(B))
                        secret_key = diffHellmanFormula(P, A, private_number)
                        aes_key = secret_key.to_bytes(32, 'big')
                        print("---SECRET KEY----")
                        print(secret_key)
                        print("----AES KEY in hex---- ")
                        print(aes_key.hex())
                        #print(aes_key_hex)

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
                        sockfd.send(access_message)

                    elif request == "@":
                        print("Encrypted Card ID:", data[0:1].decode("utf-8") + dataAsHex[2:len(dataAsHex)])

                        card_id = aes_decryption(aes_key, data[1:len(data)])
                        print(card_id[:8])
                        access_message = search_for_pair_in_database(device_id, card_id[0:8])
                        sockfd.send(access_message)
                    else:
                        sockfd.send(stringToBytes("SORRY"))

                # client disconnected, so remove from socket list
                except Exception:

                    print(traceback.format_exc())
                    # broadcast_data(sock, "Client (%s, %s) is offline" % addr)
                    print("Client (%s, %s) is offline" % addr)
                    s.close()
                    socket_list.remove(s)
                    continue
    conn.close()
    server.close()


if __name__ == "__main__":
    main()
