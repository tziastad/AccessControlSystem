# Socket server in python using select function


import socket, select
import sqlite3
import sys
import traceback



from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5

from Crypto.Cipher import AES

def search_for_pair_in_database(device_id,card_id):
    # connect with database
    conn = sqlite3.connect(r"C:\Users\Dora\Desktop\Start Diplomatiki\DoorLock.db")


    print("pair: ",device_id,"-", card_id)

    cur = conn.cursor()

    cur.execute("SELECT DoorID FROM `User` WHERE ID = ?", [card_id])

    result = cur.fetchone()
    if (result == None):
        return "disallow"
    else:
        for row in result:
            if(row==device_id):
                return "allow"

def search_for_device_id_in_database(device_id):
    # connect with database
    conn = sqlite3.connect(r"C:\Users\Dora\Desktop\Start Diplomatiki\DoorLock.db")

    cur = conn.cursor()

    cur.execute("SELECT ID FROM `Door` WHERE ID = ?", [device_id])

    result = cur.fetchone()
    if (result == None):
        return "Sorry, this device id is unknown."
    else:
        for row in result:
            if(row==device_id):
                return "Device id is known."


def aes_decryption(aes_key,encrypted_data):
    """aes = AES.new(aes_key, AES.MODE_ECB)  # Decryption in ECB mode requires re creating an aes object
    decrypted_text = aes.decrypt(encrypted_data)
    print("Plaintext:", decrypted_text.hex())
    output = decrypted_text.hex()"""
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    aes = AES.new(aes_key, AES.MODE_CBC, iv)  # Decryption in CBC mode requires re creating an aes object
    den_text = aes.decrypt(encrypted_data)
    print("Plaintext:", den_text)
    output = den_text.hex()
    return output


def main():
    CONNECTION_LIST = []  # list of socket clients
    RECV_BUFFER = 4096  # Advisable to keep it as an exponent of 2
    PORT = 8080

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this has no effect, why ?
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", PORT))
    server_socket.listen(1)

    # Add server socket to the list of readable connections
    CONNECTION_LIST.append(server_socket)

    print("Chat server started on port !" + str(PORT))


    #RSA KEYS
    new_key = RSA.generate(1024)

    private_key = new_key.exportKey("PEM")
    public_key = new_key.publickey().exportKey("PEM")
    print(type(public_key))
    print(len(public_key))
    print(public_key)

    fd = open("private_key.pem", "wb")
    fd.write(private_key)
    fd.close()

    fd = open("public_key.pem", "wb")
    fd.write(public_key)
    fd.close()


    while 1:
        # Get the list sockets which are ready to be read through select
        read_sockets, write_sockets, error_sockets = select.select(CONNECTION_LIST, [], [])

        for sock in read_sockets:

            # New connection
            if sock == server_socket:
                # Handle the case in which there is a new connection recieved through server_socket
                sockfd, addr = server_socket.accept()
                CONNECTION_LIST.append(sockfd)
                print("Client (%s, %s) connected" % addr)

            # Some incoming message from a client
            else:
                # Data recieved from client, process it
                try:
                    # In Windows, sometimes when a TCP program closes abruptly,
                    # a "Connection reset by peer" exception will be thrown
                    data = sock.recv(RECV_BUFFER)
                    print("len of data:", len(data))
                    #print(type(data))
                    #print(data)F
                    dataAsHex=data.hex()
                    global aes_key
                    #print("data as hex:", dataAsHex)
                    if (data[0:1].decode("utf-8") == "!"):
                        print("message is:", data.decode("utf-8"))
                        #sockfd.send(public[26:247])
                        sockfd.send(public_key)
                    elif (data[0:1].decode("utf-8") == "^"):
                        print("------------------------------------------------------------")
                        print("Encrypted AES key", data[0:1].decode("utf-8") + dataAsHex[2:len(dataAsHex)])
                        #print("kommeno:",data[1:len(data)])
                        #print(len(data[1:len(data)]))

                        key = RSA.import_key(open('private_key.pem').read())
                        sentinel = Random.new().read(128)  # data length is 256
                        cipher = PKCS1_v1_5.new(key)
                        aes_key = cipher.decrypt(data[1:len(data)], sentinel)
                        print(".......................")
                        #print("decrypted message:",aes_key)
                        print(len(aes_key))
                        print("aes key is:", aes_key.hex())
                        print("------------------------------------------------------------")
                    elif(data[0:1].decode("utf-8")=="#"):


                        print("Data device:", data[0:1].decode("utf-8") + dataAsHex[2:len(dataAsHex)])
                        device_id=dataAsHex[2:len(dataAsHex)]
                        #print(data[1:len(data)])
                        #print(len(data[1:len(data)]))


                        #aes = AES.new(aes_key, AES.MODE_ECB)  # Decryption in CBC mode requires re creating an aes object
                        #den_text = aes.decrypt(data[1:len(data)])
                        #print("Plaintext:", den_text.hex())
                        device_id=aes_decryption(aes_key,data[1:len(data)])
                        access_message = search_for_device_id_in_database(device_id)
                        sockfd.send(access_message.encode())
                    elif(data[0:1].decode("utf-8")=="@"):
                        print("Data card:", data[0:1].decode("utf-8") + dataAsHex[2:len(dataAsHex)])
                        card_id = dataAsHex[2:len(dataAsHex)]
                        #print(data)
                        #print(len(data))
                        #print(device_id)
                        card_id = aes_decryption(aes_key, data[1:len(data)])
                        #print(len(card_id))
                        print(card_id[:8])
                        access_message=search_for_pair_in_database(device_id,card_id[0:8])
                        sockfd.send(access_message.encode())

                # client disconnected, so remove from socket list
                except Exception:

                    print(traceback.format_exc())
                    # broadcast_data(sock, "Client (%s, %s) is offline" % addr)
                    print("Client (%s, %s) is offline" % addr)
                    sock.close()
                    CONNECTION_LIST.remove(sock)
                    continue
    conn.close()
    server_socket.close()


if __name__ == "__main__":
    main()
