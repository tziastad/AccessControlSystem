# DoorLockSystem
The aim of the project is the implementation of a secure access control system with RFID cards, the encoded
communication of IoT devices using cryptographic functions and secure
cryptographic key exchange protocols and the evaluation of the
performance of the cryptographic processes of the system with or without
hardware acceleration. The system consists of a server, the FRDM-K64F microcontroller
and the MIFARE RC522 RFID system. The microcontroller software is based on
the real-time operating system Mbed while the server
is programmed in Python. The MFRC522 driver software used for the
communication between the microcontroller and the RFID system.

The main need of the authorization system is the secure exchange
information between IoT devices to avoid malicious attacks. Thus,
a hybrid cryptographic algorithm is developed by combining the
Rivest-Shamir-Adleman (RSA) algorithm to exchange the cryptographic keys and
the Advanced Encryption Standard (AES) algorithm for the cryptography of
messages. In a second phase, developed the Diffie Hellman (DH) algorithm. The above implementations are done using the
mbedtls library and Python cryptographic libraries.

The most frequent, and most time-consuming processes of the system, are the calls to
AES. Thus, the cryptographic processes of AES are evaluated as a function of
different key sizes using only software and also
hardware acceleration by activating the platform co-processor using
the mmCAU library. The power and energy consumption, the throughput as well as the initialization time of the different AES key sizes,
the execution time of encryption and decryption and the
processor clock cycles per byte of data.
