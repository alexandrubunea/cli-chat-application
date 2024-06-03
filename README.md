# CLI Chat Application

This project is a command-line interface (CLI) chat application that enables secure communication between clients and a server using cryptographic techniques. The application is built in Python and utilizes asynchronous programming to handle multiple client connections efficiently. <br>
The server will only handle which users want to chat, based on their username, then they are chatting will be disconnected from the server to free the load, and start chatting on a private connection hosted by one of them (still in a secure way).

## Features

- **SHA-256 Hashing**: Securely hash numbers using the SHA-256 algorithm.
- **AES Encryption/Decryption**: Encrypt and decrypt messages using AES (Advanced Encryption Standard) in CBC mode.
- **Diffie-Hellman Key Exchange**: Securely exchange keys between clients and the server.
- **Multiple Commands**: Support various operations such as changing usernames, searching users, sending chat requests, and more.
- **Asynchronous Programming**: Handle multiple client connections simultaneously using Python's `asyncio` module.
- **Threading**: The client uses two threads for I/O, one to receive data from the server continuously, and another one to send data.

## Requirements

- Python 3.8 or higher
- `cryptography` library
- `blessed` library
- `argparse` library (standard with Python)
- `hashlib` library (standard with Python)
- `secrets` library (standard with Python)
- `socket` library (standard with Python)
- `threading` library (standard with Python)
- `time` library (standard with Python)
- `deque` library (standard with Python)

Install the required packages using pip:

```sh
pip install cryptography blessed
```
## Usage

### Server
Start the server with the following command:
```sh
python Server.py --host <host> --port <port> --max_clients_allowed <max_clients> --debug
```
Replace `<host>`, `<port>`, and `<max_clients>` with appropriate values. Use the --debug flag to enable debugging information.

### Client
Start the client with the following command:
```sh
python Client.py --host <host> --port <port> --username <username>
```
Replace `<host>`, `<port>`, and `<username>` with appropriate values.

## File Descriptions
### Util.py
Contains utility functions for cryptographic operations and command conversion.
### Client.py
Handles the client-side operations, connecting to the server, sending and receiving messages.
### Server.py
Manages server-side operations, including handling multiple client connections, processing commands, and managing secure communication.
### DHKeys.py
Defines the Diffie-Hellman keys used for secure key exchange.

## Contributing
Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
3. Make your changes.
4. Commit your changes (git commit -am 'Add new feature').
5. Push to the branch (git push origin feature-branch).
6. Create a new Pull Request.

## License
This project is licensed under the Apache 2.0 License. See the LICENSE file for details.

## Known issues
There is a compatibility issue in Linux based operating systems, on the client side, when two clients start to chat, the chat gets a little buggy.

## Acknowledgments
Author: Bunea Alexandru <br>
Thanks to the developers and maintainers of the libraries used in this project.<br>
Feel free to raise any issues or pull requests on the GitHub repository.

## Images
### Bob's client
![bob-client](https://i.imgur.com/bVkK2Qu.png)
### Alice's client
![alice-client](https://i.imgur.com/8unDmex.png)
### Server Log
![server](https://i.imgur.com/xDAQQNT.png)
### Bob and Alice chatting
![bob-alice-chat](https://i.imgur.com/LMWBER1.png)
