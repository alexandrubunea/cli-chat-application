"""
Client program for the CLI Chat Application

Author: Bunea Alexandru
"""
import secrets
import socket

from Security.DHKeys import P_KEY, G_KEY
from Util.Util import sha_256_int, aes_encrypt_str


class Client:
    def __init__(self, host: str, host_port: int, client_port: int = 1713):
        """
        Initialize the client.
        :param host: Host to connect.
        :param host_port: Port of the host.
        :param client_port: Client port which will be used later for messaging.
        """

        # Assign args
        self.host = host
        self.host_port = host_port
        self.client_port = client_port

        # Default values
        self.username = "0"  # Used when there is no username set

        # Diffie-Hellman
        self.private_key = secrets.randbits(4096)  # Generates a number for the secret key
        self.public_key = pow(G_KEY, self.private_key, P_KEY)  # Calculate the public key

    def start(self) -> None:
        """
        Starts the client application.
        :return: None
        """
        print("__          __  _                            _ \n"
              "\ \        / / | |                          | |       \n"
              " \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___  \n"
              "  \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \ \n"
              "   \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |\n"
              "    \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/ \n")
        print("   _____                           ________          __  ___              \n"
              "  / ___/___  _______  __________  / ____/ /_  ____ _/ /_/   |  ____  ____ \n"
              "  \__ \/ _ \/ ___/ / / / ___/ _ \/ /   / __ \/ __ `/ __/ /| | / __ \/ __ \ \n"
              " ___/ /  __/ /__/ /_/ / /  /  __/ /___/ / / / /_/ / /_/ ___ |/ /_/ / /_/ /\n"
              "/____/\___/\___/\__,_/_/   \___/\____/_/ /_/\__,_/\__/_/  |_/ .___/ .___/ \n"
              "                                                           /_/   /_/      \n")
        print(f"* Trying to connect you to the host [{self.host}:{self.host_port}]")
        self.__check_host_availability__()
        self.__establish_connection__()

    def __establish_connection__(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.host_port))
                sha_256_secret_key = self.__secure_connection__(s)
                self.__user_input__(s, sha_256_secret_key)
                s.close()

        except (socket.timeout, socket.error) as e:
            print(f"* Connection ended: {e}")

    def __secure_connection__(self, soc: socket.socket) -> bytes:
        """
        Secure the connection with the server, or another client using Diffie-Hellman Key Exchange
        :param soc: Socket of the client.
        :return: A secure key in hashed in SHA-256.
        """
        # Sharing keys
        packed_key = self.public_key.to_bytes(
            513,
            byteorder="big"
        )
        soc.sendall(packed_key)
        raw_data = soc.recv(513)
        server_public_key = int.from_bytes(raw_data, byteorder="big")
        secret_key = pow(server_public_key, self.private_key, P_KEY)  # Using Diffie-Hellman
        sha_256_secret_key = sha_256_int(secret_key)

        return sha_256_secret_key

    def __encrypt_str__(self, text: str, secret_key: str) -> str:
        """
        Encrypts a text using AES
        :param text: Text to be encrypted
        :return: Encrypted text
        """

    def __user_input__(self, soc: socket.socket, secret_key: bytes) -> None:
        """
        Handles the user input and sends requests to the server
        :param soc: socket of connection
        :param secret_key: secret key used to encrypt the text
        :return: None
        """
        print("* Now you are connected to the server!")
        print("* Please, set your username by typing \"username <your username>\" (e.g: username 8uNNy_h0p)")
        print("* Type \"help\" to see the available commands...")

        running = True  # Run until the user wants to chat with another user

        text_commands = {
            "username": "username [name] - set your username to let other users to find you and chat",
            "search": "search [username] - search a user by its username to see if it's present on the server",
            "chat": "chat [username] - send a request to a user by using their username",
            "requests": "requests - see the requests of the users that want to chat with you",
            "accept": "accept [username] - accept to chat with a user",
            "exit": "exit - close the application"
        }

        while running:
            in_keyboard = input().lower()

            # To optimize data usage, for representing each command we will try to use as few letters as possible
            req = ""

            if " " in in_keyboard:
                cmd, param = in_keyboard.split(" ")
            else:
                cmd = in_keyboard
                param = None

            match cmd:
                case "help":
                    print("* Available commands: username [name], search [username], "
                          "chat [username], requests, accept [request id], exit")
                    for values in text_commands.values():
                        print(values)

                case "username":
                    if not param:
                        print(text_commands["username"])
                        continue

                    req = "u" + self.username + ":" + param
                    req_encrypted = aes_encrypt_str(req, secret_key)
                    soc.sendall(req_encrypted)

                    # Get confirmation from the server
                    res = int.from_bytes(soc.recv(1))

                    if res:
                        self.username = param
                        print(f"* Your username was set successfully to {self.username}")
                    else:
                        print(f"* This username is already taken, please chose another one.")

                case "search":
                    if not param:
                        print(text_commands["search"])
                        continue

                    req = "s" + param
                case "chat":
                    if not param:
                        print(text_commands["chat"])
                        continue

                    req = "c" + param
                case "requests":
                    if not param:
                        print(text_commands["requests"])
                        continue

                    req = "r" + param
                case "accept":
                    if not param:
                        print(text_commands["accept"])
                        continue

                    req = "a" + param
                case "exit":
                    running = False

                    req = "q" + username  # We should let the server know that a user have disconnected
                case _:
                    print("* Invalid command! Type \"help\" to see the available commands...")

    def __check_host_availability__(self) -> bool:
        """
        Checks if the host is up and running on the specified port.
        :return: true if the server is up, false otherwise
        """
        try:
            with socket.create_connection((self.host, self.host_port), 5):
                return True
        except (socket.timeout, socket.error) as e:
            print(f"* Failed to connect to {self.host}:{self.host_port}: {e}")
            return False


if __name__ == "__main__":
    client = Client("127.0.0.1", 1712, 1713)
    client.start()
