"""
Client program for the CLI Chat Application

Author: Bunea Alexandru
"""
import secrets
import socket
import threading
import time

from Security.DHKeys import P_KEY, G_KEY
from Util.Util import sha_256_int, aes_encrypt_str, convert_operation_to_code, aes_decrypt_to_str, \
    convert_code_to_operation_str


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
        self.chat_requests = set()
        self.last_response = None  # Last response from the server to a request
        self.is_host = False
        self.cut_connection_to_server = threading.Event()
        self.chat_mode = False
        self.partner_name = None

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
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            soc.connect((self.host, self.host_port))
        except (socket.timeout, socket.error) as e:
            print(f"* Connection ended: {e}")
            return

        sha_256_secret_key = self.__secure_connection__(soc)

        # Listen the responses from the server
        listen_server_thread = threading.Thread(target=self.__listen_to_server__, args=(soc, sha_256_secret_key))
        listen_server_thread.start()

        # Listen the user input
        listen_user_thread = threading.Thread(target=self.__user_input__, args=(soc, sha_256_secret_key))
        listen_user_thread.start()

        # Wait for both threads to finish
        try:
            listen_server_thread.join()
            listen_user_thread.join()
        except KeyboardInterrupt:
            pass

        if self.chat_mode:
            self.__chat__()

    def __chat__(self):
        """
        Handles the chat between two users
        :return: None
        """
        soc = None

        if self.is_host:
            ...
        else:
            ...

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

    def __listen_to_server__(self, soc: socket.socket, secret_key: bytes) -> None:
        """
        Actively listens to the server for incoming chat requests or other informations.
        :param soc: Socket of the client.
        :param secret_key: Secret key used to communicate with the server.
        :return: None
        """
        while not self.cut_connection_to_server.is_set():
            try:
                # How does listening to server for messages?
                # Well, we listen for all of the responses, but if it is something boring like true or false,
                # or basically something that the user requested, then it will be saved in "last_response"
                # but if it's not, and it's something that the server is sending to the user than that will be handled
                # in a specific way, because is something more "complex"
                encrypted_data = soc.recv(512)
                if encrypted_data == b'0' or encrypted_data == b'1':  # Boring response
                    self.last_response = int(encrypted_data.decode("utf-8"))
                    continue

                data = aes_decrypt_to_str(encrypted_data, secret_key)
                cmd, param = None, None

                if "#" in data:
                    cmd, param = data.split("#", 1)
                else:
                    cmd = data
                cmd = convert_code_to_operation_str(cmd)
                match cmd:
                    case "receive_chat_request":
                        if not param or ":" not in param:
                            print("* Something went really wrong, please try again later")
                            continue

                        sender_addr, sender_name = param.split(":", 1)
                        self.chat_requests.add((sender_addr, sender_name))

                        print(f"* You received a chat request from {sender_name}. Type \"accept {sender_name}\""
                              f" to chat with them!")

                    case "transform_to_host":
                        if not param:
                            print("* Something went really wrong, please try again later")
                            continue

                        print(f"* {param} accepted your request to chat, you will be the host of the conversation using"
                              f" the port {self.client_port}.")
                        self.partner_name = param
                        self.is_host = True

                    case "request_access_port":
                        res = convert_operation_to_code("send_access_port") + "#" + str(self.client_port)
                        encrypted_res = aes_encrypt_str(res, secret_key)
                        soc.sendall(encrypted_res)

                    case "receive_access_port":
                        if not param:
                            print("* Something went really wrong, please try again later")
                            continue

                        self.host_port = int(param)

                    case "receive_ip":
                        if not param:
                            print("* Something went really wrong, please try again later")
                            continue

                        self.host = param

                        res = convert_operation_to_code("ready")
                        encrypted_res = aes_encrypt_str(res, secret_key)
                        soc.sendall(encrypted_res)

                    case "close_connection":
                        self.cut_connection_to_server.set()
                        self.chat_mode = True
                        soc.close()
                        print("Press ENTER to continue...")

            except (socket.timeout, socket.error) as e:
                if not self.cut_connection_to_server.is_set():
                    print(f"* Connection ended: {e}")
                break

    def __receive_res_from_req__(self) -> int:
        """
        Handles the "boring" responses from the server, and ensurses that the data had arrived.
        :return: The response from the server.
        """
        while self.last_response is None:
            time.sleep(0.1)

        res = self.last_response
        self.last_response = None

        if res is None:
            print("Something went really wrong, please try again later.")
            res = 0

        return res

    def __update_requests_list__(self, soc: socket.socket, secret_key: bytes) -> None:
        """
        Update the list of requests by checking if the users in the request list are still online on the server.
        :return: None
        """
        updated_list = set()
        for request in self.chat_requests:
            unique_identifier = request[0]

            req = convert_operation_to_code("check_identity_status") + "#" + unique_identifier
            req_encrypted = aes_encrypt_str(req, secret_key)
            soc.sendall(req_encrypted)

            res = self.__receive_res_from_req__()

            if res:
                updated_list.add(request)

        self.requests_list = updated_list

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

        text_commands = {
            "username": "username [name] - set your username to let other users to find you and chat",
            "search": "search [username] - search a user by its username to see if it's present on the server",
            "chat": "chat [username] - send a request to a user by using their username",
            "requests": "requests - see the requests of the users that want to chat with you",
            "accept": "accept [username] - accept to chat with a user",
            "exit": "exit - close the application"
        }

        while not self.cut_connection_to_server.is_set():
            try:
                in_raw = input()
            except (UnicodeDecodeError, EOFError, KeyboardInterrupt):  # Program closed by the user
                self.cut_connection_to_server.set()
                soc.close()
                break

            in_keyboard = in_raw.lower()

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

                    req = convert_operation_to_code("change_username") + "#" + param
                    req_encrypted = aes_encrypt_str(req, secret_key)
                    soc.sendall(req_encrypted)

                    # Get confirmation from the server
                    res = self.__receive_res_from_req__()

                    if res:
                        self.username = param
                        print(f"* Your username was set successfully to {self.username}")
                    else:
                        print(f"* This username is already taken, please chose another one.")

                case "search":
                    if not param:
                        print(text_commands["search"])
                        continue

                    req = convert_operation_to_code("search_user") + "#" + param
                    req_encrypted = aes_encrypt_str(req, secret_key)
                    soc.sendall(req_encrypted)

                    # Get the result from the server, 1 = users is online, 0 = user is not online
                    res = self.__receive_res_from_req__()

                    status = "online" if res else "offline"
                    print(f"* User {param} is {status}.")

                case "chat":
                    if not param:
                        print(text_commands["chat"])
                        continue

                    if self.username == "0":
                        print("* You must set your username before sending a chat request.")
                        continue

                    if self.username == param:
                        print("* You can't chat with yourself. Or maybe?")
                        continue

                    req = convert_operation_to_code("chat_with_user") + "#" + param
                    req_encrypted = aes_encrypt_str(req, secret_key)
                    soc.sendall(req_encrypted)

                    res = self.__receive_res_from_req__()

                    if res:
                        print(f"* You have sent a chat request to {param}.")
                    else:
                        print(f"* User {param} is offline.")

                case "requests":
                    self.__update_requests_list__(soc, secret_key)

                    if not len(self.requests_list):
                        print("* There are no requests to chat with you.")
                        continue

                    print("* The following users have sent a request to chat with you:")
                    for request in self.requests_list:
                        print(f"> {request[1]}")

                case "accept":
                    if not param:
                        print(text_commands["accept"])
                        continue

                    user = None
                    for request in self.chat_requests:
                        if request[1] == param:
                            user = request
                            break

                    if not user:
                        print("* This user didn't sent you a request to chat with you. To see if someone had sent"
                              "you a chat request type \"requests\".")
                        continue

                    req = convert_operation_to_code("accept_chat_request") + "#" + user[0] + ":" + user[1]
                    req_encrypted = aes_encrypt_str(req, secret_key)
                    soc.sendall(req_encrypted)

                    res = self.__receive_res_from_req__()
                    if res:
                        print(f"* You will be connected to {param} soon.")
                        self.partner_name = param
                    else:
                        print(f"* {param} is no longer online, or they had reconnected.")

                case "exit":
                    self.cut_connection_to_server.set()
                    soc.close()
                    break

                case _:
                    if not self.cut_connection_to_server.is_set():
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
