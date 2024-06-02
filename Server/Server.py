"""
Server program for the CLI Chat Application

Author: Bunea Alexandru
"""
import asyncio
import secrets

from Security.DHKeys import P_KEY, G_KEY
from Util.Util import sha_256_int, aes_decrypt_to_str, convert_code_to_operation_str, convert_operation_to_code, \
    aes_encrypt_str, generate_random_sha_256


class Server:
    def __init__(self, host: str = "127.0.0.1", port: int = 1712, max_clients_allowed: int = 100, debug: bool = True):
        """
        Initialize the server.
        :param host: Host of the server.
        :param port: Port of the server.
        :param max_clients_allowed: Maximum number of clients allowed to connect to the server.
        :param debug: If it's true the server will print to the console different debugging information.
        """

        # Assign args
        self.host = host
        self.port = port
        self.max_clients_allowed = max_clients_allowed
        self.debug = debug

        # Diffie-Hellman
        self.private_key = secrets.randbits(4096)  # Generates a number for the secret key
        self.public_key = pow(G_KEY, self.private_key, P_KEY)  # Calculate the public key

        # Users
        self.users = {}  # This hashmap will store their connection to the server, and will have their username as key
        # This hashmap is used to store usernames based on ips, so when a socket is closed suddenly, the username will
        # be removed from self.users
        self.identities = {}

        self.__print_debug__("The server was initialized.")
        self.__print_debug__(f"Will run on {host}:{port}")
        self.__print_debug__(f"Allowing a maximum number of {max_clients_allowed} clients to connect.")

    def start(self) -> None:
        """
        Starts the server.
        :return: None
        """
        asyncio.run(self.__run_server__())

    async def __run_server__(self):
        """
        Stars a server instance, so multiple clients can connect
        :return:
        """
        self.__print_debug__("Starting a server instance on asyncio...")
        server = await asyncio.start_server(self.__handle_client__, self.host, self.port)

        # Gets all the sockets where the server is running.
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        self.__print_debug__(f"Serving on {addrs}")

        async with server:
            await server.serve_forever()

    async def __handle_client__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """
        Handles the connection with a client.
        :param reader: Reader used for receiving data.
        :param writer: Writer used for sending data.
        :return: None
        """

        try:
            sha_256_secret_key = await self.__secure_connection__(reader, writer)
            user_identity = generate_random_sha_256()  # Gives the user an identity, to avoid confusions in the future
            user_peername = writer.get_extra_info("peername")
            current_username = "0"

            if sha_256_secret_key == b'0':  # This means it was just an availability check, connection can be dropped
                self.__print_debug__(f"Connection tested by {user_peername}")
                return

            # Run until the client closes the connection
            while True:
                try:
                    raw_data = await reader.read(512)
                    if not raw_data:
                        # If no data is received, assume connection is closed
                        raise ConnectionResetError("Connection closed by the client")

                    data = aes_decrypt_to_str(raw_data, sha_256_secret_key)
                    cmd, param = None, None

                    if "#" in data:
                        cmd, param = data.split("#", 1)
                    else:
                        cmd = data
                    cmd = convert_code_to_operation_str(cmd)

                    self.__print_debug__(f"Command {cmd} from {user_peername} with param {param}")

                    match cmd:
                        case "change_username":
                            new_username = param
                            res = self.__change_user_username__(current_username, new_username,
                                                                user_identity, writer, sha_256_secret_key)

                            # Update the username on server-side too...
                            if res == b'1':
                                current_username = new_username

                            writer.write(res)
                            await writer.drain()

                        case "search_user":
                            res = self.__search_username__(param)

                            writer.write(res)
                            await writer.drain()

                        case "chat_with_user":
                            from_user = self.identities[user_identity]
                            res = await self.__send_chat_request__(from_user, user_identity, param)

                            writer.write(res)
                            await writer.drain()

                        case "check_identity_status":
                            res = self.__is_identity_online__(param)

                            writer.write(res)
                            await writer.drain()

                        case "accept_chat_request":
                            # Your logic for accepting a chat request
                            pass

                except (ConnectionResetError, OSError):
                    # Connection with the user is broken.
                    self.__print_debug__(f"User {user_peername} has disconnected.")
                    if user_identity in self.identities:
                        self.identities.pop(user_identity)
                        self.__print_debug__(f"{user_identity} removed from identities list.")

                    if current_username != "0" and current_username in self.users:
                        self.users.pop(current_username)
                        self.__print_debug__(f"{current_username} removed from users list.")

                    writer.close()
                    await writer.wait_closed()
                    break

                except Exception as e:
                    # Handle unexpected exceptions
                    self.__print_debug__(f"An unexpected error occurred: {e}")
                    writer.close()
                    await writer.wait_closed()
                    break

        except Exception as e:
            self.__print_debug__(f"Failed to establish secure connection or an error occurred: {e}")

    async def __send_chat_request__(self, from_user: str, from_user_identity: str,
                                    to_user: str) -> bytes:
        """
        Sends a chat request from a user to another user.
        :param from_user: User that sends the chat request.
        :param to_user: User who will receive the chat request.
        :return: 1 if the operation was successful, 0 otherwise.
        """
        if not self.__search_username__(to_user):  # If to_user is offline
            return b'0'

        writer, sha_256_secret_key = self.users[to_user]
        res = convert_operation_to_code("receive_chat_request") + "#" + from_user_identity + ":" + from_user
        res_encrypted = aes_encrypt_str(res, sha_256_secret_key)

        writer.write(res_encrypted)
        await writer.drain()

        return b'1'

    def __is_identity_online__(self, identity: str) -> bytes:
        """
        Checks if a user is online by using its identity.
        :param identity: Identity of the user.
        :return: True if user is online, False otherwise.
        """
        return b'1' if identity in self.identities else b'0'

    def __search_username__(self, username: str) -> bytes:
        """
        Search a user by its username to check if its active or not.
        :param username: username to be checked.
        :return: 1 if the username is active, 0 if not.
        """
        return b'1' if username in self.users else b'0'

    def __change_user_username__(self, current_username: str, new_username: str,
                                 user_identity: str, writer: asyncio.StreamWriter, sha_256_secret_key: bytes) -> bytes:
        """
        Set/update the username of a user.
        :param current_username: Current username, if the user doesn't have a username this value will be "0"
        :param new_username: New username
        :param user_identity: Identity of the user, is a random SHA-256
        :param writer: Writer used for sending data. Here is used to link the username to a sending data stream (writer)
        :return: 1 if the change was successful, otherwise 0
        """
        if new_username == "0":  # Invalid username, "0" is used to express a username that is not set
            return b'0'
        if new_username in self.users:
            return b'0'

        # If the user doesn't have already a username
        if current_username == "0":
            self.users[new_username] = (writer, sha_256_secret_key)  # sha_256_secret_key is required...
            self.identities[user_identity] = new_username

            user_peername = writer.get_extra_info("peername")
            self.__print_debug__(f"{user_peername} set their username to {new_username}")

        # If the user does have already a username
        else:
            self.users[new_username] = self.users[current_username]
            self.identities[user_identity] = new_username
            self.users.pop(current_username)

            self.__print_debug__(f"{current_username} changed their username to {new_username}")

        return b'1'

    async def __secure_connection__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
        """
        Using Diffie-Hellman Key Excahnge, a secure shared key is created.
        :param reader: Reader to send data to the client.
        :param writer: Writer to receive data from the client.
        :return: A secure key in hashed in SHA-256.
        """
        raw_data = await reader.read(513)  # It's not a magic number, it's from the size of P_KEY which is 4096-bit
        client_public_key = int.from_bytes(raw_data, byteorder="big")

        if not client_public_key:  # This mean it was just an availability check, connection can be dropped
            return b'0'

        packed_key = self.public_key.to_bytes(
            513,
            byteorder="big"
        )
        writer.write(packed_key)
        await writer.drain()

        secret_key = pow(client_public_key, self.private_key, P_KEY)  # Using Diffie-Hellman
        sha_256_secret_key = sha_256_int(secret_key)

        self.__print_debug__(f"Secure connection established with {writer.get_extra_info('peername')[0]}")

        return sha_256_secret_key

    def __print_debug__(self, msg: str) -> None:
        """
        Prints a string to the console as a debug message
        :param msg: The message to print
        :return: None
        """
        if self.debug:
            print(f"[DEBUG]: {msg}")


if __name__ == "__main__":
    zerver = Server()
    zerver.start()
