"""
Server program for the CLI Chat Application

Author: Bunea Alexandru
"""
import asyncio
import secrets

from Security.DHKeys import P_KEY, G_KEY
from Util.Util import sha_256_int, aes_decrypt_to_str


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
        :param reader: Reader used for reciving data.
        :param writer: Writer used for sending data.
        :return: None
        """

        sha_256_secret_key = await self.__secure_connection__(reader, writer)

        if sha_256_secret_key == b'0':  # This mean it was just an availability check, connection can be dropped
            return

        # Run until the client closes the connection
        running = True

        while running:
            raw_data = await reader.read(256)
            if not raw_data:  # User probably disconnected or lost connection
                break

            data = aes_decrypt_to_str(raw_data, sha_256_secret_key)
            cmd, param = None, None

            if len(data) > 1:
                cmd, param = data[:1], data[1:]
            else:
                cmd = data

            match cmd:
                case "u":  # set username
                    current_username, new_username = param.split(":")
                    res = 0  # We assume that the desired username is already taken
                    # If the user doesn't have already a username
                    if current_username == "0" and new_username not in self.users:
                        self.users[new_username] = writer
                        res = 1
                    # If the user does have already a username
                    elif current_username != "0" and new_username not in self.users:
                        self.users[new_username] = self.users[current_username]
                        self.users.pop(current_username)
                        res = 1

                    writer.write(res.to_bytes(1))
                    await writer.drain()

                case "s":  # search username
                    ...
                case "c":  # chat with user
                    ...
                case "r":  # view requests, used to update on client side
                    ...
                case "r":  # accept connection
                    ...
                case "q":  # client closes connection
                    running = False

        writer.close()
        await writer.wait_closed()

    async def __secure_connection__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
        """
        Using Diffie-Hellman Key Excahnge, a secure shared key is created.
        :param reader: Reader to send data to the client.
        :param writer: Writer to recieve data from the client.
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
