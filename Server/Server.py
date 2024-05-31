"""
Server program for the CLI Chat Application

Author: Bunea Alexandru
"""
import asyncio
import secrets

from Security.DHKeys import P_KEY, G_KEY


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
        raw_data = await reader.read(513)  # It's not a magic number, it's from the size of P_KEY which is 4096-bit
        client_public_key = int.from_bytes(raw_data, byteorder="big")

        if not client_public_key:  # This mean it was just an availability check, connection can be dropped
            return

        packed_key = self.public_key.to_bytes(
            513,
            byteorder="big"
        )
        writer.write(packed_key)
        await writer.drain()

        secret_key = pow(client_public_key, self.private_key, P_KEY)  # Using Diffie-Hellman

        writer.close()
        await writer.wait_closed()

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
