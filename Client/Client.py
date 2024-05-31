"""
Client program for the CLI Chat Application

Author: Bunea Alexandru
"""
import secrets
import socket

from Security.DHKeys import P_KEY, G_KEY


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

                # Sharing keys
                packed_key = self.public_key.to_bytes(
                    513,
                    byteorder="big"
                )
                s.sendall(packed_key)
                raw_data = s.recv(513)
                server_public_key = int.from_bytes(raw_data, byteorder="big")
                secret_key = pow(server_public_key, self.private_key, P_KEY)  # Using Diffie-Hellman

                s.close()

        except (socket.timeout, socket.error) as e:
            print(f"* Connection ended: {e}")

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
