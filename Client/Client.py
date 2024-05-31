"""
Client program for the CLI Chat Application

Author: Bunea Alexandru
"""


class Client:
    def __init__(self, host: str, port: int):
        # Assign args
        self.host = host
        self.port = port

        print("Client initialized.")