# IS496: Computer Networks (Spring 2022)
# Programming Assignment 3 - Starter Code
# Name and Netid of each member:
# Member 1: Ken Wu (shwu2) 
# Member 2: Thomas Huang (yenshuo2) 
# Member 3: Jack Chuang (yzc2)

import socket, threading, sys, os, struct, argparse, pickle
from typing import *

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from pg3lib import *


BUFFER = 1024

def addrToString(addr: Tuple[str, str]):
    return f"{addr[0]}:{addr[1]}"


def sendAck(conn: socket.socket, ack: int):
    data = str(ack)
    payload = f"{data:<{64}}"
    conn.sendall(payload.encode("utf-8"))


def recvAck(conn: socket.socket) -> Union[int, None]:
    data = conn.recv(64).decode().strip()
    return int(data)


def sendDataStream(conn: socket.socket, data: Union[str, bytes]):
    data_encoded = data.encode() if type(data) == str else data
    size = len(data_encoded)
    size_segment = f"{size:<{BUFFER}}".encode()

    conn.sendall(size_segment)

    res = recvAck(conn)

    if res != 1:
        print("[ERROR] receiver did not recive correct size segment")
        return

    i = 0
    while i * BUFFER < size:
        payload = data_encoded[i*BUFFER : (i+1)*BUFFER]
        conn.sendall(payload)
        i += 1


def recvDataStream(conn: socket.socket) -> bytes:
    size_segment = conn.recv(BUFFER).decode()

    try:
        size = int(size_segment.strip())
        if size < 0: raise Exception("Size is smaller than 0")
        sendAck(conn, 1)
    except Exception as e:
        print(e)
        sendAck(conn, -1)

    data = b""
    while len(data) < size:
        data += conn.recv(BUFFER)

    return data





class TCPThreadedClient():
    def __init__(self, args: argparse.Namespace) -> None:
        self.HOST = args.hostname
        self.PORT = args.port
        self.SOCK_ADDR = (self.HOST, self.PORT)

        try:
            self.mSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            print('[ERROR] Failed to create mSocket.', e)
            sys.exit()

        try:
            self.recvSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            print('[ERROR] Failed to create recvSocket.', e)
            sys.exit()

        self.lastInput = ""

        

    def connect(self):
        try:
            self.mSocket.connect(self.SOCK_ADDR)
        except Exception as e:
            print("[ERROR] (mSocket) Something went wrong while connecting to server", e)
            sys.exit()

        try:
            self.recvSocket.connect(self.SOCK_ADDR)
        except Exception as e:
            print("[ERROR] (recvSocket) Something went wrong while connecting to server", e)
            sys.exit()

        sendThread = threading.Thread(target=self.sendHandler)
        recvThread = threading.Thread(target=self.recvHandler)
        sendThread.start()
        recvThread.start()


    def sendHandler(self):
        try:
            serverPubkey = recvDataStream(self.mSocket)
            sendDataStream(self.mSocket, args.username)
            usrAck = recvAck(self.mSocket)
            if usrAck != 1:
                while True:
                    password = input("Enter user's password: ").strip()
                    sendDataStream(self.mSocket, encrypt(password.encode(), serverPubkey))
                    pwAck = recvAck(self.mSocket)
                    if pwAck == 1: break
            else:
                password = input("Enter password: ")
                sendDataStream(self.mSocket, encrypt(password.encode(), serverPubkey))
                
            mPubkey = getPubKey()
            sendDataStream(self.mSocket, mPubkey)

            while True:
                op = self.lastInput = input("> ")
                sendDataStream(self.mSocket, op)

                if op == "EX":
                    self.mSocket.close()
                    self.recvSocket.close()
                    break
                elif op == "BM":
                    msg = input("> Enter the public message: ")
                    sendDataStream(self.mSocket, msg)
                elif op == "PM":
                    peerList = pickle.loads(recvDataStream(self.mSocket))
                    for i, peer in enumerate(peerList):
                        if i == 0: print("Peer(s) online: ")
                        print(peer)
                    
                    while True:
                        targetPeer = input("Peer to message: ")
                        if targetPeer in peerList:
                            msg = input("Enter private message: ")
                            break
                        print("Invalid user. Try again...")

                    sendDataStream(self.mSocket, targetPeer)
                    targetPubkey = recvDataStream(self.mSocket)

                    
                    sendDataStream(self.mSocket, 
                                   encrypt(f"*** Incoming Private Message ***: {msg}".encode(), targetPubkey))
                    sendDataStream(self.mSocket, 
                                   encrypt(f"{msg}".encode(), serverPubkey))

                elif op == "CH":
                    res = recvAck(self.mSocket)
                    if res != 1: 
                        print("No chat history")
                        continue

                    history = decrypt(recvDataStream(self.mSocket)).decode()
                    print(history)
        except Exception as e:
            print(e)
            sendDataStream(self.mSocket, "EX")
            self.mSocket.close()
        except KeyboardInterrupt as e:
            print("[INFO] Shutting down connection manually...")
            sendDataStream(self.mSocket, "EX")
            self.mSocket.close()

        


    def recvHandler(self):
        try:
            while True:
                msgType = recvAck(self.recvSocket)
                if msgType == 5:
                    msg = recvDataStream(self.recvSocket).decode()
                elif msgType == 4:
                    encrpyted_msg = recvDataStream(self.recvSocket)
                    msg = decrypt(encrpyted_msg).decode()

                print("\n", msg)
                print("\r> ", end="")
        except Exception as e:
            if self.lastInput != "EX":
                print("[ERROR] Error occured in recvHandler: ", e)
            self.recvSocket.close()




if __name__ == '__main__': 
    parser = argparse.ArgumentParser(description="Chat Room Server")
    parser.add_argument("-hn", "--hostname", type=str, metavar="", default="127.0.0.1",
                        help="Hostname")
    parser.add_argument("-p", "--port", type=int, metavar="", default=9999,
                        help="port")
    parser.add_argument("-un", "--username", type=str, metavar="", default="testuser",
                        help="enter a unique username")
    args = parser.parse_args()

    client = TCPThreadedClient(args)
    client.connect()
