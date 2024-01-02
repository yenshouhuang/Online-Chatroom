# IS496: Computer Networks (Spring 2022)
# Programming Assignment 3 - Starter Code
# Name and Netid of each member:
# Member 1: Ken Wu (shwu2) 
# Member 2: Thomas Huang (yenshuo2) 
# Member 3: Jack Chuang (yzc2)

import socket, threading, sys, os, struct, argparse, pickle, datetime
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


    if (res := recvAck(conn)) != 1:
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



class TCPThreadedServer():
    def __init__(self, args: argparse.Namespace) -> None:
        self.HOST = args.hostname
        self.PORT = args.port
        self.SOCK_ADDR = (self.HOST, self.PORT)

        try:
            self.mSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            print('[ERROR] Failed to create socket.', e)
            sys.exit()
    
        try:
            self.mSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception as e:
            print('[ERROR] Failed to set socket option.', e)
            sys.exit()

        try:
            self.mSocket.bind(self.SOCK_ADDR)
        except socket.error as e:
            print('[ERROR] Failed to bind socket.', e)
            sys.exit()

        self.activeUsrDi: Dict[str, socket.socket] = {}
        self.clientPubkey: Dict[str, bytes] = {}
        self.usrRecDi: Dict[str, str] = {}


        usrRecFileName = "users.txt"
        if not os.path.isfile(usrRecFileName):
            file = open(usrRecFileName, "w+")
            file.close()
        with open(usrRecFileName, "r") as f:
            for line in f:
                if line: self.usrRecDi[line.split(" ")[0].strip()] = line.split(" ")[1].strip()




    def listen(self):
        self.mSocket.listen()
        print(f"[INFO] Listening on {self.HOST}:{self.PORT}")

        try:
            while True:
                client, addr = self.mSocket.accept()
                clientRecv, clientRecv_addr = self.mSocket.accept()
                # client.settimeout(60)

                t = threading.Thread(target=self.clientHandler, args=(client, clientRecv, addr))
                t.start()

        except KeyboardInterrupt:
            print(f"\r[INFO] Server shut down manually")
            



    
    def clientHandler(self, client: socket.socket, clientRecv: socket.socket, addr):
        serverPubkey = getPubKey()
        try:
            sendDataStream(client, serverPubkey)
            curUser = recvDataStream(client).decode().strip()
            
            if curUser in self.usrRecDi.keys():
                sendAck(client, 0)
                while True:
                    encrypted_password = recvDataStream(client)
                    recvPassword = decrypt(encrypted_password).decode().strip()
                    if recvPassword != self.usrRecDi[curUser]:
                        sendAck(client, 0)
                    else:
                        sendAck(client, 1)
                        break
            else:
                sendAck(client, 1)
                encrypted_password = recvDataStream(client)
                recvPassword = decrypt(encrypted_password).decode().strip()
                self.usrRecDi[curUser] = recvPassword
                with open("users.txt", "a") as f:
                    f.write(f"{curUser} {recvPassword}\n")
            
            self.activeUsrDi[curUser] = clientRecv
            self.clientPubkey[curUser] = recvDataStream(client)

            while True:
                
                if (op := recvDataStream(client).decode()) == "EX":
                    client.close()
                    clientRecv.close()
                    self.activeUsrDi.pop(curUser)
                    break

                elif op == "BM":
                    msg = recvDataStream(client).decode()

                    for peerName, sock in self.activeUsrDi.items():
                        if peerName == curUser: continue
                        sendAck(sock, 5)
                        sendDataStream(sock, f"*** Incoming Public Message ***: {msg}")
                        TCPThreadedServer.writeChatHistory(peerName, True, curUser, "*", msg)
                    TCPThreadedServer.writeChatHistory(curUser, True, curUser, "*", msg)
                
                elif op == "PM":
                    peerLs = []
                    for usr in self.activeUsrDi:
                        if usr == curUser: continue
                        peerLs.append(usr)
                    sendDataStream(client, pickle.dumps(peerLs))

                    targetPeer = recvDataStream(client).decode().strip()
                    sendDataStream(client, self.clientPubkey[targetPeer])
                    encrypted_msg = recvDataStream(client)
                    msg_to_save = decrypt(recvDataStream(client)).decode()
                    


                    sock = self.activeUsrDi[targetPeer]
                    sendAck(sock, 4)
                    sendDataStream(sock, encrypted_msg)

                    TCPThreadedServer.writeChatHistory(targetPeer, False, curUser, targetPeer, msg_to_save)
                    TCPThreadedServer.writeChatHistory(curUser, False, curUser, targetPeer, msg_to_save)    
                
                elif op == "CH":
                    if not os.path.isfile(f"{curUser}.chat.txt"): 
                        sendAck(client, -1)
                        continue
                    sendAck(client, 1)

                    with open(f"{curUser}.chat.txt", "r") as f:
                        history = ""
                        for line in f:
                            history += line
                        sendDataStream(client, encrypt(history.encode(), self.clientPubkey[curUser]))
        except Exception as e: 
            print(f"[ERROR] error occurs for user: {curUser}\n", e)
    


    @staticmethod
    def writeChatHistory(username: str, isBM: bool, sender: str, receiver: str, msg: str):
        fname = f"{username}.chat.txt"
        if not os.path.isfile(f"{fname}"):
            with open(f"{fname}", "w"):
                pass

        with open(f"{fname}", "a") as f:
            msgType = "BM" if isBM else "PM"
            f.write(f"{datetime.datetime.now()}\t{msgType}\tsentby:{sender} recvby:{receiver}\t{msg}\n")






if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Chat Room Server")
    parser.add_argument("-hn", "--hostname", type=str, metavar="", default="127.0.0.1",
                        help="Hostname")
    parser.add_argument("-p", "--port", type=int, metavar="", default=9999,
                        help="port")
    args = parser.parse_args()

    server = TCPThreadedServer(args)
    server.listen()

        
