# Programming Assignment 3 (PG3) - Online Chat Room

IS496: Computer Networks (Spring 2023) \
Name and Netid of each member: \
Member 1: Ken Wu (shwu2) \
Member 2: Thomas Huang (yenshuo2) \
Member 3: Jack Chuang (yzc2)

## Background

We implement the client and server sides of a online chat room application in this programming assignment. TCP will be used for the message transfer, with the client determining the operation to be performed (BM: Broadcast Messaging, PM: Private Messaging, EX: Exit). The server will respond to the specific command appropriately. This document contains specifics about the protocol.

## Preparation

```shell
import socket
import threading
import sys, argparse, subprocess, os
```

## Execution

Please connect to your student machines first.

```shell
$ ssh YOUR_NET_ID@student00.ischool.illinois.edu

$ ssh YOUR_TEAM_MEMBER_NET_ID@student01.ischool.illinois.edu
```

The server is running on student00, the client should be tested on student student01/student02/student03.



### Chat Room Program

Our implementation includes both the client and server sides of an chat room app that transfers messages over TCP. The client is in charge of choosing the command.  

Chatroom client that takes in:

- The hostname of the server (argument 1).
- The port number on the server (argument 2).

```shell
YOUR_NET_ID@is-student00:~$ /YOUR_PATH/python3 chatclient.py -hn [HOST_NAME] -p [PORT_NUMBER]
```

Chatroom server that takes in:

- The port number on the server (argument 1).

Run the socket server program.

```shell
YOUR_NET_ID@is-student00:~$ /YOUR_PATH/python3 chatserver.py -p [PORT_NUMBER]
```

Then the terminal will show the messages below:

```
[INFO] Waiting for connection on port 9999...

```

Run the socket client program.

```shell
YOUR_TEAM_MEMBER_NET_ID@is-student01:~$ /YOUR_PATH/python3 client.py -hn [SERVER_HOST_NAME] -p [PORT_NUMBER]
```

Then the server terminal will show the messages based on New User or Existing User:

New User:

```shell
Enter Password: 
```

Existing User:

```shell
Enter user's password: 
```

After connection established, client sends command to server; then server responds accordingly.


[BM]: Client broadcast messages to all active users who have successfully logged into the system. The client sends the operation to the server, which acknowledges the request and prompts the client to send the message. The server keeps track of all client connections and sends the broadcast message to each one. Once the message is sent, the server sends a confirmation to the client, and both return to their initial states of waiting for new operations or messages. The specific format and content of the acknowledgment and confirmation messages are left to implementation discretion.


[PM]: Client send a message private message to a specific online user. The server keeps track of the usernames of all online users and sends this list to the client upon request. The client then prompts the user for the target user's username and message. The client sends this information to the server, which checks if the target user exists/online. If the target user is online, the server forwards the message to their corresponding socket descriptor, and a confirmation message is sent to the client indicating whether the message was sent or the target user does not exist. The protocol then returns to the initial "prompt user for operation" and "wait for operation from client" state. 

[CH]: Client send request for getting chat history. Server load file and then send the chat history back to client. Works even if you log out and log back in again

[EX]: Client sends an operation to the server to close its connection and end the program. On receiving the operation, the server closes the socket descriptor for the client and updates its tracking record of active clients and online user's usernames. This ensures proper termination of the communication and releases the resources used by the client and server.

```
If client quits, server return to "[INFO] Waiting for connection on port 9999..."
```
