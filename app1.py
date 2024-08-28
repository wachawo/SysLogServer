#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging.handlers
import socket
import threading
# import urllib3

PORT = 514

LOGGING = {
    'handlers': [
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(filename='app1.log', maxBytes=1024*1024*10, backupCount=3),
    ],
    'format': '%(asctime)s.%(msecs)03d [%(levelname)s]: (%(name)s) %(message)s',
    'level': logging.DEBUG,
    'datefmt': '%Y-%m-%d %H:%M:%S',
}
logging.basicConfig(**LOGGING)
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def tcp_handler(client_socket, addr):
    with client_socket:
        logging.debug(f"[TCP] {addr}: Connected")
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            logging.info(f"[TCP] {addr}: {data.decode('utf-8').replace('\n', ' ')}")
        logging.debug(f"[TCP] {addr}: Disconnected")

def udp_handler(udp_socket):
    while True:
        data, addr = udp_socket.recvfrom(1024)
        logging.info(f"[UDP] {addr}: {data.decode('utf-8')}")

def tcp_server_start():
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.bind(('', PORT))
    tcp_server.listen(5)
    logging.info(f"[TCP] Server listening on port {PORT}")
    while True:
        client_socket, addr = tcp_server.accept()
        t = threading.Thread(target=tcp_handler, args=(client_socket, addr))
        t.start()

def udp_server_start():
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind(('', PORT))
    logging.info(f"[UDP] Server listening on port {PORT}")
    t = threading.Thread(target=udp_handler, args=(udp_server,))
    t.start()

if __name__ == "__main__":
    tcp_thread = threading.Thread(target=tcp_server_start)
    udp_thread = threading.Thread(target=udp_server_start)
    tcp_thread.start()
    udp_thread.start()
    tcp_thread.join()
    udp_thread.join()