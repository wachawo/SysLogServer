#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging.handlers
import signal
import socket
import threading
import os
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

PORT = 514
EVENT = threading.Event()
LOG_PATH = 'logs'

LOGGING = {
    'handlers': [
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(filename=f'{LOG_PATH}/app1.log', maxBytes=1024*1024*1024, backupCount=10),
    ],
    'format': '%(asctime)s.%(msecs)03d [%(levelname)s]: (%(name)s) %(message)s',
    'level': logging.DEBUG,
    'datefmt': '%Y-%m-%d %H:%M:%S',
}
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(**LOGGING)
logging.getLogger('watchdog.observers.inotify_buffer').setLevel(logging.WARNING)
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
        logging.info(f"[UDP] {addr}: {data.decode('utf-8').replace('\n', ' ')}")

def tcp_server_start():
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.bind(('', PORT))
    tcp_server.listen(5)
    logging.info(f"[TCP] Server listening on port {PORT}")
    # while True:
    #    client_socket, addr = tcp_server.accept()
    #    t = threading.Thread(target=tcp_handler, args=(client_socket, addr))
    #    t.start()
    tcp_server.settimeout(1)
    while not EVENT.is_set():
        try:
            client_socket, addr = tcp_server.accept()
            t = threading.Thread(target=tcp_handler, args=(client_socket, addr))
            t.start()
        except socket.timeout:
            continue
    tcp_server.close()
    logging.info(f"[TCP] Server on port {PORT} closed")

def udp_server_start():
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind(('', PORT))
    logging.info(f"[UDP] Server listening on port {PORT}")
    # t = threading.Thread(target=udp_handler, args=(udp_server,))
    # t.start()
    udp_server.settimeout(1)
    while not EVENT.is_set():
        try:
            data, addr = udp_server.recvfrom(1024)
            logging.info(f"[UDP] {addr}: {data.decode('utf-8').replace('\n', ' ')}")
        except socket.timeout:
            continue
    udp_server.close()
    logging.info(f"[UDP] Server on port {PORT} closed")

def signal_handler(sig, frame):
    logging.info("Shutdown signal received")
    EVENT.set()

class ReloadHandler(FileSystemEventHandler):
    def __init__(self, shutdown_event):
        self.shutdown_event = EVENT

    @staticmethod
    def restart_server():
        logging.info("Restarting server...")
        python = sys.executable
        os.execl(python, python, *sys.argv)

    def on_modified(self, event):
        if event.src_path.endswith('.py'):
            logging.info(f"Modified: {event.src_path}")
            self.restart_server()

def start_file_watcher():
    event_handler = ReloadHandler(EVENT)
    obsrv = Observer()
    path = os.path.abspath('.')
    if not os.path.exists(path):
        logging.error(f"Path {path} does not exist")
        return None
    obsrv.schedule(event_handler, path=path, recursive=False)
    obsrv.start()
    return obsrv

if __name__ == "__main__":
    if not os.path.exists(LOG_PATH):
        os.makedirs(LOG_PATH)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    ob_server = start_file_watcher()
    if ob_server:
        try:
            tcp_thread = threading.Thread(target=tcp_server_start)
            udp_thread = threading.Thread(target=udp_server_start)
            tcp_thread.start()
            udp_thread.start()
            tcp_thread.join()
            udp_thread.join()
        finally:
            ob_server.stop()
            ob_server.join()
        logging.info("Shutdown complete")
    else:
        logging.error("Failed to start file watcher")
