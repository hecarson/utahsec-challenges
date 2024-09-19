from socketserver import ThreadingTCPServer, StreamRequestHandler
import subprocess
from argparse import ArgumentParser
import os

SUBPROCESS_TIMEOUT = 60 * 60 # 1 hour

class ChalTCPHandler(StreamRequestHandler):
    def handle(self):
        subprocess.run(["python", "chal.py"], stdin=self.rfile, stdout=self.wfile, timeout=SUBPROCESS_TIMEOUT)

if "FLAG" not in os.environ:
    print("FLAG environment variable not set!")
    exit()

arg_parser = ArgumentParser()
arg_parser.add_argument("-a", default="0.0.0.0") # Listening address
arg_parser.add_argument("-p", required=True) # Listening port
args = arg_parser.parse_args()
address = args.a
port = int(args.p)

class ChalTCPServer(ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True # Allow rapid server restart

server = ChalTCPServer((address, port), ChalTCPHandler)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
