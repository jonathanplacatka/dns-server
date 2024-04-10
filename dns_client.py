import socket
import sys
from message_builder import MessageBuilder
from message_parser import MessageParser


class DNSClient:
    def __init__(self, ns_addr, ns_port):
        self.builder = MessageBuilder()
        self.parser = MessageParser()

        self.ns_addr = ns_addr
        self.ns_port = ns_port
        self.ns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def run_cli(self):
        while(True):
            domain = input("Enter a domain name: ")
            self.resolve_domain(domain)

    def resolve_domain(self, domain):
        builder = MessageBuilder()
        parser = MessageParser()
        
        request = builder.build_request(domain, True)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(request, (self.ns_addr, self.ns_port))
        response, _ = sock.recvfrom(1024)

        message = parser.parse_message(response)
        message.print()

def main():
    r = DNSClient(sys.argv[1], int(sys.argv[2]))
    r.run_cli()
   
if __name__ == "__main__":
    main()

