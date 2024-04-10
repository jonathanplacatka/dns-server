import socket
import sys
from message_builder import MessageBuilder
from message_parser import MessageParser
from constants import Type

class DNSClient:
    def __init__(self, ns_addr, ns_port):
        self.builder = MessageBuilder()
        self.parser = MessageParser()

        self.ns_addr = ns_addr
        self.ns_port = ns_port
        self.ns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #run client cli
    def run_cli(self):
        while(True):
            domain = input("\nEnter a domain name: ")
            self.resolve_domain(domain)

    #send request to DNS server and print the response
    def resolve_domain(self, domain):
        builder = MessageBuilder()
        parser = MessageParser()
        
        request = builder.build_request(domain, True)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(request, (self.ns_addr, self.ns_port))
        response, _ = sock.recvfrom(1024)

        print('\nRESPONSE MESSAGE:\n------------------')
        message = parser.parse_message(response)
       
        message.print()

        print('\nRESPONSE VALUES:\n----------------')
        for r in  message.answers:
            print('{} RECORD: {}'.format(Type(r.type).name, r.rdata))

def main():
    r = DNSClient(sys.argv[1], int(sys.argv[2]))
    r.run_cli()
   
if __name__ == "__main__":
    main()

