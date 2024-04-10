import socket
import sys

from constants import Type, RCode

from dns_cache import DNSCache
from message_builder import MessageBuilder
from message_parser import MessageParser

ROOT_SERVER = '198.41.0.4'
DNS_PORT = 53

class DNSServer:

    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        
        self.builder = MessageBuilder()
        self.parser = MessageParser()
        
        self.cache = DNSCache()

    #run the DNS server on a specified port
    def run(self):
        print("Starting DNS server on port {}...".format(self.server_port))
        
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.bind((self.server_ip, self.server_port))
     
        while True:
            try: 
                message, address = server_sock.recvfrom(1024) 
                request = self.parser.parse_message(message)

                if request.question.type == Type.A.value:
                    print("DNS request from {} for {}".format(address, request.question.domain))

                    answers = self.cache.get(request.question.domain)

                    if answers == None:
                        answers = self.resolve(request.question.domain)
             
                    if len(answers) > 0:
                        self.cache.set(request.question.domain, answers, answers[0].ttl)
                        response_bytes = self.builder.build_response(request, RCode.SUCCESS, answers)
                        print("DNS response for {}".format(request.question.domain))
                        for r in  answers:
                            print('\t{} RECORD: {}'.format(Type(r.type).name, r.rdata))
                    else:
                        response_bytes = self.builder.build_response(request, RCode.NOT_FOUND, answers)
                        print("IP Address for {} could not be found".format(request.question.domain))

                else:
                    print('Unsupported Request Type for request:')
                    response_bytes = self.builder.build_response(request, RCode.NOT_IMPLEMENTED, [])
                  
                server_sock.sendto(response_bytes, address)

            except Exception:
                pass

                
    #send a request to a specified name server
    def send_request(self, server_ip, domain):        
        request = self.builder.build_request(domain, False)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(request, (server_ip, DNS_PORT))

        response_bytes, _ = sock.recvfrom(1024)
        response = self.parser.parse_message(response_bytes)
    
        return response
    
    #find the ip address(es) for a given domain
    def resolve(self, domain):
        return self.resolve_recursive(ROOT_SERVER, domain)

    def resolve_recursive(self, server_ip, domain):
        response = self.send_request(server_ip, domain)

        if response.header.answer_cnt > 0:
            #if this is an alias, do another lookup for the canonical name
            cnames = response.get_records_by_type(Type.CNAME.value, response.answers)
            if len(cnames) > 0:
                return response.answers + self.resolve_recursive(ROOT_SERVER, cnames[0].rdata)

            #otherwise, we are done
            return response.answers
        
        elif response.header.auth_cnt > 0:
            if ns_ip := self.resolve_ns_ip(response):
                return self.resolve_recursive(ns_ip, domain)

        return []
 

    #given a response containing an NS record, find the corresponding ip
    def resolve_ns_ip(self, response):
        name_servers = response.get_records_by_type(Type.NS.value, response.auth)
        for rr in name_servers: 
            #first check the response for glue records
            ns_ip = response.get_ns_ip(rr.rdata) 

            #if no glue records exist, do another lookup
            if ns_ip == None: 
                ns_answers = self.resolve_recursive(ROOT_SERVER, rr.rdata)
                ns_ip = ns_answers[0].rdata
            return ns_ip

#TODO: cli args for port?
def main():
    server = DNSServer('localhost', int(sys.argv[1]))
    server.run()
   
if __name__ == "__main__":
    main()

        
    
        



