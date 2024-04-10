import struct
import random

from bitstring import BitArray
from dns_message import DNSHeader, DNSQuestion, DNSResourceRecord, DNSMessage
from message_parser import MessageParser

from constants import Type

class MessageBuilder:

    #build a request bytestring for a standard dns request
    def build_request(self, domain, recursion_desired):
        bytestring = b''

        #build header
        header = DNSHeader()
        
        header.id = random.randint(0, 65535)
        header.question_cnt = 1
        header.query_response = 0
        header.recursion_desired = recursion_desired

        header.flags = self._build_header_flags(header)
        bytestring += self._build_header(header)

        #build question
        question = DNSQuestion()
        question.domain = domain
        question.type = Type.A.value

        bytestring += self._build_question(question)

        return bytestring
    
    #build a response bytestring for a given request
    def build_response(self, request, response_code, answers):
        bytestring = b''

        header = DNSHeader()
        header.id = request.header.id
        header.question_cnt = 1
        header.answer_cnt = len(answers)

        header.query_response = 1
        header.opcode = 1
        header.recursion_desired = 1
        header.recursion_available = 1
        header.response_code = response_code

        header.flags = self._build_header_flags(header)

        bytestring += self._build_header(header) + self._build_question(request.question)

        for rr in answers:
            bytestring += self._build_resource_record(rr)

        return bytestring

    #given a DNSHeader object, return the corresponding bytestring
    def _build_header(self, header):
        bytestring = struct.pack('>HHHHHH', header.id, header.flags, header.question_cnt, header.answer_cnt, header.auth_cnt, header.additional_cnt)
        return bytestring
    
    #given a DNSHeader object, convert the flag values to a 2-byte flag string
    def _build_header_flags(self, header):
        bits = BitArray(length=16)

        bits[0] = header.query_response
        #opcode is typically always 0
        bits[5] = header.auth_answer
        bits[6] = header.truncated
        bits[7] = header.recursion_desired
        bits[8] = header.recursion_available
        #bits 9-12 are reserved, laeave as 0
        #TODO: handle response code 
        return bits.uint
    
    #given a DNSQuestion object, return the corresponding bytestring
    def _build_question(self, question):
        bytestring = self._encode_domain(question.domain)
        bytestring += struct.pack('>HH', question.type, question.classcode)
        return bytestring
    
    #given a ResourceRecord object, return the corresponding bytestring
    def _build_resource_record(self, rr):
        bytestring = self._encode_domain(rr.domain)
        bytestring += struct.pack('>HHIH', rr.type, rr.classcode, rr.ttl, rr.rdlength)
       
        if(rr.type == Type.A.value):
            bytestring += self._encode_ipv4(rr.rdata)
        elif(rr.type == Type.CNAME.value or rr.type == Type.NS.value):
            bytestring += self._encode_domain(rr.rdata)

        return bytestring    
    
    #encode the string represntation of a domain name as bytes
    def _encode_domain(self, domain):
        bytestring = b''
        labels = domain.split('.')
        for l in labels:
            bytestring += len(l).to_bytes(1, 'big') + l.encode()
        return bytestring + b'\x00'
    
    #encode the string represntation of an ipv4 address as bytes
    def _encode_ipv4(self, ipv4):
        bytestring = b''
        values = ipv4.split('.')
        for v in values:
            bytestring += int(v).to_bytes(1, 'big')
        return bytestring
            
            




