import struct

from bitstring import BitArray
from dns_message import DNSHeader, DNSQuestion, DNSResourceRecord, DNSMessage

from constants import Type

class MessageParser:  

    def __init__(self):
        self.index = 0 #current byte position of the parser

    #parse a DNS message as bytes and return the corresponding DNSMessage object
    def parse_message(self, bytestring):
        self.index = 0
        message = DNSMessage()

        message.header = self._parse_header(bytestring)
        message.question = self._parse_question(bytestring)

        for _ in range(message.header.answer_cnt):
            message.answers.append(self._parse_resource_record(bytestring))

        for _ in range(message.header.auth_cnt):
            message.auth.append(self._parse_resource_record(bytestring))

        for _ in range(message.header.additional_cnt):
            message.additional.append(self._parse_resource_record(bytestring))

        return message
    
    #parse dns header
    def _parse_header(self, message):
        header = DNSHeader()
        header.id, header.flags, header.question_cnt, header.answer_cnt, header.auth_cnt, header.additional_cnt = struct.unpack('>HHHHHH', message[0:12])
        
        #parse flag bits
        bits = BitArray(header.flags.to_bytes(2, 'big'))
        header.query_response = bits[0]
        header.op_code = bits[1:5]
        header.auth_answer = bits[5]
        header.truncated = bits[6]
        header.recursion_desired = bits[7]
        header.recursion_available = bits[8]
        header.reserved = bits[9:12]
        header.response_code = bits[12:16]

        return header
    
    #parse question record
    def _parse_question(self, message):
        self.index = 12
        question = DNSQuestion()

        question.domain = self._read_domain(self.index, message)

        question.type, question.classcode = struct.unpack('>HH', message[self.index:self.index+4])
        self.index += 4

        return question
    
    #parse resource record
    def _parse_resource_record(self, message):
        rr = DNSResourceRecord()
        rr.domain = self._read_domain(self.index, message)

        rr.type, rr.classcode, rr.ttl, rr.rdlength = struct.unpack('>HHIH', message[self.index:self.index+10])
  
        self.index += 10

        #decode rdata depending on the record type
        if(rr.type == Type.CNAME.value or rr.type == Type.NS.value):
            rr.rdata = self._read_domain(self.index, message)
        elif(rr.type == Type.A.value):
            rr.rdata = self._read_ipv4(self.index, message)
            self.index += rr.rdlength
        else:
            rr.rdata = message[self.index:self.index+rr.rdlength]
            self.index += rr.rdlength

        return rr
    
    #returns the string representation of an ipv4 address from bytes
    def _read_ipv4(self, offset, message):
        return "{}.{}.{}.{}".format(message[offset], message[offset+1], message[offset+2], message[offset+3])
        
    #returns the string representation of an domain from bytes
    def _read_domain(self, offset, message):
        labels = self._read_domain_recursive(offset, message)
        return '.'.join(labels)

    #recursively read the byte represntation of a domain, handling compression labels.
    #returns a list of labels (e.g, domain segments)
    def _read_domain_recursive(self, offset, message):
        domain = []
        label = None

        while label != b'':
            #read length of next label
            length = message[offset] 

            bits = BitArray(message[offset:offset+2])

            #handle compression labels
            if(bits[0:2] == '0b11'):
                bits[0:2] = '0b00'
                ptr = bits.uint
                tmp = self.index
                domain += self._read_domain_recursive(ptr, message)
                self.index = tmp+2
                return domain

            #read label
            else:
                label = message[offset+1:offset+1+length]
                offset += len(label)+1
                self.index = offset 
                if(len(label) > 0):
                    domain.append(label.decode())

        return domain
