from enum import Enum

class Type(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28

class RCode(Enum):
    SUCCESS = 0
    NOT_FOUND = 3
    NOT_IMPLEMENTED = 4

    
