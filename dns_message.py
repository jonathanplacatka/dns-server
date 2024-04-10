from constants import Type

#DNS message, consisting of a header, question, and records
class DNSMessage:
    def __init__(self):
        self.header = None
        self.question = None
        self.answers = []
        self.auth = []
        self.additional = []

    def get_records_by_type(self, type, section):
        return [r for r in section if r.type == type]
    
    def get_ns_ip(self, domain):
        return next((r.rdata for r in self.additional if r.type == Type.A.value and r.domain == domain), None)
    
    #print all message components
    def print(self):
        self.header.print()
        self.header.print_flags()
        self.question.print()
        self.print_records()

    #print all resource records
    def print_records(self):
        for r in self.answers + self.auth + self.additional:
            r.print()

    
#DNS message header
class DNSHeader:
    def __init__(self):
        #header fields
        self.id = 0
        self.flags = 0
        self.question_cnt = 0
        self.answer_cnt = 0
        self.auth_cnt = 0
        self.additional_cnt = 0

        #header flags
        self.query_response = 0
        self.op_code = 0
        self.auth_answer = 0
        self.truncated = 0
        self.recursion_desired = 0
        self.recursion_available = 0
        self.reserved = 0
        self.response_code = 0 

    def print(self):
        print("\nHEADER:\n\tidentifier: {}\n\tqcnt: {}\n\tanscnt: {}\n\tauthcnt: {}\n\taddcnt: {}".format(
        self.id, self.question_cnt, self.answer_cnt, self.auth_cnt, self.additional_cnt))

    def print_flags(self):
        print("\nFLAGS:\n\tquery_response: {}\n\top_code: {}\n\tauth_answer: {}\n\ttruncated: {}\n\trecursion_desired: {}\n\trecursion_available: {}\n\treserved: {}\n\tresponse_code: {}".format(
            self.query_response, self.op_code, self.auth_answer, self.truncated, 
            self.recursion_desired, self.recursion_available, self.reserved, self.response_code))

#DNS question record 
class DNSQuestion:
    def __init__(self):
        self.domain = ''
        self.type = None
        self.classcode = 1

    def print(self):
        print("\nQUESTION:\n\tdomain: {}\n\ttype: {}\n\tclasscode: {}".format(
            self.domain, self.type, self.classcode))

#DNS resource record
class DNSResourceRecord:
    def __init__(self):
        self.domain = ''
        self.type = None
        self.classcode = 1
        self.ttl = None
        self.rdlength = None
        self.rdata = None

    def print(self):
        print("\n{} RECORD:\n\tdomain: {}\n\trdata: {}\n\tttl: {}".format(Type(self.type).name, self.domain, self.rdata, self.ttl))


