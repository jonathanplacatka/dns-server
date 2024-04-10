import time

#a simple cache for storing DNS resource records
class DNSCache:
    def __init__(self):
        self.cache = {}

    #add item to the cache with expiry time
    def set(self, domain, answers, ttl):
        expiry = time.time() + ttl
        self.cache[domain] = (answers, expiry)

    def get(self, domain):
        if domain in self.cache:
            answers, expiry = self.cache[domain]
            if time.time() <= expiry:
                return answers
            else:
                del self.cache[domain]
        return None  

