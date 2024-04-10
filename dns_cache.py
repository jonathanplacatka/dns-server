import time

class DNSCache:
    def __init__(self):
        self.cache = {}

    def set(self, domain, answers, ttl):
        print("CACHE SIZE {}".format(len(self.cache)))
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

