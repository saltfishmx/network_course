from utils.network import resolve_domain_name

dnsIP, dnsPort = "localhost", 9999

def resolve(domain):
 resp = resolve_domain_name(domain, dnsIP, dnsPort)
 if resp:
   return resp.response_val
 return None

result = resolve("stfw.localhost.computer")
print(result)