from constants import *
from helpers import *

services = {}
for row in open(os.path.join(CACHE_DIR, 'domain_keywords.txt'),'r'):
	domain,service,_ = row.strip().split(',')
	services[service] = None

other_services = {}
for row in open(os.path.join(CACHE_DIR, 'service_to_servicetype.csv'),'r'):
	service,servicetype = row.strip().split(',')
	other_services[service] = None

print(get_difference(other_services,services))
print(get_difference(services,other_services))