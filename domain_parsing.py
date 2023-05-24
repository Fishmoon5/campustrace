import numpy as np, tqdm, os
from constants import *
from helpers import *


class Domain_Parsing():
	def __init__(self, popular_domains = {}):
		known_popular_domains = [
			'cdn.mwbsys.com', # antivirus
		]
		self.popular_domains = popular_domains
		for k in known_popular_domains:
			self.popular_domains[k] = None
		self.dont_map_keywords = []#['googleapi']
		self.keywords = {}
		self.sevice_to_keywords, self.keyword_to_service = {}, {}
		self.valid_priorities = {}
		for row in open(os.path.join(CACHE_DIR, 'domain_keywords.txt'),'r'):
			keyword,serviceid,priority = row.strip().split(',')
			self.keywords[keyword] = int(priority)
			self.valid_priorities[int(priority)] = None
			try:
				self.sevice_to_keywords[serviceid].append(keyword)
			except KeyError:
				self.sevice_to_keywords[serviceid] = [keyword] 
			self.keyword_to_service[keyword] = serviceid
		self.valid_priorities = sorted(list(self.valid_priorities))

	def map_hr_str_to_keyword(self, hr_str):
		# todo -- incorporate priorities
		for dmk in self.dont_map_keywords:
			if dmk in hr_str: return None
		for priority in self.valid_priorities:
			for kw,prio in self.keywords.items():
				if prio != priority: continue
				if kw in hr_str:
					return kw
		return None

	def map_uid_to_service(self, uid):
		domain, sni = uid
		info = {}

		info['ignore'] = False

		try:
			self.popular_domains[domain]
			return {
				'used_field': 'domain',
				'mapped_to_service': False,
				'ignore': True,
			}
		except KeyError:
			pass
		try:
			self.popular_domains[sni]
			return {
				'used_field': 'sni',
				'mapped_to_service': False,
				'ignore': True,
			}
		except KeyError:
			pass

		domain_map = self.map_hr_str_to_keyword(domain)
		sni_map = self.map_hr_str_to_keyword(sni)
		info['mapped_to_service'] = False
		info['used_field'] = None


		if sni_map is not None:
			service = self.keyword_to_service[sni_map]
			info['service'] = service
			info['used_field'] = 'sni'
			info['mapped_to_service'] = True
		elif domain_map is not None:
			service = self.keyword_to_service[domain_map]
			info['service'] = service
			info['used_field'] = 'domain'
			info['mapped_to_service'] = True
			

		return info

	def create_domain_keywords(self):
		### purpose to is to use domains to compare internet usage across buildings
		## not really to definitively map all domains to services

		domain_to_bytes = {}
		for row in open(os.path.join(DATA_DIR, 'topdomains_buildingip_inbytes_outbytes.txt'),'r'):
			domain,building,inb,outb = row.strip().split(',')
			try:
				domain_to_bytes[domain] += int(inb)
			except KeyError:
				domain_to_bytes[domain] = int(inb)
		total_b = sum(list(domain_to_bytes.values()))
		

		dump_list = []
		mapped_bytes, unmapped_bytes = 0,0
		kw_mappings = {}
		for domain,nb in domain_to_bytes.items():
			kw = self.map_domain_to_keyword(domain)
			if kw is None:
				unmapped_bytes += nb
				dump_list.append((domain,nb))
				kw_mappings[domain] = [(domain,nb)]
			else:
				mapped_bytes += nb
				service = self.keyword_to_service[kw]
				try:
					kw_mappings[service].append((domain,nb))
				except KeyError:
					kw_mappings[service] = [(domain,nb)]
		print("{} percent of bytes mapped".format(round(mapped_bytes * 100.0 / total_b)))

		with open(os.path.join(CACHE_DIR, 'services_bytes.txt'),'w') as f:
			for service,domainsvols in sorted(kw_mappings.items(), key = lambda el : -1 * sum([ell[1] for ell in el[1]])):
				this_service_bytes = sum(vol for domain,vol in domainsvols)
				domain_str = ";".join([domain for domain,vol in domainsvols])
				f.write("{},{},{}\n".format(service,this_service_bytes,domain_str))
		with open(os.path.join(CACHE_DIR, 'unmapped_domains.txt'),'w') as f:
			for domain,nb in sorted(dump_list, key = lambda el : -1 * el[1]):
				f.write("{},{},{}\n".format(domain,nb,round(nb*100.0/total_b,3)))
		token_parts = {}
		for domain,nb in dump_list:
			for tpart1 in domain.split(".")[:-1]:
				if "cdn" in tpart1:
					try:
						token_parts[tpart1] += nb
					except KeyError:
						token_parts[tpart1] = nb
					continue
				for tpart2 in tpart1.split("-"):
					if tpart2 == "": continue
					try:
						token_parts[tpart2] += nb
					except KeyError:
						token_parts[tpart2] = nb
		# print(sorted(token_parts.items(), key = lambda el : el[1]))