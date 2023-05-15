import selenium
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import time, json, os
from helpers import *
from domain_analyzer import Domain_Analyzer

class Service_Mapper():
	def __init__(self):
		self.load_not_done_domains()

	def load_done_sites(self):
		"""Loads domains that have already been fetched via selenium."""
		self.sites_to_sites = {}
		bad_cache = []
		for row in open(os.path.join(CACHE_DIR, 'sites_to_sites.txt'),'r'):
			if row.strip() == "": 
				continue
			try:
				site,sites = row.strip().split('\t')
				sites = sites.split(";")
				not_bad_sites = get_difference(sites,bad_cache)
				self.sites_to_sites[site] = not_bad_sites
				bad_cache = []
			except ValueError:
				site = row.strip()
				bad_cache.append(site)
				bad_cache.append("https://" + site)
				bad_cache.append("https://www." + site)
				self.sites_to_sites[site] = []

		for site in list(self.sites_to_sites):
			self.sites_to_sites[site] = list(set(self.sites_to_sites[site]))
		return self.sites_to_sites

	def load_all_domains(self):
		self.all_domains = {}
		for row in open(os.path.join(DATA_DIR, 'topdomains_buildingip_inbytes_outbytes.txt'),'r'):
			if row.strip() == "": continue
			domain,bip,inb,outb = row.strip().split(",")
			try:
				self.all_domains[domain] += (float(inb) + float(outb))
			except KeyError:
				self.all_domains[domain] = (float(inb) + float(outb))

	def load_not_done_domains(self):
		"""Loads domains seen in campus network traces."""
		already_done_sites = list(self.load_done_sites())
		self.sites = []
		for row in open(os.path.join(DATA_DIR, 'topdomains_buildingip_inbytes_outbytes.txt'),'r'):
			if row.strip() == "": continue
			domain,bip,inb,outb = row.strip().split(",")
			if domain in already_done_sites: continue
			self.sites.append(domain)
		self.sites = self.sites

	def get_fetched_resources(self, site):
		"""Gets all sites that are fetched during a page load to 'site'."""
		try:
			self.driver.get(site)
		except selenium.common.exceptions.WebDriverException as e:
			if "net::ERR_NAME_NOT_RESOLVED" in str(e) or "net::ERR_CONNECTION_RESET" in str(e)\
				or "net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH" in str(e):
				return []
			else:
				print(site)
				print(str(e))
				return []
		## Wait for site to load
		time.sleep(10)
	  
		## Gets all the logs from performance in Chrome
		logs = self.driver.get_log("performance")
	  
		# Iterate the logs
		urls = []
		for log in logs:
			network_log = json.loads(log["message"])["message"]
			try:
				url = network_log["params"]["request"]["url"]
				if "." not in url: continue
				if url.startswith("https://"):
					add_site = "/".join(url.split("/")[0:3])
				else:
					add_site = url.split("/")[0]
				urls.append(add_site)
			except Exception as e:
				pass
		return list(set(urls))

	def get_selenium_driver(self):
		# Enable Performance Logging of Chrome.
		desired_capabilities = DesiredCapabilities.CHROME
		desired_capabilities["goog:loggingPrefs"] = {"performance": "ALL"}
	  
		# Create the webdriver object and pass the arguments
		options = webdriver.ChromeOptions()
	  
		# Chrome will start in Headless mode
		options.add_argument('headless')
	  
		# Ignores any certificate errors if there is any
		options.add_argument("--ignore-certificate-errors")
	  
		# Startup the chrome webdriver with executable path and
		# pass the chrome options and desired capabilities as
		# parameters.
		self.driver = webdriver.Chrome(options=options,
								  desired_capabilities=desired_capabilities)
	def close_resources(self):
		self.driver.quit()

	def compute_domains_to_services(self):
		## for each domain
		## if it's a keyword -> map to service
		## check to see if it's in many web page results, if so, discard
		## check to see if it's in a very small number of web page results, possibly call those their own service
		self.load_all_domains()
		da = Domain_Analyzer()
		
		self.load_done_sites()

		def domain_to_domainstr(s):
			if s.startswith("https://"):
				s = s[len("https://"):]
			s = s.split("/")[0]
			domain_els = s.split(".")
			if len(domain_els) > 3:
				significant_domain_els = domain_els[-3:]
				domain_str = ".".join(significant_domain_els)
			else:
				domain_str = s
			return domain_str

		site_ctr = {}
		subsite_to_supersite = {}
		for site, sites in self.sites_to_sites.items():
			ctd_this_site = {}
			for s in sites:
				domain_str = domain_to_domainstr(s)
				try:
					ctd_this_site[domain_str]
					continue
				except KeyError:
					pass

				try:
					subsite_to_supersite[domain_str].append(site)
				except KeyError:
					subsite_to_supersite[domain_str] = [site]
				try:
					site_ctr[domain_str] += 1
				except KeyError:
					site_ctr[domain_str] = 1
				ctd_this_site[domain_str] = None
		self.popular_domains, self.unpopular_domains = {}, {}
		for s, n in site_ctr.items():
			if n < 3:
				self.unpopular_domains[s] = None
			elif n > 20:
				self.popular_domains[s] = None
		print(self.popular_domains)

		unmappable_domains = []
		known_services = {}
		mapped_bytes, total_b = 0,0
		for domain, bts in self.all_domains.items():
			kw = da.map_domain_to_keyword(domain)
			if kw is None:
				try:
					self.popular_domains[domain_to_domainstr(domain)]
					continue
				except KeyError:
					total_b += bts
					try:
						raise KeyError
						self.unpopular_domains[domain_to_domainstr(domain)]
						# service = domain
					except KeyError:
						unmappable_domains.append(domain)
						continue
			else:
				mapped_bytes += bts
				total_b += bts
				service = da.keyword_to_service[kw]
			try:
				known_services[service].append(domain)
			except KeyError:
				known_services[service] = [domain]
		with open(os.path.join(CACHE_DIR, 'computed_domain_to_service.txt'),'w') as f:
			for service,domains in known_services.items():
				domains_str = ";".join(domains)
				f.write("{}\t{}\n".format(service,domains_str))
		with open(os.path.join(CACHE_DIR, 'unmapped_domains_new.txt'),'w') as f:
			for domain in unmappable_domains:
				f.write("{}\n".format(domain))
		heaviest_hitters = sorted(unmappable_domains, key = lambda el : -1 * self.all_domains[el])
		for heavy_hitter in heaviest_hitters[0:100]:
			domain_str = domain_to_domainstr(heavy_hitter)
			print("{} {}".format(domain_str, subsite_to_supersite.get(domain_str, [])))

		print("{} percent of bytes mapped".format(round(mapped_bytes * 100.0 / total_b)))


	def fetch_domains(self):
		try:
			self.get_selenium_driver()
			for site in self.sites:
				with open(os.path.join(CACHE_DIR, 'sites_to_sites.txt'),'a') as f:
					if "www" not in site:
						site_to_fetch = "https://www." + site
					else:
						site_to_fetch = "https://" + site
					fetched_resources = self.get_fetched_resources(site_to_fetch)
					if len(fetched_resources) > 0:
						fetched_resources_str = ";".join(fetched_resources)
						f.write("{}\t{}\n".format(site, fetched_resources_str))
					else:
						f.write("{}\t\n".format(site))
		except:
			import traceback
			traceback.print_exc()
		finally:
			try:
				self.close_resources()
			except:
				pass

if __name__ == "__main__":
	sm = Service_Mapper()
	sm.fetch_domains()
	# sm.compute_domains_to_services()




