import selenium, tqdm, copy
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import time, json, os
from helpers import *
from domain_parsing import Domain_Parsing, Cluster_Domain_Parser
from traceroute_analyzer import Campus_Measurement_Analyzer

INCLUDE_UNKNOWN = False

class Service_Mapper(Campus_Measurement_Analyzer):
	def __init__(self):
		super().__init__()
		self.load_not_done_domains()
		self.service_to_service_type = {}
		for row in open(os.path.join(CACHE_DIR, 'service_to_servicetype.csv'),'r'):
			service,servicetype = row.strip().split(',')
			self.service_to_service_type[service] = servicetype
		self.domain_to_service_cache_fn = os.path.join(CACHE_DIR, 'domain_sni_to_service_cache.pkl')

		self.cma = Campus_Measurement_Analyzer()
		self.cma.check_load_ip_to_asn()

	def load_done_sites(self):
		"""Loads domains that have already been fetched via selenium."""
		self.sites_to_sites = {}
		bad_cache = []
		n_check_against = 200
		prev_100 = {i:None for i in range(n_check_against)}
		rowi=0
		for row in open(os.path.join(CACHE_DIR, 'sites_to_sites.txt'),'r'):
			if row.strip() == "": 
				continue
			try:
				site,sites = row.strip().split('\t')
				sites = sites.split(";")
				not_bad_sites = get_difference(sites,bad_cache)
				not_bad_sites = get_difference(not_bad_sites, list(prev_100.values()))
				self.sites_to_sites[site] = not_bad_sites
				bad_cache = []
			except ValueError:
				site = row.strip()
				bad_cache.append(site)
				bad_cache.append("https://" + site)
				bad_cache.append("https://www." + site)
				self.sites_to_sites[site] = []

			rowi += 1
			prev_100[rowi % n_check_against] = "https://" + site
			rowi += 1
			prev_100[rowi % n_check_against] = "https://www." + site


		for site in list(self.sites_to_sites):
			self.sites_to_sites[site] = list(set(self.sites_to_sites[site]))
			for i,s in enumerate(self.sites_to_sites[site]):
				self.sites_to_sites[site][i] = domain_to_domainstr(s)

		return self.sites_to_sites

	def classify_traffic_types_high_level_small(self):
		data = {}
		for row in open(os.path.join(DATA_DIR, 'protocol_port_nbytes_nflows.csv'),'r'):
			flowuid,istcp,port,nflows,nbytes = row.strip().split(',')
			if flowuid == "":continue
			istcp = int(istcp)
			data[istcp,port] = float(nbytes)
		total_volume = sum(list(data.values()))
		cum_pct = 0
			
		uid_to_high_level = ['web (TLS)', 'web (QUIC)', 'web (HTTP)', 'communication',
				'communication','VPN','filesharing','communication','?',
				'gaming','communication','email','?','?','VPN','?','?','?','gaming','?',
				'communication','management','gaming','management','communication','http','VPN',
				'gaming']


		high_level_to_pct = {hl:0 for hl in uid_to_high_level}
		i=0

		for (istcp,port),nb in sorted(data.items(), key = lambda el : -1 * el[1])[0:100]:
			protocol = 'tcp' if istcp else 'udp'

			pct = round(nb*100.0/total_volume,2)
			cum_pct += pct
			# print("{}:{}, {} pct. of traffic, {} cum".format(protocol,port,
			# 	pct,cum_pct))

			try:
				high_level_to_pct[uid_to_high_level[i]] += pct
				print("{} -- {} is {}".format(protocol,port,uid_to_high_level[i]))				
			except IndexError:
				high_level_to_pct['?'] += pct
			i += 1

		import pprint
		pprint.pprint(high_level_to_pct)

	def classify_traffic_types_high_level(self):
		## get port breakdown, http, https, etc..

		cache_fn = os.path.join(CACHE_DIR, 'high_level_traffic_classification.pkl')

		if not os.path.exists(cache_fn):
			np.random.seed(31415)
			self.get_service_bytes_by_separator()


			### things to look for
			## domain y/n, sni y/n
			## port breakdown
			## tcp udp

			traffic_classes = {}
			for row in tqdm.tqdm(open(os.path.join(DATA_DIR, 'per_flow_data_april.csv'),'r'),
				desc="Loading April flow data"):
				flowuid,tstart,tend,unit,dstip,nb,dns,_,sni,port,EyeballVote,HighPort,DstNoDNS = row.strip().split(",")
				if flowuid == "": continue
				### Todo -- add protocol info
				uid = (domain_to_domainstr(dns),domain_to_domainstr(sni), dstip, port, None)


				no_domain_indicator = (uid[0] == "")
				no_sni_indicator =  ( uid[1] == "")
				no_domainsni_indicator =  (uid[0] == "" and uid[1] == "")

				service = self.map_to_service(uid)
				service_mapped_indicator = (service is not None)

				overall_indicator = (port,protocol,no_domain_indicator,no_sni_indicator,no_domain_sni_indicator,
					service_mapped_indicator)

				try:
					traffic_classes[overall_indicator] += nb
				except KeyError:
					traffic_classes[overall_indicator] = nb


			pickle.dump({
				'traffic_classes': traffic_classes,
			 }, open(cache_fn, 'wb'))
		else:
			traffic_classes = pickle.load(open(cache_fn,'rb'))

	def load_all_domain_sni_uids(self, **kwargs):
		try:
			self.domain_sni_uids
			if not kwargs.get('force_load', False):
				return
		except AttributeError:
			pass
		self.domain_sni_uids = {}
		self.domain_sni_uids_by_building_bytes = {}
		self.domain_sni_uids_by_building_flows = {}
		self.domain_sni_uids_by_building_time = {}
		self.domain_sni_uids_by_hour_bytes = {}
		self.dstip_to_flow_time = {}
		self.dstip_to_domain_sni = {}
		# n_every_delete = int(10e6)
		# p_delete = 1 - 1 / float(n_every_delete)
		# pct_delete = .1
		# n_delete = int(pct_delete * n_every_delete / 100)
		# print("Deleting UIDs with less than {} entries every {}M iters".format(n_delete, round(n_every_delete/1e6,1)))
		fns = kwargs.get('months_of_interest', ['2024-01'])
		for fn in fns:
			with open(os.path.join(DATA_DIR, 
				'flow_info', "{}.tsv".format(fn)),'r') as f:
				csvr = csv.reader(f, delimiter='\t', quotechar='"')
				for row in tqdm.tqdm(csvr, desc="Loading flow info in {}...".format(fn)):
					i,frame_time,frame_time_end,unit_ip,building,ip,isTCP,nb,dns_name,dns_name_orig,sni,port = row
					if i == "": continue
					domain = domain_to_domainstr(dns_name)
					sni = domain_to_domainstr(sni)
					protocol = 'tcp' if isTCP == 'True' else 'udp'
					dst_as = self.cma.parse_asn(ip)

					if port == '':
						port = None
						protocol = None
					uid = (domain,sni,dst_as,port,protocol)
					try:
						self.domain_sni_uids[uid] += float(nb)
					except KeyError:
						self.domain_sni_uids[uid] = float(nb)
					try:
						self.domain_sni_uids_by_building_bytes[building]
					except KeyError:
						self.domain_sni_uids_by_building_bytes[building] = {}
						self.domain_sni_uids_by_building_flows[building] = {}
						self.domain_sni_uids_by_building_time[building] = {}
					try:
						self.domain_sni_uids_by_building_bytes[building][uid] += float(nb)
						self.domain_sni_uids_by_building_flows[building][uid] += 1
						self.domain_sni_uids_by_building_time[building][uid] += (float(frame_time_end) - float(frame_time))
					except KeyError:
						self.domain_sni_uids_by_building_bytes[building][uid] = float(nb)
						self.domain_sni_uids_by_building_flows[building][uid] = 1
						self.domain_sni_uids_by_building_time[building][uid] = (float(frame_time_end) - float(frame_time))
					
					hour = int(float(frame_time_end)) // 60 
					try:
						self.domain_sni_uids_by_hour_bytes[hour]
					except KeyError:
						self.domain_sni_uids_by_hour_bytes[hour] = {}
					try:
						self.domain_sni_uids_by_hour_bytes[hour][uid] += float(nb)
					except KeyError:
						self.domain_sni_uids_by_hour_bytes[hour][uid] = float(nb)
					try:
						self.dstip_to_domain_sni[ip]
					except KeyError:
						self.dstip_to_domain_sni[ip] = {}
					try:
						self.dstip_to_domain_sni[ip][uid] += float(nb)
					except KeyError:
						self.dstip_to_domain_sni[ip][uid] = float(nb)

					try:
						self.dstip_to_flow_time[ip] += (float(frame_time_end) - float(frame_time))
					except KeyError:
						self.dstip_to_flow_time[ip] = (float(frame_time_end) - float(frame_time))
		### For Shuyue to analyze
		pickle.dump(self.dstip_to_flow_time, open(os.path.join(CACHE_DIR, 'exports', 'dstip_to_flow_time.pkl'),'wb'))

	def load_not_done_domains(self):
		"""Loads domains seen in campus network traces."""
		self.sites = []
		return
		#### UNUSED
		already_done_sites = {s:None for s in self.load_done_sites()}
		self.sites = []
		for row in open(os.path.join(DATA_DIR, 'topdomains_buildingip_inbytes_outbytes.txt'),'r'):
			if row.strip() == "": continue
			domain,bip,inb,outb = row.strip().split(",")
			try:
				already_done_sites[domain]
				continue
			except KeyError:
				pass
			self.sites.append(domain)
		self.sites = self.sites

	def get_fetched_resources(self, site):
		"""Gets all sites that are fetched during a page load to 'site'."""
		try:
			self.driver.get(site)
		except selenium.common.exceptions.WebDriverException as e:
			if "net::ERR_NAME_NOT_RESOLVED" in str(e) or "net::ERR_CONNECTION_RESET" in str(e)\
				or "net::ERR_SSL_VERSION_OR_CIPHER_MISMATCH" in str(e):
				self.driver.get_log("performance")
				self.driver.get_log("browser")
				return []
			else:
				print(site)
				print(str(e))
				self.driver.get_log("performance")
				self.driver.get_log("browser")
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
		## Clear
		self.driver.get_log("performance")
		self.driver.get_log("browser")

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

	def get_service_activity_measure_dists(self, **kwargs):
		## Get volume data
		by_measure_cache_fn = os.path.join(CACHE_DIR, 'by_activity_measure_cache.pkl')
		if not os.path.exists(by_measure_cache_fn):
			self.get_service_bytes_by_separator()
			by_measure = {
				'dns_responses': {},
				'bytes': {},
				'flows': {},
				'time': {},
			}
			for arr,activity_type in zip([self.domain_sni_uids_by_building_bytes,
				self.domain_sni_uids_by_building_flows,
				self.domain_sni_uids_by_building_time], ['bytes', 'flows', 'time']):
				for building in arr:
					for uid,n in arr[building].items():
						service = self.domain_sni_to_service.get(uid)
						if service is None: continue
						try:
							by_measure[activity_type][service] += n
						except KeyError:
							by_measure[activity_type][service] = n
			da = Domain_Parsing(popular_domains = self.popular_domains)
			with open(os.path.join(DATA_DIR, '2024-01-dns-activity.tsv'),'r') as f:
				csvr = csv.reader(f, delimiter='\t', quotechar='"')
				for row in tqdm.tqdm(csvr, desc="Loading dns response counts..."):
					try:
						flow_uid,building,domain,n = row
					except ValueError:
						continue
					if flow_uid == "": continue
					if domain == "": continue
					uid = (domain, "", None, None, None)
					info = self.map_to_service(uid)
					if info['ignore']: continue
					if info['mapped_to_service']:
						service = info['service']
					else:
						service = uid
					try:
						by_measure['dns_responses'][service] += float(n)
					except KeyError:
						by_measure['dns_responses'][service] = float(n)

			pickle.dump(by_measure, open(by_measure_cache_fn,'wb'))
		else:
			by_measure = pickle.load(open(by_measure_cache_fn, 'rb'))

		if kwargs.get('service_or_type', 'service') == 'type':
			### Convert services to service types
			by_service_type = {}
			for k in by_measure:
				by_service_type[k] = {}
				for service,nb in by_measure[k].items():
					service_type = self.service_to_service_type.get(service,'unknown')
					if service_type == 'unknown' and not INCLUDE_UNKNOWN: continue
					try:
						by_service_type[k][service_type] += nb
					except KeyError:
						by_service_type[k][service_type] = nb
			del by_measure
			by_measure = by_service_type

		return by_measure

	def get_service_bytes_by_separator(self, **kwargs):
		self.compute_domains_to_services(**kwargs)

		if kwargs.get('by','building') == 'building':
			self.domain_sni_uids_by_separator = self.domain_sni_uids_by_building_bytes
		elif kwargs.get('by','building') == 'hour':
			self.domain_sni_uids_by_separator = self.domain_sni_uids_by_hour_bytes
		service_bytes_by_separator = {separator: {} for separator in self.domain_sni_uids_by_separator}
		print("converting sni uid to by service")
		for separator in self.domain_sni_uids_by_separator:
			for uid,nb in self.domain_sni_uids_by_separator[separator].items():
				service = self.domain_sni_to_service.get(uid)
				if service is None: continue
				try:
					service_bytes_by_separator[separator][service] += nb
				except KeyError:
					service_bytes_by_separator[separator][service] = nb

		if kwargs.get('service_or_type', 'service') == 'type':
			### Convert services to service types
			by_service_type = {}
			for k in service_bytes_by_separator:
				by_service_type[k] = {}
				for service,nb in service_bytes_by_separator[k].items():
					service_type = self.service_to_service_type.get(service,'unknown')
					if service_type == 'unknown' and not INCLUDE_UNKNOWN: continue
					try:
						by_service_type[k][service_type] += nb
					except KeyError:
						by_service_type[k][service_type] = nb
			del service_bytes_by_separator
			service_bytes_by_separator = by_service_type

		return service_bytes_by_separator

	def investigate_service_mapping(self):
		### Look at high volume apple domains
		self.compute_domains_to_services(by='building')
		self.load_all_domain_sni_uids(by='building')

		apple_services = ['icloud', 'appletv', 'applemusic']
		apple_uids = list(set([uid for uid,service in self.domain_sni_to_service.items() 
			if service in apple_services or 'apple' in uid[0] or 'apple' in uid[1]]))

		sorted_apple_uids = sorted(apple_uids, key = lambda el : -1 * self.domain_sni_uids[el])
		total_v = sum(self.domain_sni_uids[uid] for uid in apple_uids)
		for important_apple_uid in sorted_apple_uids[0:100]:
			print("{} -- {} pct.".format(important_apple_uid, round(self.domain_sni_uids[important_apple_uid] * 100 / total_v, 2)))

	def map_to_service(self, uid, **kwargs):
		try:
			self.domain_analyzer
		except AttributeError:
			computation_method = kwargs.get('computation_method', 'sigcomm2024')
			if computation_method == 'imc2023':
				self.domain_analyzer = Domain_Parsing(popular_domains = self.popular_domains)
			elif computation_method == 'sigcomm2024':
				self.domain_analyzer = Cluster_Domain_Parser(popular_domains = self.popular_domains)
			else:
				raise ValueError("Domain to service computation method {} not implemented".format(computation_method))
		

		return self.domain_analyzer.map_uid_to_service(uid)


	def summarize_unmappable_domains(self):
		### print out ports, dst ASes, protocols responsible for unmappable, no-domain traffic
		by_asn = {}
		for (domain,sni,asn,port,protocol), nb in self.unmapped_domains.items():
			if port in ['443','80','8080']: continue
			if asn is None:
				asn = "???"
			try:
				by_asn[domain,sni,asn,port,protocol] += nb
			except KeyError:
				by_asn[domain,sni,asn,port,protocol] = nb


		sorted_unmappable = sorted(by_asn.items(), key = lambda el : -1 * el[1])
		all_v = sum(list(by_asn.values()))

		for uid,bts in sorted_unmappable[0:200]:
			print("{} -- {} pct.".format(uid, round(bts*100.0/all_v,2)))
		# exit(0)

	def compute_domains_to_services(self, **kwargs):
		### calls loading of all flow information
		### for each UID, tries to map UID to service using lower-level domain_parsing
		### summarizes mapping statistics
		### outputs cached objects for quick analysis further down the pipeline

		cache_fn = kwargs.get('save_cache_fn', self.domain_to_service_cache_fn)

		if not os.path.exists(cache_fn):
			self.load_all_domain_sni_uids(**kwargs)
			self.load_done_sites()
			site_ctr = {}
			subsite_to_supersite = {}
			for site, sites in self.sites_to_sites.items():
				ctd_this_site = {}
				for s in sites:
					s = domain_to_domainstr(s)
					try:
						ctd_this_site[s]
						continue
					except KeyError:
						pass

					try:
						subsite_to_supersite[s].append(site)
					except KeyError:
						subsite_to_supersite[s] = [site]
					try:
						site_ctr[s] += 1
					except KeyError:
						site_ctr[s] = 1
					ctd_this_site[s] = None

			self.popular_domains, self.unpopular_domains = {}, {}
			for s, n in site_ctr.items():
				s = domain_to_domainstr(s)
				if n < 3:
					self.unpopular_domains[s] = None
				elif n > 100:
					self.popular_domains[s] = None
			# print("\n\nPOPULAR DOMAINS---")
			# print(self.popular_domains)

			unmappable_domains = []
			known_services = {}
			service_to_nb = {}
			mapped_bytes, total_b = 0,0
			bts_ignore,overall_total_b = 0,0
			bts_by_used_field = {}
			service_to_bytes = {}
			self.domain_sni_to_service,self.unmapped_domains = {},{}
			for uid, bts in tqdm.tqdm(self.domain_sni_uids.items(), desc="Mapping all domains to services."):
				overall_total_b += bts
				info = self.map_to_service(uid)
				if info['ignore']: 
					bts_ignore += bts
					continue
				total_b += bts
				if info['mapped_to_service']:
					service = info['service']
					self.domain_sni_to_service[uid] = service
					indicator = info['indicator']
					try:
						bts_by_used_field[info['used_field']] += bts 
					except KeyError:
						bts_by_used_field[info['used_field']] = bts
					try:
						service_to_nb[service] += bts
					except KeyError:
						service_to_nb[service] = bts
					try:
						known_services[service].append(indicator)
					except KeyError:
						known_services[service] = [indicator]
					mapped_bytes += bts
					try:
						service_to_bytes[service] += bts
					except KeyError:
						service_to_bytes[service] = bts

				else:
					try:
						self.unmapped_domains[uid] += bts
					except KeyError:
						self.unmapped_domains[uid] = bts
					unmappable_domains.append(uid)
					if uid[0] != "" or uid[1] != "":
						service = (uid[0],uid[1])
					else:
						service = uid
					self.domain_sni_to_service[uid] = service
					try:
						service_to_bytes[service] += bts
					except KeyError:
						service_to_bytes[service] = bts
			self.summarize_unmappable_domains()
			print("popular services are {} pct of bytes".format(round(100*bts_ignore/overall_total_b,2)))
			with open(os.path.join(CACHE_DIR, 'computed_domain_to_service.txt'),'w') as f:
				for service in sorted(known_services, key = lambda el : -1 * service_to_nb[el]):
					domains = known_services[service]
					domains_str = ";".join([";;".join([str(ell) for ell in el]) for el in domains])
					f.write("{}\t{}\n".format(service,domains_str))
			with open(os.path.join(CACHE_DIR, 'unmapped_domains_new.txt'),'w') as f:
				for domain in unmappable_domains:
					f.write("{}\n".format(domain))
			self.sorted_unmappable_domains = sorted(unmappable_domains, key = lambda el : -1 * self.domain_sni_uids[el])
			# print("\n\nHEAVY HITTERS")
			# for heavy_hitter in self.sorted_unmappable_domains[0:100]:
			# 	domain_str = heavy_hitter[0]
			# 	print("{} {}".format(heavy_hitter, subsite_to_supersite.get(domain_str, [])))

			print("{} percent of bytes mapped".format(round(mapped_bytes * 100.0 / total_b)))
			print("Of those mapped bytes, here's how they were mapped")
			for k,v in bts_by_used_field.items():
				print("{} -- {} pct".format(k, round(100*v/total_b,2)))


			# sorted_doms = sorted(list([self.domain_sni_uids[uid] for uid in unmappable_domains]),key = lambda el : -1 * el)
			# cumsum = 1-np.cumsum(sorted_doms) / sum(sorted_doms)

			# import matplotlib.pyplot as plt
			# plt.semilogx(np.arange(len(cumsum)), cumsum)
			# plt.xlabel("Number of Unmappable Domains")
			# plt.ylabel("CDF of Traffic")
			# plt.grid(True)
			# plt.savefig("figures/unmappable_domain_volume_contribution.pdf")
			# plt.clf(); plt.close()


			#### Remove domains/services that contribute almost no volume
			print("{} services before pruning".format(len(set(self.domain_sni_to_service.values()))))
			sorted_services = sorted(list(set(self.domain_sni_to_service.values())), key = lambda el : -1 * service_to_bytes.get(el,0))
			services_vol = np.array([service_to_bytes.get(el,0) for el in sorted_services]) / np.sum(list(service_to_bytes.values()))
			cs_services_vol = np.cumsum(services_vol)
			keep_up_to = np.where(cs_services_vol > .999)[0][0]
			keep_services = {s:None for s in sorted_services[0:keep_up_to]}
			new_sts = {}
			for uid,ser in self.domain_sni_to_service.items():
				try:
					keep_services[ser]
					new_sts[uid] = ser
				except KeyError:
					pass
			self.domain_sni_to_service = new_sts
			new_arr_bts, new_arr_f, new_arr_tm = {}, {}, {}
			for building in self.domain_sni_uids_by_building_bytes:
				new_arr_bts[building] = {}
				new_arr_f[building] = {}
				new_arr_tm[building] = {}
				for uid in self.domain_sni_uids_by_building_bytes[building]:
					try:
						self.domain_sni_to_service[uid]
						new_arr_bts[building][uid] = self.domain_sni_uids_by_building_bytes[building][uid]
						new_arr_f[building][uid] = self.domain_sni_uids_by_building_flows[building][uid]
						new_arr_tm[building][uid] = self.domain_sni_uids_by_building_time[building][uid]
					except KeyError:
						pass
			self.domain_sni_uids_by_building_bytes = new_arr_bts
			self.domain_sni_uids_by_building_flows = new_arr_f
			self.domain_sni_uids_by_building_time = new_arr_tm
			new_arr_bts = {}
			for hour in self.domain_sni_uids_by_hour_bytes:
				new_arr_bts[hour] = {}
				for uid in self.domain_sni_uids_by_hour_bytes[hour]:
					try:
						self.domain_sni_to_service[uid]
						new_arr_bts[hour][uid] = self.domain_sni_uids_by_hour_bytes[hour][uid]
					except KeyError:
						pass
			self.domain_sni_uids_by_hour_bytes = new_arr_bts
			
			print("{} services after pruning".format(len(set(self.domain_sni_to_service.values()))))


			if kwargs.get('by','building') == 'building':
				pickle.dump({
					'popular_domains': self.popular_domains,
					'domain_sni_to_service': self.domain_sni_to_service,
					'dstip_to_domain_sni': self.dstip_to_domain_sni,
					'sorted_unmappable_domains': self.sorted_unmappable_domains,
					'domain_sni_uids_by_building_bytes': self.domain_sni_uids_by_building_bytes,
					'domain_sni_uids_by_building_flows': self.domain_sni_uids_by_building_flows,
					'domain_sni_uids_by_building_time': self.domain_sni_uids_by_building_time,
					'domain_sni_uids_by_hour_bytes': self.domain_sni_uids_by_hour_bytes,
				}, open(cache_fn,'wb'))
		else:
			print("Loading domain sni from cache")
			cache = pickle.load(open(cache_fn, 'rb'))
			self.popular_domains = cache['popular_domains']
			self.domain_sni_to_service = cache['domain_sni_to_service']
			self.dstip_to_domain_sni = cache['dstip_to_domain_sni']
			self.sorted_unmappable_domains = cache['sorted_unmappable_domains']
			self.domain_sni_uids_by_building_bytes = cache['domain_sni_uids_by_building_bytes']
			self.domain_sni_uids_by_building_flows = cache['domain_sni_uids_by_building_flows']
			self.domain_sni_uids_by_building_time = cache['domain_sni_uids_by_building_time']
			self.domain_sni_uids_by_hour_bytes = cache['domain_sni_uids_by_hour_bytes']

	def look_at_akamai(self):
		asns_of_interest = {k:{} for k in [None, '2906','3630', '3754', '3756', '3629', '20940']}
		# total_bts, interesting_bts = 0,0
		# for row in tqdm.tqdm(open(os.path.join(DATA_DIR, 'flow_info', '2024-01.tsv')),
		# 	desc="Parsing flow data..."):
		# 	fields = row.strip().split('\t')
		# 	if fields[0] == 'frame_time': continue
		# 	dst_ip = fields[5]
		# 	dst_as = self.cma.parse_asn(dst_ip)
		# 	bts = float(fields[7])
		# 	total_bts += bts
		# 	try:
		# 		asns_of_interest[dst_as]
		# 	except KeyError:
		# 		continue
		# 	try:
		# 		asns_of_interest[dst_as][dst_ip] += bts
		# 	except KeyError:
		# 		asns_of_interest[dst_as][dst_ip] = bts
		# 	interesting_bts += bts
		# 	if np.random.random() > .999999:break
		# pickle.dump([total_bts, interesting_bts,asns_of_interest], open('tmp.pkl','wb'))
		# for dst_as in asns_of_interest:
		# 	print("DST AS : {}".format(dst_as))
		# 	for ip,bts in sorted(asns_of_interest[dst_as].items(), key = lambda el : -1 * el[1])[0:100]:
		# 		print("{} -- ({} pct total, {} pct interesting)".format(ip,
		# 			round(bts*100/total_bts,4), round(bts*100/interesting_bts,2)))
		total_bts,interesting_bts,asns_of_interest = pickle.load(open('tmp.pkl','rb'))
		print(round(sum(list(asns_of_interest['2906'].values())) * 100 / interesting_bts, 2))
		print("Akamai has {} IPs, {} pct. of interesting volume".format(len(asns_of_interest['20940']),
			round(sum(list(asns_of_interest['20940'].values())) * 100 / interesting_bts, 2)))
		print(asns_of_interest['2906'])

	
	def output_service_data_for_shuyue(self):

		## First, parse everything for shuyues time of interest
		# (add dec/22 - may/23 when they're available)
		import glob
		# months_of_interest = ['2022-12', '2023-01','2023-02',
		# 	'2023-03','2023-04', '2023-05', '2023-06', '2023-07', 
		# 	'2023-11', '2023-12', '2024-01']
		months_of_interest = ['2024-01']
		all_cache_fns = glob.glob(os.path.join(CACHE_DIR, 'domain_sni_to_service_cache_shuyue_all_months-*.pkl'))
		months_of_interest = [m for m in months_of_interest if not any(m in fn for fn in all_cache_fns)]
		n_per_iter = 1
		n_chunks = int(np.ceil(len(months_of_interest) / n_per_iter))
		month_chunks = split_seq(sorted(months_of_interest), n_chunks)
		out_fn = os.path.join(CACHE_DIR,'exports','domain_to_service_data_for_shuyue.csv')
		if not os.path.exists(out_fn):
			with open(out_fn, 'w') as f:
				f.write("domain,sni,dst_as,port,protocol,service,servicetype\n")
		for month_chunk in month_chunks:
			month_chunk = sorted(month_chunk)
			kwargs = {}
			kwargs['force_load'] = True
			kwargs['months_of_interest'] = month_chunk
			months_str = "&".join(month_chunk)
			print("Parsing months : {}".format(month_chunk))
			save_cache_fn = os.path.join(CACHE_DIR, 'domain_sni_to_service_cache_shuyue_all_months-{}.pkl'.format(months_str))
			kwargs['save_cache_fn'] = save_cache_fn
			self.compute_domains_to_services(**kwargs)

			cache = pickle.load(open(save_cache_fn, 'rb'))

			self.domain_sni_to_service = cache['domain_sni_to_service']
			known_services = {s:None for s in self.service_to_service_type}

			
			with open(out_fn,'a') as f:
				for uid,service in self.domain_sni_to_service.items():
					domain,sni,dst_as,port,protocol = uid
					try:
						known_services[service]
					except KeyError:
						service = "unknown"
					service_type = self.service_to_service_type.get(service,"unknown")
					f.write("{},{},{},{},{},{},{}\n".format(domain,sni,dst_as,port,protocol,
						service,service_type))

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
	# sm.output_service_data_for_shuyue()
	sm.look_at_akamai()
	# sm.classify_traffic_types_high_level_small()
	# sm.investigate_service_mapping()
	# sm.classify_traffic_types_high_level_small()
	# sm.fetch_domains()
	# sm.compute_domains_to_services()
	# sm.correlate_over_time()
	# sm.identify_services_from_correlation()




