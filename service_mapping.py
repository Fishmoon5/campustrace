import selenium, tqdm, copy
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import time, json, os
from helpers import *
from domain_parsing import Domain_Parsing
from traceroute_analyzer import Campus_Measurement_Analyzer

class Service_Mapper(Campus_Measurement_Analyzer):
	def __init__(self):
		super().__init__()
		self.load_not_done_domains()

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

	def identify_services_from_correlation(self):
		cache_fn = os.path.join(CACHE_DIR, 
				'relevant_service_ctrs.pkl')
		service_ctrs = pickle.load(open(cache_fn, 'rb'))

		self.get_service_bytes_by_separator()

		for service in service_ctrs:
			print("\n")
			print(service)
			i=0
			for related_service,vals in sorted(service_ctrs[service].items(), key = lambda el : -1 * el[1]['frac_flow']):
				if vals['n_flow_total'] < 100: continue
				print("{} -- {}".format(related_service,vals))

				i += 1
				if i >= 10:
					break
			if np.random.random() > .9:break
		print(len(service_ctrs))

	def classify_traffic_types_high_level_small(self):
		data = {}
		for row in open(os.path.join(DATA_DIR, 'protocol_port_nbytes_nflows.csv'),'r'):
			flowuid,istcp,port,nflows,nbytes = row.strip().split(',')
			if flowuid == "":continue
			istcp = int(istcp)
			data[istcp,port] = float(nbytes)
		total_volume = sum(list(data.values()))
		cum_pct = 0
			
		uid_to_high_level = ['tls','quic','http','communication','vpn','filesharing',
		'communication','?','gaming','communication','email','vpn','http','http',
		'?','vpn','vpn','communication','?','gaming','?','communication','management',
		'gaming','management','?','communication','vpn','gaming']

		high_level_to_pct = {hl:0 for hl in uid_to_high_level}
		i=0
		for (istcp,port),nb in sorted(data.items(), key = lambda el : -1 * el[1])[0:100]:
			protocol = 'tcp' if istcp else 'udp'

			pct = round(nb*100.0/total_volume,2)
			cum_pct += pct
			print("{}:{}, {} pct. of traffic, {} cum".format(protocol,port,
				pct,cum_pct))

			try:
				high_level_to_pct[uid_to_high_level[i]] += pct
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
				uid = (domain_to_domainstr(dns),domain_to_domainstr(sni))


				no_domain_indicator = (uid[0] == "")
				no_sni_indicator =  ( uid[1] == "")
				no_domainsni_indicator =  (uid[0] == "" and uid[1] == "")

				service = self.domain_sni_to_service.get(uid)
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

	def map_destinations_to_services(self):
		np.random.seed(31415)
		self.get_service_bytes_by_separator()

		dst_to_services_nb = {}
		service_to_dst_nb = {}
		service_to_time = {}

		for row in tqdm.tqdm(open(os.path.join(DATA_DIR, 'per_flow_data_april.csv'),'r'),
			desc="Loading April flow data"):
			flowuid,tstart,tend,unit,dstip,nb,dns,_,sni,port,EyeballVote,HighPort,DstNoDNS = row.strip().split(",")
			if flowuid == "": continue
			uid = (domain_to_domainstr(dns),domain_to_domainstr(sni))

			if uid[0] == "" and uid[1] == "": continue

			service = self.domain_sni_to_service.get(uid)
			if service is None:
				continue

			try:
				dst_to_services_nb[dstip][service] = float(nb)
			except KeyError:
				dst_to_services_nb[dstip] = {service: float(nb)}
			try:
				service_to_dst_nb[service][dstip] = float(nb)
			except KeyError:
				service_to_dst_nb[service] = {dstip: float(nb)}
			try:
				service_to_time[service] += (float(tend) - float(tstart))
			except KeyError:
				service_to_time[service] = (float(tend) - float(tstart))


		pickle.dump({
			'dst_to_services_nb': dst_to_services_nb,
			'service_to_dst_nb': service_to_dst_nb,
			'service_to_time': service_to_time,
		 }, open(os.path.join(CACHE_DIR, 'destinations_to_services.pkl'), 'wb'))

	def correlate_over_time(self):
		np.random.seed(31415)
		self.get_service_bytes_by_separator()

		cache_fn = os.path.join(CACHE_DIR, 'relevant_service_ctrs.pkl')
		relevant_service_ctrs = {}
		if os.path.exists(cache_fn):
			relevant_service_ctrs = pickle.load(open(cache_fn,'rb'))
		service_to_flows = {}
		serviceunit_to_flows = {}
		unit_to_flows = {}
		all_services = {}
		service_to_units = {}
		no_dns_traffic = {}
		total_traffic = 0
		self.load_traceroute_helpers()
		for row in tqdm.tqdm(open(os.path.join(DATA_DIR, 'per_flow_data_april.csv'),'r'),
			desc="Loading April flow data"):
			flowuid,tstart,tend,unit,dstip,nb,dns,_,sni,port,EyeballVote,HighPort,DstNoDNS = row.strip().split(",")
			if flowuid == "": continue
			total_traffic += float(nb)
			uid = (domain_to_domainstr(dns),domain_to_domainstr(sni))
			

			# if dns == "":
			# 	### No DNS traffic
			# 	asn = self.parse_asn(dstip)
			# 	EyeballVote = int(EyeballVote)
			# 	obj = {
			# 		'port': port,
			# 		'dstnodns': int(DstNoDNS != 'False'),
			# 		'eyeballvote': (EyeballVote//1000, (EyeballVote%1000) // 100, (EyeballVote%100) // 10, 
			# 			(EyeballVote%10) // 1),
			# 		'highport': int(HighPort != 'False'),
			# 		'nb': float(nb),
			# 	}
			# 	try:
			# 		no_dns_traffic[asn].append(obj)
			# 	except KeyError:
			# 		no_dns_traffic[asn] = [obj]

			if uid[0] == "" and uid[1] == "": continue

			service = self.domain_sni_to_service.get(uid)
			if service is None:
				continue

			try:
				service_to_flows[service]
			except KeyError:
				service_to_flows[service] = []
			try:
				serviceunit_to_flows[service,unit]
			except KeyError:
				serviceunit_to_flows[service,unit] = []
			service_to_flows[service].append((float(tstart), float(tend), float(nb)))
			serviceunit_to_flows[service,unit].append((float(tstart), float(tend), float(nb)))
			try:
				unit_to_flows[unit][service] = None
			except KeyError:
				unit_to_flows[unit] =  {service:None}
			all_services[service] = None
			try:
				service_to_units[service][unit] = None
			except KeyError:
				service_to_units[service] = {unit:None}


		# all_no_dns = sum([flow['nb'] for flows in no_dns_traffic.values() for flow in flows])
		# print("No DNS is {} pct.".format(all_no_dns * 100.0 / total_traffic))
		# cases_by_asn = {'cases':{}, 'orgs': self.org_to_as}
		# for asn, flows in no_dns_traffic.items():
		# 	cases_by_asn['cases'][asn] = {}
		# 	for flow in flows:
		# 		is_eyeball = any(list(flow['eyeballvote']))
		# 		# problem children are its being called eyeball but has dns
		# 		high_port = flow['highport']
		# 		nodns = flow['dstnodns']
		# 		case = (is_eyeball, high_port, nodns)
		# 		try:
		# 			cases_by_asn['cases'][asn][case] += flow['nb']
		# 		except KeyError:
		# 			cases_by_asn['cases'][asn][case] = flow['nb']

		# pickle.dump(cases_by_asn, open('cache/nodns.pkl','wb'))
		# exit(0)


		total_bytes_by_service = {}
		for service, flowlist in service_to_flows.items():
			for ts,te,nb in flowlist:
				try:
					total_bytes_by_service[service] += nb
				except KeyError:
					total_bytes_by_service[service] = nb
		for service_of_interest in self.sorted_unmappable_domains:
			try:
				relevant_service_ctrs[service_of_interest]
				continue
			except KeyError:
				pass
			try:
				service_to_flows[service_of_interest]
			except KeyError:
				print("Warning -- no flows for {}".format(service_of_interest))
				continue
			nbs = list([el[2]/1e3 for el in service_to_flows[service_of_interest]])
			sorted_nbs = list(sorted(nbs))
			cs_sorted_nbs = np.cumsum(sorted_nbs) / np.sum(sorted_nbs)
			cutoff = np.where(cs_sorted_nbs > .2)[0][0]
			volume_of_interest = sorted_nbs[cutoff]
			print("Volume of interest : {} kB, {} pct of flows".format(volume_of_interest / 1e3,
				(len(cs_sorted_nbs) - cutoff) * 100.0 / len(cs_sorted_nbs)))


			these_units = list(service_to_units[service_of_interest])
			serviceunit_to_flows_cp = copy.deepcopy(serviceunit_to_flows)
			for unit in these_units:
				serviceunit_to_flows_cp[service_of_interest,unit] = list([el for el in serviceunit_to_flows[service_of_interest,unit] if 
					el[2] > cutoff])

			max_n = max(len(serviceunit_to_flows_cp[service_of_interest,unit]) for unit in these_units)
			flow_arr = np.zeros((3,max_n))
			for unit in these_units:
				serviceunit_to_flows_cp[service_of_interest,unit] = sorted(serviceunit_to_flows_cp[service_of_interest,unit],
					key = lambda el : el[0])
				for i, (ts,te,nb) in enumerate(serviceunit_to_flows_cp[service_of_interest,unit]):
					flow_arr[0,i] = ts
					flow_arr[1,i] = te
					flow_arr[2,i] = nb

			time_of_interest = 60 # s
			relevant_service_ctr = {service: {
				'frac_flow': 0,
				'n_flow': 0,
				'n_flow_total': len(service_to_flows[service]),
				'frac_bytes': 0,
				'n_bytes': 0,
				'n_bytes_total': total_bytes_by_service[service],
			} for service in all_services}

			## 2 questions
			### when i see unmapped domain of interest, what is fraction of time it was preceded by service?
			# this will help me assign bytes to services

			for unit in tqdm.tqdm(these_units,desc="Mapping services to services..."):
				for service in unit_to_flows[unit]:
					if service == service_of_interest: continue
					### when i see service, what's the fraction of times it is followed by unmapped domain of interest?
					# this will help me map domains to services
					for ts,te,nb in serviceunit_to_flows_cp.get((service,unit),[]):
						deltas = flow_arr[0,:] - ts
						if len(np.where(np.abs(deltas) < time_of_interest)[0]) > 0:
							relevant_service_ctr[service]['n_flow'] += 1
							relevant_service_ctr[service]['n_bytes'] += nb
			for service in relevant_service_ctr:
				relevant_service_ctr[service]['frac_flow'] = relevant_service_ctr[service]['n_flow'] / len(service_to_flows[service])
				relevant_service_ctr[service]['frac_bytes'] = relevant_service_ctr[service]['n_bytes'] / total_bytes_by_service[service]


			# for top n domains that we can't classify, find the relevant service ctr
			# post-process using clustering or some heuristic to identify the service

			print(service_of_interest)
			print(sorted(relevant_service_ctr.items(), key = lambda el : -1 * el[1]['frac_flow'])[0:100])
			relevant_service_ctrs[service_of_interest] = relevant_service_ctr
			if np.random.random() > .99:
				pickle.dump(relevant_service_ctrs, open(cache_fn,'wb'))
		pickle.dump(relevant_service_ctrs, open(cache_fn,'wb'))

	def load_all_domain_sni_uids(self, **kwargs):
		try:
			self.domain_sni_uids
			return
		except AttributeError:
			pass
		self.domain_sni_uids = {}
		if kwargs.get('by','building') == 'building':
			self.domain_sni_uids_by_building = {}
			self.domain_sni_uids_by_building_flows = {}
			for row in open(os.path.join(DATA_DIR, 
				'buildingip_dns_dnsorig_sni_inbytes_outbytes_nflows.csv'),'r'):
				if row.strip() == "": continue
				i,building,domain,_,sni,nb,nflows = row.strip().split(",")
				if i == "": continue
				domain = domain_to_domainstr(domain)
				sni = domain_to_domainstr(sni)
				if domain == "" and sni == "": continue ### NO DNS TRAFFIC
				uid = (domain,sni)
				try:
					self.domain_sni_uids[uid] += float(nb)
				except KeyError:
					self.domain_sni_uids[uid] = float(nb)
				try:
					self.domain_sni_uids_by_building[building]
				except KeyError:
					self.domain_sni_uids_by_building[building] = {}
					self.domain_sni_uids_by_building_flows[building] = {}
				try:
					self.domain_sni_uids_by_building[building][uid] += float(nb)
					self.domain_sni_uids_by_building_flows[building][uid] += float(nflows)
				except KeyError:
					self.domain_sni_uids_by_building[building][uid] = float(nb)
					self.domain_sni_uids_by_building_flows[building][uid] = float(nflows)
		elif kwargs.get('by','building') == 'unit':
			self.domain_sni_uids_by_unit = {}
			for row in tqdm.tqdm(open(os.path.join(DATA_DIR, 
				'per_flow_data_april.csv'),'r'),desc="Loading per flow data..."):
				flowuid,tstart,tend,unit,dstip,nb,dns,_,sni = row.strip().split(",")
				if flowuid == "": continue
				uid = (domain_to_domainstr(dns),domain_to_domainstr(sni))
				if uid[0] == "" and uid[1] == "": continue

				try:
					self.domain_sni_uids[uid] += float(nb)
				except KeyError:
					self.domain_sni_uids[uid] = float(nb)
				try:
					self.domain_sni_uids_by_unit[unit]
				except KeyError:
					self.domain_sni_uids_by_unit[unit] = {}
				try:
					self.domain_sni_uids_by_unit[unit][uid] += float(nb)
				except KeyError:
					self.domain_sni_uids_by_unit[unit][uid] = float(nb)

		elif kwargs.get('by','building') == 'hour':
			self.domain_sni_uids_by_hour = {}
			for row in tqdm.tqdm(open(os.path.join(DATA_DIR, 
				'time_service_nbytes.csv'),'r'),desc="Loading per hour data..."):
				flowuid,time,dns,dns_name_orig,sni,nb = row.strip().split(",")
				if flowuid == "": continue
				uid = (domain_to_domainstr(dns),domain_to_domainstr(sni))
				if uid[0] == "" and uid[1] == "": continue

				time = "-".join(time.split('-')[0:-1])
				try:
					self.domain_sni_uids[uid] += float(nb)
				except KeyError:
					self.domain_sni_uids[uid] = float(nb)
				try:
					self.domain_sni_uids_by_hour[time]
				except KeyError:
					self.domain_sni_uids_by_hour[time] = {}
				try:
					self.domain_sni_uids_by_hour[time][uid] += float(nb)
				except KeyError:
					self.domain_sni_uids_by_hour[time][uid] = float(nb)


	def load_not_done_domains(self):
		"""Loads domains seen in campus network traces."""
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

	def get_service_activity_measure_dists(self):
		## Get volume data
		by_measure_cache_fn = os.path.join(CACHE_DIR, 'by_activity_measure_cache.pkl')
		if not os.path.exists(by_measure_cache_fn):
			self.get_service_bytes_by_separator()
			service_to_time = pickle.load(open(os.path.join(CACHE_DIR, 
				'destinations_to_services.pkl'),'rb'))['service_to_time']
			by_measure = {
				'dns_responses': {},
				'bytes': {},
				'flows': {},
				'time': service_to_time,
			}
			for arr,activity_type in zip([self.domain_sni_uids_by_building,
				self.domain_sni_uids_by_building_flows], ['bytes', 'flows']):
				for building in arr:
					for uid,n in arr[building].items():
						service = self.domain_sni_to_service.get(uid)
						if service is None: continue
						try:
							by_measure[activity_type][service] += n
						except KeyError:
							by_measure[activity_type][service] = n
			da = Domain_Parsing(popular_domains = self.popular_domains)
			for row in tqdm.tqdm(open(os.path.join(DATA_DIR, 'building_service_ndns.csv'),'r'),
				desc="Loading dns response counts..."):
				try:
					flow_uid,building,domain,n = row.strip().split(',')
				except ValueError:
					continue
				if flow_uid == "": continue
				if domain == "": continue
				uid = (domain, "")
				info = da.map_uid_to_service(uid)
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
		return by_measure

	def get_service_bytes_by_separator(self, **kwargs):
		self.compute_domains_to_services(**kwargs)

		if kwargs.get('by','building') == 'building':
			self.domain_sni_uids_by_separator = self.domain_sni_uids_by_building
		elif kwargs.get('by','building') == 'unit':
			self.domain_sni_uids_by_separator = self.domain_sni_uids_by_unit
		elif kwargs.get('by','building') == 'hour':
			self.domain_sni_uids_by_separator = self.domain_sni_uids_by_hour
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
			
		# remove unimportant services
		vol_by_service = {}
		if kwargs.get('by','building') == 'unit':
			print(list(service_bytes_by_separator))
			for s in service_bytes_by_separator:
				for service,nb in service_bytes_by_separator[s].items():
					try:
						vol_by_service[service] += nb
					except KeyError:
						vol_by_service[service] = nb
			print("{} services total".format(len(vol_by_service)))
			x,cdf_x = get_cdf_xy(list(vol_by_service.values()),logx=True)
			sl = sorted(list(vol_by_service.values()),reverse=True)
			sl = np.array(sl)
			cssl = np.cumsum(sl)
			ssl = np.sum(sl)
			cutoff_v = sl[np.where(cssl >= .99 * ssl)[0][0]]
			services_to_keep = {s:None for s,nb in vol_by_service.items() if nb >= cutoff_v}
			print("Keeping {} services".format(len(services_to_keep)))
			for s in service_bytes_by_separator:
				for service in list(service_bytes_by_separator[s]):
					try:
						services_to_keep[service]
						continue
					except KeyError:
						del service_bytes_by_separator[s][service]
			for s in list(service_bytes_by_separator):
				if len(service_bytes_by_separator[s]) == 0:
					del service_bytes_by_separator[s]

			print("Cutoff volume is {}".format(cutoff_v))
			import matplotlib.pyplot as plt
			plt.semilogx(x,cdf_x)
			plt.xlabel("Volume")
			plt.grid(True)
			plt.ylabel("CDF of Services")
			plt.savefig("volume_by_service.pdf")
			plt.clf(); plt.close()


		return service_bytes_by_separator

	def compute_domains_to_services(self, **kwargs):
		## for each domain
		## if it's a keyword -> map to service
		## check to see if it's in many web page results, if so, discard
		## check to see if it's in a very small number of web page results, possibly call those their own service

		domain_to_service_cache_fn = os.path.join(CACHE_DIR, 'domain_sni_to_service_cache.pkl')
		if not os.path.exists(domain_to_service_cache_fn) or kwargs.get('by','building') != 'building':
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
			da = Domain_Parsing(popular_domains = self.popular_domains)

			unmappable_domains = []
			known_services = {}
			service_to_nb = {}
			mapped_bytes, total_b = 0,0
			bts_ignore,overall_total_b = 0,0
			self.domain_sni_to_service = {}
			for uid, bts in tqdm.tqdm(self.domain_sni_uids.items(), desc="Mapping all domains to services."):
				overall_total_b += bts
				info = da.map_uid_to_service(uid)
				if info['ignore']: 
					bts_ignore += bts
					continue
				used_field = info['used_field']
				total_b += bts
				if info['mapped_to_service']:
					service = info['service']
					self.domain_sni_to_service[uid] = service
					try:
						service_to_nb[service] += bts
					except KeyError:
						service_to_nb[service] = bts
					try:
						known_services[service].append(uid)
					except KeyError:
						known_services[service] = [uid]
					mapped_bytes += bts
				else:
					unmappable_domains.append(uid)
					self.domain_sni_to_service[uid] = uid
			print("popular services are {} pct of bytes".format(round(100*bts_ignore/overall_total_b,2)))
			with open(os.path.join(CACHE_DIR, 'computed_domain_to_service.txt'),'w') as f:
				for service in sorted(known_services, key = lambda el : -1 * service_to_nb[el]):
					domains = known_services[service]
					domains_str = ";".join([";;".join(el) for el in domains])
					f.write("{}\t{}\n".format(service,domains_str))
			with open(os.path.join(CACHE_DIR, 'unmapped_domains_new.txt'),'w') as f:
				for domain in unmappable_domains:
					f.write("{}\n".format(domain))
			self.sorted_unmappable_domains = sorted(unmappable_domains, key = lambda el : -1 * self.domain_sni_uids[el])
			print("\n\nHEAVY HITTERS")
			for heavy_hitter in self.sorted_unmappable_domains[0:100]:
				domain_str = heavy_hitter[0]
				print("{} {}".format(heavy_hitter, subsite_to_supersite.get(domain_str, [])))

			print("{} percent of bytes mapped".format(round(mapped_bytes * 100.0 / total_b)))

			sorted_doms = sorted(list([self.domain_sni_uids[uid] for uid in unmappable_domains]),key = lambda el : -1 * el)
			cumsum = 1-np.cumsum(sorted_doms) / sum(sorted_doms)

			import matplotlib.pyplot as plt
			plt.semilogx(np.arange(len(cumsum)), cumsum)
			plt.xlabel("Number of Unmappable Domains")
			plt.ylabel("CDF of Traffic")
			plt.grid(True)
			plt.savefig("figures/unmappable_domain_volume_contribution.pdf")
			plt.clf(); plt.close()


			if kwargs.get('by','building') == 'building':
				pickle.dump({
					'popular_domains': self.popular_domains,
					'domain_sni_to_service': self.domain_sni_to_service,
					'sorted_unmappable_domains': self.sorted_unmappable_domains,
					'domain_sni_uids_by_building': self.domain_sni_uids_by_building,
					'domain_sni_uids_by_building_flows': self.domain_sni_uids_by_building_flows,
				}, open(domain_to_service_cache_fn,'wb'))
		else:
			print("Loading domain sni from cache")
			cache = pickle.load(open(domain_to_service_cache_fn, 'rb'))
			self.popular_domains = cache['popular_domains']
			self.domain_sni_to_service = cache['domain_sni_to_service']
			self.sorted_unmappable_domains = cache['sorted_unmappable_domains']
			self.domain_sni_uids_by_building = cache['domain_sni_uids_by_building']
			self.domain_sni_uids_by_building_flows = cache['domain_sni_uids_by_building_flows']

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
	sm.classify_traffic_types_high_level_small()
	# sm.map_destinations_to_services()
	# sm.fetch_domains()
	# sm.compute_domains_to_services()
	# sm.correlate_over_time()
	# sm.identify_services_from_correlation()




