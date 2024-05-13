import os,glob,numpy as np, json, tqdm, csv, pytricia, gzip, matplotlib.pyplot as plt
from vasilis_traceroute import Traceroute
from helpers import *
from constants import *
from google_utilities import *
from subprocess import call, check_output
from get_top_ips import get_top_ips



###### IMC 2023
# ## 5/11/2023, 5/15/2023, 5/23/2023
TIMES_OF_INTEREST = ['1683848502', '1684156449','1684845466']



###### SIGCOMM 2024
# 1/31/2024, 2/1/2024
# TIMES_OF_INTEREST = ['1706715933','1706817104']

class Campus_Measurement_Analyzer:
	def __init__(self):
		self.asn_cache_file = "ip_to_asn.csv" # we slowly build the cache over time, as we encounter IP addresses
		self.as_siblings = {}
		self.ip_to_asn = {}
		self.target_fn = os.path.join(MEASUREMENT_DIR, 'topips_buildingip_inbytes_outbytes.txt')

	def check_load_siblings(self):
		""" Loads siblings file, creates mapping of asn -> organization and vice-versa.
			Useful for checking if two ASNs are basically the same."""

		# In most places, we treat ASes as the same if they are siblings (\ie owned by the same organization)
		# We treat siblings the same since treating siblings separatetly would make the logic for various things
		# like calculating if a route is Valley Free uglier
		if self.as_siblings != {}: return
		print("Loading siblings")
		uid = int(1e6) # each organization is defined as an integer > 1e6 since real ASNs are less than 1e6
		def check_add_siblings(sib1, sib2, uid,v=0):
			# Check to see if we have created sibling groups for either of these AS's
			have_s1 = False
			have_s2 = False
			try:
				self.as_siblings[sib_1]
				have_s1 = True
			except KeyError:
				pass
			try:
				self.as_siblings[sib_2]
				have_s2 = True
			except KeyError:
				pass
			# if we haven't seen these ASes before, form a new organization for these ASes
			if not have_s1 and not have_s2:
				self.as_siblings[sib_1] = uid
				self.as_siblings[sib_2] = uid
				uid += 1
			elif have_s1: # S1 and S2 are siblings -- update our data structure
				this_sib_uid = self.as_siblings[sib_1]
				self.as_siblings[sib_2] = this_sib_uid
			else:
				this_sib_uid = self.as_siblings[sib_2]
				self.as_siblings[sib_1] = this_sib_uid
			return uid
		
		# It is important that these files stay the same, and are loaded in the same order, or else we have to recalculate lots of things in the cache
		self.siblings_fns = ["vasilis_siblings_20200816.txt"] # from Vasilis Giotsas
		siblings_fn = os.path.join(DATA_DIR, self.siblings_fns[0])
		with open(siblings_fn, 'r') as f:
			for row in f:
				sib_1, sib_2 = row.strip().split(' ')
				uid = check_add_siblings(sib_1,sib_2,uid)
		
		# form the inverse image of the mapping
		self.org_to_as = {}
		for sib_as, org_id in self.as_siblings.items():
			try:
				self.org_to_as[org_id]
			except KeyError:
				self.org_to_as[org_id] = []
			self.org_to_as[org_id].append(sib_as)

	def parse_asn(self, ip_or_asn):
		"""Make sure you've tried to look up this IP address' ASN before calling this function."""
		# if input is IP address, converts to organzation
		# if input is ASN, converts to organization
		# if input is organization, leaves it alone
		# if we don't know the ASN of the IP address, returns None
		if ip_or_asn is None: return None
		if ip_or_asn == "": return None
		if type(ip_or_asn) == str:
			if "." in ip_or_asn:
				ip_or_asn = ip_or_asn.split("/")[0]
				# IP
				try:
					asn = self.ip_to_asn[ip32_to_24(ip_or_asn)]
					if asn.lower() == 'unknown' or asn.lower() == 'none' or asn.lower() == "na" or asn.lower() == "null": 
						raise KeyError
				except KeyError:
					asn = self.routeviews_pref_to_asn.get(ip_or_asn + "/32")
					if asn is None: return None
			else:
				asn = ip_or_asn
		else:
			asn = ip_or_asn
		if type(asn) == str:
			if asn.lower() == 'unknown' or asn.lower() == 'none' or asn.lower() == "na" or asn.lower() == "null":
				return None
		if int(asn) > 1e6:
			# Already converted to organization
			asn = int(asn)
		else:
			asn = str(asn)
		try:
			asn = self.as_siblings[asn]
		except KeyError:
			pass
		return asn

	def save_ip_to_asn(self):
		"""IP to ASN mapping is saved in a Python pickle file."""
		print("Saving IP to ASN don't exit.")
		ip2asn_fn = os.path.join(CACHE_DIR, self.asn_cache_file)
		with open(ip2asn_fn, 'w') as f:
			f.write("ip\tasn\n")
			for ip,asn in self.ip_to_asn.items():
				f.write("{}\t{}\n".format(ip,asn))
		print("Done.")

	def check_load_ip_to_asn(self):
		"""Loads IP to ASN mapping if we haven't already."""
		if self.ip_to_asn != {}: return
		ip2asn_fn = os.path.join(CACHE_DIR, self.asn_cache_file)
		self.ip_to_asn = {}
		if os.path.exists(ip2asn_fn):
			pbar = tqdm.tqdm(total=6300000, desc="Loading IP to ASN cache")
			ip2asn_d = csv.DictReader(open(ip2asn_fn,'r'), delimiter='\t')
			for row in ip2asn_d:
				self.ip_to_asn[row['ip']] = row['asn']
				pbar.update(1)
			if np.random.random() > .99:
				# periodically delete ones we couldn't find just to check
				print("\nRandomly causing checks for unknown IP addresses")
				to_del = []
				for ip,asn in self.ip_to_asn.items():
					if asn == 'NA' or asn == "None":
						to_del.append(ip)
				print("Deleting {} ip addresses".format(len(to_del)))
				for ip in to_del: del self.ip_to_asn[ip]
				self.save_ip_to_asn()
		self.ip_to_asn["*"] = None # unknown hops are associated with ASN None

		self.routeviews_asn_to_pref = {}
		self.routeviews_pref_to_asn = pytricia.PyTricia()
		# https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/
		routeviews_pref_to_as_fn = os.path.join(DATA_DIR, "routeviews-rv2-20230507-1200.pfx2as")
		for row in open(routeviews_pref_to_as_fn):
			pref,l,asn = row.strip().split('\t')
			asns = asn.split(",")

			for asn in asns:
				asn = self.parse_asn(asn)
				try:
					self.routeviews_asn_to_pref[asn].append(pref + "/" + l)
				except KeyError:
					self.routeviews_asn_to_pref[asn] = [pref + "/" + l]
				self.routeviews_pref_to_asn[pref + "/" + l] = asn

		self.routeviews_pref_to_asn['199.109.0.0/16'] = self.parse_asn(3754)

	def load_traceroute_helpers(self):
		# Traceroute parsing helper class from Vasilis Giotsas
		self.check_load_siblings()
		self.check_load_ip_to_asn()
		self.tr = Traceroute(ip_to_asn = self.parse_asn)
		ixp_ip_members_file = os.path.join(DATA_DIR,"ixp_members.merged-20190826.txt") # from Vasilis Giotsas
		ixp_prefixes_file = os.path.join(DATA_DIR,"ixp_prefixes.merged-20190826.txt") # from Vasilis Giotsas
		self.tr.read_ixp_ip_members(ixp_ip_members_file)
		self.tr.read_ixp_prefixes(ixp_prefixes_file)

	def load_target_data(self):
		self.targets = {}
		for row in open(self.target_fn, 'r'):
			ip,_,inbytes,outbytes = row.strip().split(',')
			inbytes = float(inbytes)
			outbytes = float(outbytes)
			try:
				self.targets[ip]
			except KeyError:
				self.targets[ip] = {'in': 0, 'out':0, 'total': 0}
			self.targets[ip]['in'] += inbytes
			self.targets[ip]['out'] += outbytes
			self.targets[ip]['total'] += (inbytes + outbytes)

	def lookup_asns_if_needed(self, d):
		"""Looks up ASes associated with IP addresses in d. Uses cymruwhois Python library, which is slow. 
			Hence we cache answers."""
		# d is list or dict where elements are CIDR prefix strings
		dont_know = []
		for el in d:
			pref = el.split('/')[0]
			pref_24 = ip32_to_24(pref)
			if is_bad_ip(pref): continue # don't resolve private IP addresses
			try:
				self.ip_to_asn[pref]
			except KeyError:
				if self.routeviews_pref_to_asn.get(pref) is not None: continue
				dont_know.append(pref_24)
		dont_know = list(set(dont_know))
		if dont_know == []: return
		ret = lookup_asn(dont_know)
		for k,v in ret.items():
			self.ip_to_asn[k] = v
		self.save_ip_to_asn()	

	def parse_ripe_trace_result(self, result, ret_ips=False, verb=False):
		"""Parse traceroute measurement result from RIPE Atlas into a nice form."""
		src,dst = result['src'], result['dst']
		if src == "" or dst == "": return None

		ret = {}
		ret['src'] = src
		ret['dst'] = dst
		raw_ripe_paths = []
		hop_rtts = []
		# Extract hops and RTTs
		try:
			result['hops']
		except KeyError:
			if ret_ips:
				return []
			else:
				return None
		for el in result['hops']:
			this_arr = [el['addr']]
			this_rtt_arr = [el['rtt']]
			hop_rtts.append(this_rtt_arr)
			raw_ripe_paths.append(this_arr)
		if len(raw_ripe_paths) == 0:
			# Bad measurement
			return None
		# prepend/append the source/dest if we haven't
		# we know if the traceroute didn't reach the destination if rtts[-1] == []
		if src not in set(raw_ripe_paths[0]):
			raw_ripe_paths = [[src]] + raw_ripe_paths
			hop_rtts = [[0]] + hop_rtts

		every_ip = list(set([ip for hop_set in raw_ripe_paths for ip in hop_set])) + [dst]
		if ret_ips: return every_ip

		ret['reached_dst_network'] = False
		asn_path = self.tr.ip_to_asn(raw_ripe_paths)
		dst_ntwrk = self.parse_asn(dst)
		if not dst_ntwrk is None:
			for ashop in reversed(asn_path):
				if ashop == dst_ntwrk:
					ret['reached_dst_network'] = True
					break
					
		if dst not in set(raw_ripe_paths[-1]):
			raw_ripe_paths = raw_ripe_paths + [[dst]]
			hop_rtts = hop_rtts + [[]]
			ret['reached_dst'] = False
		else:
			ret['reached_dst'] = True
		# Calculate the AS path
		# uses the Traceroute class utility function which does things like remove ASes associated with IXPs
		try:
			asn_path = self.tr.ip_to_asn(raw_ripe_paths)
		except KeyError:
			still_need = get_difference(every_ip, self.ip_to_asn)
			self.lookup_asns_if_needed(still_need)
			asn_path = self.tr.ip_to_asn(raw_ripe_paths)

		ret["ip_paths"] = raw_ripe_paths
		ret["rtts"] = hop_rtts
		for i in range(len(asn_path)):
			if asn_path[i] is None:
				asn_path[i] = "None"
			else:
				asn_path[i] = str(asn_path[i])
		ret["as_paths"] = asn_path
		ret['time'] = result['start']['sec']
		
		return ret

	def parse_ping_result_set(self):
		## get RTT to all destinations
		# self.load_traceroute_helpers()
		# self.load_target_data()

		rtts_cache_fn = os.path.join(CACHE_DIR, 'rtts.pkl')
		if not os.path.exists(rtts_cache_fn):
			targ_to_rtt =  {}
			all_ping_files = glob.glob(os.path.join(MEASUREMENT_DIR, 'pings-*.json'))
			all_ping_files = [ping_file for ping_file in all_ping_files if any(toi in ping_file for toi in TIMES_OF_INTEREST)]

			for result_fn in tqdm.tqdm(all_ping_files,
				desc="Parsing RTT measurements."):
				# result_fn = os.path.join(MEASUREMENT_DIR, 'pings-{}-14.json'.format(TIMES_OF_INTEREST[0]))
				these_results = json.load(open(result_fn,'r'))
				for result in these_results:
					if result['type'] != 'ping': continue
					for p in result['responses']:
						try:
							targ_to_rtt[result['dst']].append(p['rtt'])
						except KeyError:
							targ_to_rtt[result['dst']] = [p['rtt']]

			for dst,lats in targ_to_rtt.items():
				targ_to_rtt[dst] = {
					'min': np.min(lats),
					'mean': np.mean(lats),
					'med': np.median(lats),
				}
			pickle.dump(targ_to_rtt, open(rtts_cache_fn,'wb'))
		else:
			targ_to_rtt = pickle.load(open(rtts_cache_fn,'rb'))


		d = pickle.load(open(os.path.join(CACHE_DIR, 'destinations_to_services.pkl'),'rb'))
		dst_to_services_nb = d['dst_to_services_nb']
		services_to_rtts_nb = {}
		services_to_nb = {}
		for dst in targ_to_rtt:
			for service,nb in dst_to_services_nb.get(dst,{}).items():
				app = (targ_to_rtt[dst]['min'], nb)
				try:
					services_to_rtts_nb[service].append(app)
				except KeyError:
					services_to_rtts_nb[service] = [app]
				try:
					services_to_nb[service] += nb
				except KeyError:
					services_to_nb[service] = nb

		sorted_services = sorted(list(services_to_nb), key = lambda s : -1 * services_to_nb[s])


		import matplotlib
		matplotlib.rcParams.update({'font.size': 18})
		import matplotlib.pyplot as plt
		f,ax = plt.subplots(1,1)
		f.set_size_inches(12,6)

		services_to_rtts_avg = {}
		services_to_vol = {}
		for service, rttsnb in services_to_rtts_nb.items():
			services_to_rtts_avg[service] = np.average([np.minimum(500,el[0]) for el in rttsnb], weights=[el[1] for el in rttsnb])
			services_to_vol[service] = sum([el[1] for el in rttsnb])
		for n in [50,100,1000,-1]:
			services_to_rtts_avg_subset = list([services_to_rtts_avg[service] for service in sorted_services[0:n]])
			x,cdf_x = get_cdf_xy(services_to_rtts_avg_subset,n_points=1000,logx=True)
			labn = "Top {} Services".format(n) if n != -1 else "All Services"
			ax.semilogx(x,cdf_x,label=labn)
		x,cdf_x = get_cdf_xy(list(zip([services_to_rtts_avg[service] for service in sorted_services],
			[services_to_vol[service] for service in sorted_services])), weighted=True, logx=True, n_points=1000)
		ax.semilogx(x,cdf_x,label="All Traffic")
		x,cdf_x = get_cdf_xy(list([el['min'] for el in targ_to_rtt.values()]))
		ax.semilogx(x,cdf_x,label='All Destinations')
		ax.set_ylabel("CDF of Services")
		ax.set_xlabel("Average RTT (ms)")
		ax.set_xlim([1,300])
		ax.legend()

		ax.grid(True)
		ax.set_ylim([0,1.0])
		plt.savefig('figures/service_locality.pdf')

	def parse_trace_result_set(self):
		cdf_aspl_cache_fn = os.path.join(CACHE_DIR, 'aspl_cdfs.pkl')
		if not os.path.exists(cdf_aspl_cache_fn):
			self.load_target_data()
			self.load_traceroute_helpers()
			all_data_cache_fn = os.path.join(CACHE_DIR, 'aspls_all_objs.pkl')
			if not os.path.exists(all_data_cache_fn):

				times_of_interest = TIMES_OF_INTEREST
				all_trace_files = glob.glob(os.path.join(MEASUREMENT_DIR, 'traces-*.json'))
				all_trace_files = [trace_file for trace_file in all_trace_files if any(toi in trace_file for toi in times_of_interest)]
				
				campus_traffic_destinations_trace_files = [tf for tf in all_trace_files if 'traces-all' not in tf]
				all_destinations_trace_files = get_difference(all_trace_files, campus_traffic_destinations_trace_files)


				lookup_ips = []
				for result_fn in tqdm.tqdm(all_trace_files,
					desc="Parsing result fns to see if we need to map ASNs."):
					these_results = json.load(open(result_fn,'r'))
					these_results = [result for result in these_results if result['type'] == 'trace']
					for result in these_results:
						lookup_ips.append(self.parse_ripe_trace_result(result, ret_ips=True))
				self.lookup_asns_if_needed(list(set([ip32_to_24(ip) for res_set in lookup_ips for ip in res_set])))
				all_objs = []
				for result_fn in tqdm.tqdm(campus_traffic_destinations_trace_files, 
					desc="Parsing traceroutes"):
					these_results = json.load(open(result_fn,'r'))
					these_results = [result for result in these_results if result['type'] == 'trace']
					objs = []
					for result in these_results:
						objs.append(self.parse_ripe_trace_result(result))

					all_objs = all_objs + objs

				all_objs_by_dst = {}
				for obj in all_objs:
					if obj is None: continue
					try:
						if all_objs_by_dst[obj['dst']]['time'] < obj['time']:
							all_objs_by_dst[obj['dst']] = obj	
					except KeyError:
						all_objs_by_dst[obj['dst']] = obj
				all_objs = all_objs_by_dst

				keep_dsts = get_intersection(self.targets, all_objs)
				self.targets = {t:self.targets[t] for t in keep_dsts}
				all_objs = {t: all_objs[t] for t in keep_dsts}

				total_traffic = sum(self.targets[t]['total'] for t in self.targets)
				asps = {t:[self.parse_asn(el) for el in obj['as_paths'] if el != 'None'] for t,obj in all_objs.items()
					if obj['reached_dst']}
				pct_traffic = round(sum(self.targets[t]['total'] for t in asps) / total_traffic * 100.0 ,2)
				print("{} pct ({}) of traceroutes, {} pct of traffic, reached a destination".format(100 * len(asps) / len(all_objs),
					len(asps), pct_traffic))
				asps = {t: [self.parse_asn(el) for el in obj['as_paths'] if el != 'None'] for t,obj in all_objs.items()
					if obj['reached_dst_network']}
				pct_traffic = round(sum(self.targets[t]['total'] for t in asps) / total_traffic * 100.0 ,2)
				print("{} pct ({}) of traceroutes, {} pct of traffic, reached the destination network".format(100 * len(asps) / len(all_objs),
					len(asps),pct_traffic))

				aspls = {ip:len(set(el)) for ip,el in asps.items()}


				all_objs_whole_internet = []
				for result_fn in tqdm.tqdm(all_destinations_trace_files, 
					desc="Parsing traceroutes"):
					these_results = json.load(open(result_fn,'r'))
					these_results = [result for result in these_results if result['type'] == 'trace']
					objs = []
					for result in these_results:
						objs.append(self.parse_ripe_trace_result(result))

					all_objs_whole_internet = all_objs_whole_internet + objs

				all_objs_by_dst = {}
				for obj in all_objs_whole_internet:
					if obj is None: continue
					try:
						if all_objs_by_dst[obj['dst']]['time'] < obj['time']:
							all_objs_by_dst[obj['dst']] = obj	
					except KeyError:
						all_objs_by_dst[obj['dst']] = obj
				all_objs_whole_internet = all_objs_by_dst

				asps_whole_internet = {t: [self.parse_asn(el) for el in obj['as_paths'] if el != 'None'] for t,obj in all_objs_whole_internet.items()
					if obj['reached_dst_network']}
				

				aspls_whole_internet = {ip:len(set(el)) for ip,el in asps_whole_internet.items()}


				pickle.dump({
					"asp_campus": asps, 
					"aspl_campus": aspls, 
					"all_objs_campus": all_objs,
					"asp_whole_internet": asps_whole_internet,
					"aspl_whole_internet": aspls_whole_internet,
					"all_objs_whole_internet": all_objs_whole_internet,
					"org_to_as": self.org_to_as,
				}, open(all_data_cache_fn,'wb'))
				pickle.dump({
					'aspl_campus':aspls,
					'aspl_whole_internet':aspls_whole_internet,
				}, open(os.path.join(CACHE_DIR, 'aspls.pkl'),'wb'))
			else:
				all_objs = pickle.load(open(all_data_cache_fn, 'rb'))
				aspls_obj = pickle.load(open(os.path.join(CACHE_DIR, 'aspls.pkl'),'rb'))
				aspls = aspls_obj['aspl_campus']
				aspls_whole_internet = aspls_obj['aspl_whole_internet']
				all_objs_campus = all_objs['all_objs_campus']



			cdf_aspls = {}

			# second_hops = {}
			# first_hop = '14'
			# for dst,asp in asps.items():
			# 	for hop in asp:
			# 		if hop != first_hop:
			# 			try:
			# 				second_hops[hop] += 1
			# 			except KeyError:
			# 				second_hops[hop] = 1 
			# 			break
			# sorted_second_hops = sorted(second_hops.items(),  key = lambda el : -1 * el[1])
			# top_second_hops = sorted_second_hops[0:20]
			# top_second_hop_ases = [el[0] for el in sorted_second_hops[0:20]]
			# print("Top second hop ASes: {}".format(top_second_hops))
			# for dst,asp in asps.items():
			# 	for hop in asp:
			# 		if hop != first_hop:
			# 			if hop in top_second_hop_ases and hop not in ['174','3257', '16509','3754','40627']:
			# 				print("{} {}".format(hop,first_hop))
			# 				print("{} {} {}".format(dst,asp,all_objs[dst]))
			# 			break
			not_included = get_difference(self.targets, aspls)
			sorted_not_included = sorted(not_included, key = lambda el : -1 * self.targets[el]['total'])
			print("Worst not included {}".format(sorted_not_included[0:100]))

			targs_of_interest = list(get_intersection(aspls,self.targets))

			## load offnets and handle them separately
			offnet_addresses = pickle.load(open(os.path.join(DATA_DIR, 'offnets.p'),'rb'))
			# for oa in sorted(get_intersection(offnet_addresses, self.targets),
			# 	key = lambda el : -1 * self.targets[el]['total'])[0:100]:
			# 	print("{} -- {} (not in results {})".format(oa, self.targets[oa]['total'], oa in not_included))
				# if not (oa in not_included):
				# 	print(all_objs[oa])
			offnet_addresses = get_intersection(targs_of_interest, offnet_addresses)
			for offnet_address in offnet_addresses:
				aspls[offnet_address] += .5


			## Get ASPL by AS
			aspl_by_as = {}
			for t in targs_of_interest:
				asn = self.parse_asn(t)
				if asn is None: continue
				try:
					aspl_by_as[asn].append(aspls[t])
				except KeyError:
					aspl_by_as[asn] = [aspls[t]]
			# aspl_by_as_max = [np.max(as_aspls) for as_aspls in aspl_by_as.values()]
			# aspl_by_as_min = [np.min(as_aspls) for as_aspls in aspl_by_as.values()]
			aspl_by_as_med = [np.median(as_aspls) for as_aspls in aspl_by_as.values()]

		

			aspl_arr = [aspls[targ] for targ in targs_of_interest]
			for k, lab in zip(['out', 'total', 'in'], 
				['Out Bytes', 'Total Bytes', "In Bytes"]):
				wts = [self.targets[targ][k] for targ in targs_of_interest]
				aspl_arr_wtd = list(zip(aspl_arr,wts))
				aspl_arr_wtd_with_targs = list(zip(aspl_arr,wts,targs_of_interest))
				sorted_arr = sorted(aspl_arr_wtd_with_targs, key = lambda el : -1 * el[1])
				print(lab)
				print(sorted_arr[0:30])
				

				easier_format = {}
				for aspl,val in aspl_arr_wtd:
					try:
						easier_format[aspl] += val
					except KeyError:
						easier_format[aspl] = val
				vals = list(easier_format.keys())
				wts = list([easier_format[aspl] for aspl in vals])
				aspl_arr_wtd = list(zip(vals,wts))

				x,cdf_x = get_cdf_xy(aspl_arr_wtd, weighted=True)
				cdf_aspls[k] = (x,cdf_x)
			
			x,cdf_x = get_cdf_xy(aspl_arr)
			cdf_aspls['destinations'] = (x,cdf_x)
			x,cdf_x = get_cdf_xy(list(aspls_whole_internet.values()))
			cdf_aspls['whole_internet'] = (x,cdf_x)
			pickle.dump(cdf_aspls, open(cdf_aspl_cache_fn,'wb'))
		else:
			cdf_aspls = pickle.load(open(cdf_aspl_cache_fn, 'rb'))

		import matplotlib
		matplotlib.rcParams.update({'font.size': 18})
		import matplotlib.pyplot as plt
		f,ax = plt.subplots(1,1)
		f.set_size_inches(12,6)
		# fig, ax = plt.subplots(1, 2, figsize=(14,7))
		i = 0
		every_other = 7
		for k, lab in zip(['in', 'out', 'total','destinations','whole_internet'], 
			["In Residential Traffic", 'Out Residential Traffic', 'Total Bytes',
			'Residential Traffic Remote Hosts', "All Routable Prefixes"]):
			if k == 'total': continue
			x,cdf_x = cdf_aspls[k]
			ax.plot(x[::every_other],cdf_x[::every_other],label=lab,marker=MARKERSTYLES[i],
				markersize=8)
			i+=1

		# x,cdf_x = get_cdf_xy(aspl_by_as_med)
		# ax[1].plot(x,cdf_x,label="Campus Traffic Targets")

		# ## Get ASPL by AS for whole internet
		# aspl_by_as_whole_internet = {}
		# for t in aspls_whole_internet:
		# 	asn = self.parse_asn(t)
		# 	if asn is None: continue
		# 	try:
		# 		aspl_by_as_whole_internet[asn].append(aspls_whole_internet[t])
		# 	except KeyError:
		# 		aspl_by_as_whole_internet[asn] = [aspls_whole_internet[t]]
		# aspl_by_as_whole_internet_med = [np.median(as_aspls) for as_aspls in aspl_by_as_whole_internet.values()]
		# x,cdf_x = get_cdf_xy(aspl_by_as_whole_internet_med)
		# ax[1].plot(x,cdf_x,label="Whole Internet")

		ax.grid(True)
		# ax[1].grid(True)
		ax.set_xlabel("AS Path Length")
		# ax[1].set_xlabel("AS Path Length")
		ax.set_xlim([1,8])
		# ax[1].set_xlim([2,8])
		ax.set_ylabel("CDF of Destinations/Traffic")
		# ax[1].set_ylabel("CDF of ASes")
		ax.legend()
		ax.annotate("Offnet\nTraffic", (2.1,.26))
		# ax[1].legend()
		plt.savefig('figures/all_aspls.pdf')

	def aspl_from_bgp_routes(self):
		np.random.seed(31415)
		cdf_aspl_cache_fn = os.path.join(CACHE_DIR, 'aspl_cdfs_from_cu.pkl')
		if not os.path.exists(cdf_aspl_cache_fn):
			cache_fn = os.path.join(CACHE_DIR, 'aspls_all_objs_from_cu.pkl')
			self.load_target_data()
			self.load_traceroute_helpers()
			if not os.path.exists(cache_fn):
				import pytricia
				as_paths_by_pref = pytricia.PyTricia()
				pref = None
				for row in tqdm.tqdm(open(os.path.join(DATA_DIR,'cu_bgp_routes.txt'),'r'),
					desc="Parsing BGP table from CU"):
					fields = [el for el in row.strip().split('  ') if el.strip() != ""]
					if "/" in row:
						pref = fields[1].strip()
						prefl = pref.split('/')[1]
					elif row.count(".") == 6:
						pref = fields[1].strip()
						if pref == "0.0.0.0": continue
						pref = pref + "/" + prefl
					if pref is None:
						continue
					if row.startswith(" *>"):
						## selected route
						as_path = fields[-1].replace('i',' ').strip().split(' ')
						parsed_as_path = ['14']
						prev_hop = None
						for el in as_path:
							el = el.replace("{","").replace("}","")
							for ell in el.split(","):
								try:
									if int(el) >= 64512 and int(el) <= 65534:
										## private IP address
										continue
								except ValueError:
									pass
								if ell == '0': continue
								if prev_hop != ell:
									parsed_as_path.append(ell)
								prev_hop = ell
						as_paths_by_pref[pref] = parsed_as_path
						if len(parsed_as_path) == 2 and parsed_as_path[-1] == '16509':
							print(row)
						# if as_paths_by_pref[pref][-1] == '16509':
						# 	print(row)
						# 	print(as_paths_by_pref[pref])
						# 	if np.random.random() > .99:
						# 		exit(0)
					else:
						continue
					
				# print(as_paths_by_pref.get("199.109.94.18"))
				# exit(0)

				# print(len(as_paths_by_pref))
				
				all_objs = {} # code reuse
				to_del = []
				for t in self.targets:
					as_path = as_paths_by_pref.get(t + "/32")
					if as_path is None:
						all_objs[t] = {'as_paths': None, 'reached_dst_network': False, 'reached_dst': False}
						# if np.random.random() > .999:
						# 	print("No BGP route found for {}, random print".format(t))
					else:
						all_objs[t] = {'as_paths': as_path, 'reached_dst_network': True,'reached_dst': True}


				total_traffic = sum(self.targets[t]['total'] for t in self.targets)
				asps = {t:[self.parse_asn(el.replace("{","").replace("}","")) for el in obj['as_paths'] if el != 'None' and el != '0' and el !='?'  and el !='e'] for t,obj in all_objs.items()
					if obj['reached_dst']}
				pct_traffic = round(sum(self.targets[t]['total'] for t in asps) / total_traffic * 100.0 ,2)
				print("{} pct ({}) of traceroutes, {} pct of traffic, reached a destination".format(100 * len(asps) / len(all_objs),
					len(asps), pct_traffic))
				asps = {t: [self.parse_asn(el.replace("{","").replace("}","")) for el in obj['as_paths'] if el != 'None' and el != '0' and el !='?' and el !='e'] for t,obj in all_objs.items()
					if obj['reached_dst_network']}
				# for t,asp in sorted(asps.items(), key = lambda el : -1 * self.targets.get(t[0],{'total':0})['total']):
				# 	v = self.targets.get(t,{'total':0})['total']
				# 	if len(set(asp)) == 2:
				# 		print("{} -- {}, {}, {}".format(t,asp,all_objs[t],v))
				# 		if np.random.random() > .999:
				# 			break
				aspls = {ip:len(set(el)) for ip,el in asps.items()}

				all_objs_whole_internet = {t: {'as_paths': as_paths_by_pref.get(t), 'reached_dst_network': True} for t in as_paths_by_pref}
				asps_whole_internet = {t: [self.parse_asn(el.replace("{","").replace("}","")) for el in obj['as_paths'] if el != 'None' and el != '0' and el !='?' and el !='e'] for t,obj in all_objs_whole_internet.items()
					if obj['reached_dst_network']}
				

				aspls_whole_internet = {ip:len(set(el))+1 for ip,el in asps_whole_internet.items()}


				pickle.dump({
					"asp_campus": asps, 
					"aspl_campus": aspls, 
					"as_paths_by_pref":as_paths_by_pref,
					"all_objs_campus": all_objs,
					"asp_whole_internet": asps_whole_internet,
					"aspl_whole_internet": aspls_whole_internet,
					"all_objs_whole_internet": all_objs_whole_internet,
					"org_to_as": self.org_to_as,
				}, open(cache_fn,'wb'))
				pickle.dump({
					'aspl_campus':aspls,
					'aspl_whole_internet':aspls_whole_internet,
				}, open(os.path.join(CACHE_DIR, 'aspls_from_cu.pkl'),'wb'))
			else:
				all_objs = pickle.load(open(cache_fn, 'rb'))
				aspls_obj = pickle.load(open(os.path.join(CACHE_DIR, 'aspls_from_cu.pkl'),'rb'))
				aspls = aspls_obj['aspl_campus']
				aspls_whole_internet = aspls_obj['aspl_whole_internet']
				all_objs_campus = all_objs['all_objs_campus']

			cdf_aspls = {}

			# second_hops = {}
			# first_hop = '14'
			# for dst,asp in asps.items():
			# 	for hop in asp:
			# 		if hop != first_hop:
			# 			try:
			# 				second_hops[hop] += 1
			# 			except KeyError:
			# 				second_hops[hop] = 1 
			# 			break
			# sorted_second_hops = sorted(second_hops.items(),  key = lambda el : -1 * el[1])
			# top_second_hops = sorted_second_hops[0:20]
			# top_second_hop_ases = [el[0] for el in sorted_second_hops[0:20]]
			# print("Top second hop ASes: {}".format(top_second_hops))
			# for dst,asp in asps.items():
			# 	for hop in asp:
			# 		if hop != first_hop:
			# 			if hop in top_second_hop_ases and hop not in ['174','3257', '16509','3754','40627']:
			# 				print("{} {}".format(hop,first_hop))
			# 				print("{} {} {}".format(dst,asp,all_objs[dst]))
			# 			break
			not_included = {k:None for k in get_difference(self.targets, aspls)}
			sorted_not_included = sorted(not_included, key = lambda el : -1 * self.targets[el]['total'])
			print("Worst not included {}".format(sorted_not_included[0:100]))

			targs_of_interest = list(get_intersection(aspls, self.targets))

			## load offnets and handle them separately
			offnet_addresses = pickle.load(open(os.path.join(DATA_DIR, 'offnets.p'),'rb'))
			for oa in sorted(get_intersection(offnet_addresses, self.targets),
				key = lambda el : -1 * self.targets[el]['total'])[0:100]:

				try:
					not_included[oa]
					oaini = True
				except KeyError:
					oaini = False
				print("{} -- {} (not in results {})".format(oa, self.targets[oa]['total'], oaini))
				if not oaini:
					print(all_objs.get(oa,'offnet address from pickle not found in routes'))
			offnet_addresses = get_intersection(targs_of_interest, offnet_addresses)
			for offnet_address in offnet_addresses:
				aspls[offnet_address] += .5


			## Get ASPL by AS
			aspl_by_as = {}
			for t in targs_of_interest:
				asn = self.parse_asn(t)
				if asn is None: continue
				try:
					aspl_by_as[asn].append((t,aspls[t]))
				except KeyError:
					aspl_by_as[asn] = [(t,aspls[t])]
		

			aspl_arr = [aspls[targ] for targ in targs_of_interest]
			for k, lab in zip(['out', 'total', 'in'], 
				['Out Bytes', 'Total Bytes', "In Bytes"]):
				wts = [self.targets[targ][k] for targ in targs_of_interest]
				aspl_arr_wtd = list(zip(aspl_arr,wts))
				aspl_arr_wtd_with_targs = list(zip(aspl_arr,wts,targs_of_interest))
				sorted_arr = sorted(aspl_arr_wtd_with_targs, key = lambda el : -1 * el[1])
				print(lab)
				print(sorted_arr[0:30])
				for aspl,wt,targ in sorted_arr:
					if aspl == 2:
						print(targ)
						if np.random.random() > .99:
							break

				easier_format = {}
				for aspl,val in aspl_arr_wtd:
					try:
						easier_format[aspl] += val
					except KeyError:
						easier_format[aspl] = val

				vals = list(easier_format.keys())
				wts = list([easier_format[aspl] for aspl in vals])
				aspl_arr_wtd = list(zip(vals,wts))

				x,cdf_x = get_cdf_xy(aspl_arr_wtd, weighted=True)
				cdf_aspls[k] = (x,cdf_x)
			
			x,cdf_x = get_cdf_xy(aspl_arr)
			cdf_aspls['destinations'] = (x,cdf_x)
			x,cdf_x = get_cdf_xy(list(aspls_whole_internet.values()))
			cdf_aspls['whole_internet'] = (x,cdf_x)

			# amazon
			aspl_for_amazon = aspl_by_as[self.parse_asn('16509')]
			aspl_for_amazon = list([(aspl,self.targets[t]['total']) for t,aspl in aspl_for_amazon])
			x,cdf_x = get_cdf_xy(aspl_for_amazon,weighted=True)
			cdf_aspls['amazon'] = (x,cdf_x)

			pickle.dump(cdf_aspls, open(cdf_aspl_cache_fn,'wb'))
		else:
			cdf_aspls = pickle.load(open(cdf_aspl_cache_fn, 'rb'))

		import matplotlib
		matplotlib.rcParams.update({'font.size': 18})
		import matplotlib.pyplot as plt
		f,ax = plt.subplots(1,1)
		f.set_size_inches(12,6)
		# fig, ax = plt.subplots(1, 2, figsize=(14,7))
		i = 0
		every_other = 7
		for k, lab in zip(['in', 'out', 'total','destinations','whole_internet','amazon'], 
			["In Residential Traffic", 'Out Residential Traffic', 'Total Bytes',
			'Residential Traffic Remote Hosts', "All Routable Prefixes", "Amazon"]):
			if k == 'total': continue
			x,cdf_x = cdf_aspls[k]
			ax.plot(x[::every_other],cdf_x[::every_other],label=lab,marker=MARKERSTYLES[i],
				markersize=8)
			i+=1

		# x,cdf_x = get_cdf_xy(aspl_by_as_med)
		# ax[1].plot(x,cdf_x,label="Campus Traffic Targets")

		# ## Get ASPL by AS for whole internet
		# aspl_by_as_whole_internet = {}
		# for t in aspls_whole_internet:
		# 	asn = self.parse_asn(t)
		# 	if asn is None: continue
		# 	try:
		# 		aspl_by_as_whole_internet[asn].append(aspls_whole_internet[t])
		# 	except KeyError:
		# 		aspl_by_as_whole_internet[asn] = [aspls_whole_internet[t]]
		# aspl_by_as_whole_internet_med = [np.median(as_aspls) for as_aspls in aspl_by_as_whole_internet.values()]
		# x,cdf_x = get_cdf_xy(aspl_by_as_whole_internet_med)
		# ax[1].plot(x,cdf_x,label="Whole Internet")

		ax.grid(True)
		# ax[1].grid(True)
		ax.set_xlabel("AS Path Length")
		# ax[1].set_xlabel("AS Path Length")
		ax.set_xlim([1,8])
		# ax[1].set_xlim([2,8])
		ax.set_ylabel("CDF of Destinations/Traffic")
		# ax[1].set_ylabel("CDF of ASes")
		ax.legend()
		ax.annotate("Offnet\nTraffic", (2.1,.26))
		# ax[1].legend()
		plt.savefig('figures/all_aspls_from_cu.pdf')

	def sync_results(self):
		parent_id = traceroute_meas_folder_id
		have_results = [el.split('.')[0] for el in os.listdir(MEASUREMENT_DIR)]
		gdrive = get_gdrive()
		files = get_file_list(gdrive, parent_id)


		times_of_interest = TIMES_OF_INTEREST


		for fn in tqdm.tqdm(files,desc="Downloading files from cloud."):
			dlfn = fn['originalFilename']
			if dlfn.split('.')[0] not in have_results:
				is_interesting = False or 'topips' in dlfn
				for t in times_of_interest:
					if t in dlfn:
						is_interesting = True
						break
				if not is_interesting: continue
				out_fn = os.path.join(MEASUREMENT_DIR, dlfn)
				download_file_by_id(gdrive, fn['id'], out_fn)
		for dlfn in glob.glob(os.path.join(MEASUREMENT_DIR, "*.warts")):
			out_fn = dlfn[0:-len(".warts")] + ".json"
			cmd = "sc_warts2json {}".format(dlfn)
			json_from_warts_out_str = check_output(cmd, shell=True).decode()
			meas_objs = []
			for meas_str in json_from_warts_out_str.split('\n'):
				if meas_str == "": continue
				measurement_obj = json.loads(meas_str)
				meas_objs.append(measurement_obj)

			json.dump(meas_objs, open(out_fn,'w'))
			call("rm {}".format(dlfn),shell=True)

	def next_hops_from_bgp_routes(self):
		np.random.seed(31415)
		self.load_traceroute_helpers()
		import pytricia
		as_paths_by_pref = pytricia.PyTricia()
		pref = None
		for row in tqdm.tqdm(open(os.path.join(DATA_DIR,'cu_bgp_routes.txt'),'r'),
			desc="Parsing BGP table from CU"):
			fields = [el for el in row.strip().split('  ') if el.strip() != ""]
			if "/" in row:
				pref = fields[1].strip()
				prefl = pref.split('/')[1]
			elif row.count(".") == 6:
				pref = fields[1].strip()
				if pref == "0.0.0.0": continue
				pref = pref + "/" + prefl
			if pref is None:
				continue
			if row.startswith(" *>"):
				## selected route
				as_path = fields[-1].replace('i',' ').strip().split(' ')
				parsed_as_path = ['14']
				prev_hop = None
				for el in as_path:
					el = el.replace("{","").replace("}","")
					for ell in el.split(","):
						try:
							if int(el) >= 64512 and int(el) <= 65534:
								## private IP address
								continue
						except ValueError:
							pass
						if ell == '0': continue
						if prev_hop != ell:
							parsed_as_path.append(ell)
						prev_hop = ell
				as_paths_by_pref[pref] = parsed_as_path
				if len(parsed_as_path) == 2 and parsed_as_path[-1] == '16509':
					print(row)
			else:
				continue
		all_dsts = {}
		i = 0
		for row in open(os.path.join(DATA_DIR, 'flow_info', '2024-01.tsv')):
			i +=1
			if i == 1:
				continue
			fields = row.strip().split('\t')
			try:
				all_dsts[fields[5]] = as_paths_by_pref.get(fields[5] + '/32',['','174'])[1]
			except:
				import traceback
				traceback.print_exc()
				print("ASIOJFOIASHF")
				print(fields[5])
				continue
		with open(os.path.join(CACHE_DIR,'exports','2024-01-dst_to_next_as_hop.csv'),'w') as f:
			f.write("dst_ip,first_as_hop\n")
			for dst,first_hop in all_dsts.items():
				f.write("{},{}\n".format(dst,first_hop))
			
	def get_loc_from_target_list(self):
		## Get RDNS 
		## lookup all traceroutes
		## get cities of all the hops
		## get some heuristic of mapping hopped cities to end point cities
		top_ips_dict = get_top_ips(None)
		self.load_traceroute_helpers()

		parsed_traceroutes_cache = os.path.join(CACHE_DIR, 'parsed_traceroutes.pkl')
		if not os.path.exists(parsed_traceroutes_cache):
			

			times_of_interest = TIMES_OF_INTEREST
			all_trace_files = glob.glob(os.path.join(MEASUREMENT_DIR, 'traces-*.json'))
			all_trace_files = [trace_file for trace_file in all_trace_files if any(toi in trace_file for toi in times_of_interest)]
			
			campus_traffic_destinations_trace_files = [tf for tf in all_trace_files if 'traces-all' not in tf]

			lookup_ips = []
			for result_fn in tqdm.tqdm(campus_traffic_destinations_trace_files,
				desc="Parsing result fns to see if we need to map ASNs."):
				these_results = json.load(open(result_fn,'r'))
				these_results = [result for result in these_results if result['type'] == 'trace']
				for result in these_results:
					try:
						top_ips_dict[result['dst']]
					except KeyError:
						continue
					lookup_ips.append(self.parse_ripe_trace_result(result, ret_ips=True))
			self.lookup_asns_if_needed(list(set([ip32_to_24(ip) for res_set in lookup_ips for ip in res_set])))
			all_objs = []
			for result_fn in tqdm.tqdm(campus_traffic_destinations_trace_files, 
				desc="Parsing traceroutes"):
				these_results = json.load(open(result_fn,'r'))
				these_results = [result for result in these_results if result['type'] == 'trace']
				objs = []
				for result in these_results:
					try:
						top_ips_dict[result['dst']]
					except KeyError:
						continue
					objs.append(self.parse_ripe_trace_result(result))
				all_objs = all_objs + objs
			pickle.dump(all_objs, open(parsed_traceroutes_cache, 'wb'))
		else:
			all_objs = pickle.load(open(parsed_traceroutes_cache,'rb'))
		all_objs_by_dst = {}
		for obj in all_objs:
			if obj is None: continue
			try:
				if all_objs_by_dst[obj['dst']]['time'] < obj['time']:
					all_objs_by_dst[obj['dst']] = obj	
			except KeyError:
				all_objs_by_dst[obj['dst']] = obj
		all_objs = all_objs_by_dst

		keep_dsts = get_intersection(top_ips_dict, all_objs)
		all_objs = {t: all_objs[t] for t in keep_dsts}

		total_traffic = sum(list(top_ips_dict.values()))
		pct_traffic = round(sum(top_ips_dict[t] for t in all_objs) / total_traffic * 100.0 ,2)
		print("{} pct ({}) of traceroutes, {} pct of traffic, reached a destination".format(100 * len(all_objs) / len(top_ips_dict),
			len(all_objs), pct_traffic))

		for obj in all_objs.values():
			print(obj)
			exit(0)


	def run(self):
		# self.sync_results()
		# self.parse_ping_result_set()
		# self.parse_trace_result_set()
		# self.aspl_from_bgp_routes()
		# self.next_hops_from_bgp_routes()

		self.get_loc_from_target_list()

if __name__ == "__main__":
	cma = Campus_Measurement_Analyzer()
	cma.run()

