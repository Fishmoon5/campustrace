import os,glob,numpy as np, json, tqdm, csv, pytricia, gzip, matplotlib.pyplot as plt
from vasilis_traceroute import Traceroute
from helpers import *
from constants import *
from google_utilities import *


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

		self.msft_org = self.as_siblings['8075']

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
		# https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/2022/02/
		routeviews_pref_to_as_fn = os.path.join(DATA_DIR, "routeviews-rv2-20220216-1200.pfx2as.gz")
		with gzip.open(routeviews_pref_to_as_fn) as f:
			for row in f:
				pref,l,asn = row.decode().strip().split('\t')
				asns = asn.split(",")
				for asn in asns:
					asn = self.parse_asn(asn)
					try:
						self.routeviews_asn_to_pref[asn].append(pref + "/" + l)
					except KeyError:
						self.routeviews_asn_to_pref[asn] = [pref + "/" + l]
					self.routeviews_pref_to_asn[pref] = asn

		self.routeviews_pref_to_asn['199.109.0.0/16'] = self.parse_asn(3754)

	def load_traceroute_helpers(self):
		# Traceroute parsing helper class from Vasilis Giotsas
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
				dont_know.append(pref)
		if dont_know == []: return
		ret = lookup_asn(dont_know)
		for k,v in ret.items():
			self.ip_to_asn[k] = v
		self.save_ip_to_asn()	

	def parse_ripe_trace_result(self, result, ret_ips=False):
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

		targ_to_rtt =  {}

		times_of_interest = ['1683686967']
		all_ping_files = glob.glob(os.path.join(MEASUREMENT_DIR, 'pings-*.json'))
		all_ping_files = [ping_file for ping_file in all_ping_files if any(toi in ping_file for toi in times_of_interest)]

		for result_fn in tqdm.tqdm(all_ping_files,
			desc="Parsing RTT measurements."):
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
		pickle.dump(targ_to_rtt, open(os.path.join(CACHE_DIR, 'rtts.pkl'),'wb'))

	def parse_trace_result_set(self):
		self.load_target_data()
		all_data_cache_fn = os.path.join(CACHE_DIR, 'aspls_all_objs.pkl')
		if not os.path.exists(all_data_cache_fn):
			self.load_traceroute_helpers()

			times_of_interest = ['1683684069']
			all_trace_files = glob.glob(os.path.join(MEASUREMENT_DIR, 'traces-*.json'))
			all_trace_files = [trace_file for trace_file in all_trace_files if any(toi in trace_file for toi in times_of_interest)]
			
			lookup_ips = []
			for result_fn in tqdm.tqdm(all_trace_files,
				desc="Parsing result fns to see if we need to map ASNs."):
				these_results = json.load(open(result_fn,'r'))
				these_results = [result for result in these_results if result['type'] == 'trace']
				lookup_ips = lookup_ips + [el for result in these_results for el in 
					self.parse_ripe_trace_result(result,ret_ips=True) ]
			self.lookup_asns_if_needed(list(set([ip32_to_24(ip) for ip in lookup_ips])))
			all_objs = []
			for result_fn in tqdm.tqdm(all_trace_files, 
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
			# for asp, aspl, obj in zip(asps, aspls, all_objs):
			# 	if aspl == 1:
			# 		print("1 ! {} {}".format(asp,obj['ip_paths']))
			# 	elif aspl == 2:
			# 		print("2!!!! {} {}".format(asp,obj['ip_paths']))

			pickle.dump([asps, aspls, all_objs], open(all_data_cache_fn,'wb'))
			pickle.dump(aspls, open(os.path.join(CACHE_DIR, 'aspls.pkl'),'wb'))
		else:
			asps, aspls, all_objs = pickle.load(open(all_data_cache_fn, 'rb'))

		second_hops = {}
		first_hop = '14'
		for dst,asp in asps.items():
			for hop in asp:
				if hop != first_hop:
					try:
						second_hops[hop] += 1
					except KeyError:
						second_hops[hop] = 1 
					break
		sorted_second_hops = sorted(second_hops.items(),  key = lambda el : -1 * el[1])
		top_second_hops = sorted_second_hops[0:20]
		top_second_hop_ases = [el[0] for el in sorted_second_hops[0:20]]
		print("Top second hop ASes: {}".format(top_second_hops))
		for dst,asp in asps.items():
			for hop in asp:
				if hop != first_hop:
					if hop in top_second_hop_ases and hop not in ['174','3257', '16509','3754','40627']:
						print("{} {}".format(hop,first_hop))
						print("{} {} {}".format(dst,asp,all_objs[dst]))
					break
		targs_of_interest = list(get_intersection(aspls,self.targets))

		aspl_arr = [aspls[targ] for targ in targs_of_interest]
		for k, lab in zip(['in', 'out', 'total'], 
			['In Bytes', 'Out Bytes', "Total Bytes"]):
			wts = [self.targets[targ][k] for targ in targs_of_interest]
			aspl_arr_wtd = list(zip(aspl_arr,wts))
			aspl_arr_wtd_with_targs = list(zip(aspl_arr,wts,targs_of_interest))

			sorted_arr = sorted(aspl_arr_wtd_with_targs, key = lambda el : -1 * el[1])
			print(lab)
			print(sorted_arr[0:30])

			x,cdf_x = get_cdf_xy(aspl_arr_wtd, weighted=True)
			plt.plot(x,cdf_x,label=lab)
		x,cdf_x = get_cdf_xy(aspl_arr)
		plt.plot(x,cdf_x,label='Destinations')
		plt.grid(True)
		plt.xlabel("AS Path Length")
		plt.ylabel("CDF of Destinations/Traffic")
		plt.legend()
		plt.savefig('figures/all_aspls.pdf')

	def sync_results(self):
		parent_id = traceroute_meas_folder_id
		have_results = os.listdir(MEASUREMENT_DIR)
		gdrive = get_gdrive()
		files = get_file_list(gdrive, parent_id)
		for fn in tqdm.tqdm(files,desc="Downloading files from cloud."):
			if fn['originalFilename'] not in have_results:
				out_fn = os.path.join(MEASUREMENT_DIR, fn['originalFilename'])
				download_file_by_id(gdrive, fn['id'], out_fn)

	def run(self):
		self.sync_results()
		self.parse_ping_result_set()
		self.parse_trace_result_set()


if __name__ == "__main__":
	cma = Campus_Measurement_Analyzer()
	cma.run()

