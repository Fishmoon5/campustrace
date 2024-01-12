import numpy as np, tqdm, os, csv, pandas as pd
from constants import *
from helpers import *
import networkx as nx
from community import community_louvain

NUM_THRESHOLD = 3 # number 
TIME_THRESHOLD = 1 # second

UNIQUE_SEPARATOR_DOMAIN = "-----"



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

	def keyword_map_to_service(self, uid, verb=False):
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
		if verb:
			print("UID: {} Domain map: {} SNI map: {}".format(uid,domain_map,sni_map))
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

	def map_uid_to_service(self, uid):
		### Template function, wrapper for keyword map
		return self.keyword_map_to_service(uid)

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
				for tpart2 in tpart1.split(UNIQUE_SEPARATOR_DOMAIN):
					if tpart2 == "": continue
					try:
						token_parts[tpart2] += nb
					except KeyError:
						token_parts[tpart2] = nb
		# print(sorted(token_parts.items(), key = lambda el : el[1]))


class Cluster_Domain_Parser(Domain_Parsing):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	def compute_score(self, correlated_traffic, method='linear_manual'):
		if method == 'linear_manual':
			a = 5 # true positive multiplier
			b = 1 # true negative multiplier
			c = 1 # false positive multiplier
			d = 15 # false negative multiplier
			correlated_traffic.columns = ['dns_name', 'next_dns', 'both_appear', 'dns_appear_next_not',
				'next_appear_dns_not', 'both_not', 'both_appear(%)', 'dns_appear_next_not(%)', 'next_appear_dns_not(%)', 'both_not(%)']
			scored_correlated_traffic = correlated_traffic[['dns_name', 'next_dns', 'both_appear', 'both_appear(%)', 'dns_appear_next_not', 
				'dns_appear_next_not(%)', 'next_appear_dns_not', 'next_appear_dns_not(%)', 'both_not', 'both_not(%)']]


			scored_correlated_traffic[['TP', 'TN', 'FP', 'FN']] = scored_correlated_traffic[['both_appear(%)', 'both_not(%)', 'dns_appear_next_not(%)', 'next_appear_dns_not(%)']]

			# Calculate the score for each row as the sum of these four normalized features
			scored_correlated_traffic['score'] = a * scored_correlated_traffic['TP'] + b * scored_correlated_traffic['TN'] - c * scored_correlated_traffic['FP'] - d * scored_correlated_traffic['FN']

			scored_correlated_traffic['score'] = scored_correlated_traffic['score'].clip(-50, 50)
			scored_correlated_traffic['score'] = scored_correlated_traffic['score'] + 50
			scored_correlated_traffic.loc[(scored_correlated_traffic['TP'] < 0.1) & (scored_correlated_traffic['FN'] > 0.1), 'score'] = 0
			scored_correlated_traffic.loc[scored_correlated_traffic['both_appear'] < 5, 'score'] = 0
		else:
			raise ValueError("Method {} for computing score not yet implemented".format(method))

		return scored_correlated_traffic

	def find_correlated_traffic(self, threshold, time_interval):
		### Threshold is number of times you have to see a pair of DNS names
		### time interval specifies how long between the flow starting times is permissible to consider them "correlated"

		# Sort by user and start time
		df = self.all_flows.sort_values(by=['unit_ip', 'frame_time'])
		
		# Group by user and create pairs of consecutive visited dns names
		df['next_dns'] = df.groupby('unit_ip')['dns_name'].shift(-1)
		df['next_frame_time'] = df.groupby('unit_ip')['frame_time'].shift(-1)
		
		# Calculate the time difference between the current and next visit in seconds
		df['time_diff'] = df['next_frame_time'] - df['frame_time_end']
		
		# Filter the rows where 'time_diff' is less than or equal to the time threshold
		df_within_threshold = df[(df['time_diff'] <= time_interval) & (df['time_diff'] >= 0)]
		
		
		df = df.loc[(df['dns_name'] != df['next_dns']) & (df['time_diff'] <= time_interval) & (df['time_diff'] >= 0)]

		df.dropna(subset=['next_dns'], inplace=True)

		# Count how often each pair occurs
		pair_counts = df.groupby(['dns_name', 'next_dns']).size().reset_index(name='count')

		# Filter pairs that occur more than the threshold
		frequent_pairs = pair_counts[pair_counts['count'] >= threshold].copy()
		
		# Calculate the total occurrences of 'dns_name' and 'next_dns'
		total_occurrences_dns = df_within_threshold.groupby('dns_name').size()
		total_occurrences_next = df_within_threshold.groupby('next_dns').size()

		# Map the total occurrences onto 'frequent_pairs'
		frequent_pairs['total_occurrences_dns'] = frequent_pairs['dns_name'].map(total_occurrences_dns.to_dict()).fillna(0)
		frequent_pairs['total_occurrences_next'] = frequent_pairs['next_dns'].map(total_occurrences_next.to_dict()).fillna(0)

		frequent_pairs['freq_dns_appear_next_not'] = frequent_pairs['total_occurrences_dns'] - frequent_pairs['count']
		frequent_pairs['freq_next_appear_dns_not'] = frequent_pairs['total_occurrences_next'] - frequent_pairs['count']

		# Generate all pairs
		pairs = df_within_threshold[['dns_name', 'next_dns']]

		# Count the number of pairs
		num_pairs = len(pairs)
		
		frequent_pairs['num_dns_not_appear'] = num_pairs - frequent_pairs['total_occurrences_dns']
		frequent_pairs['count_pair_not_occur'] = frequent_pairs['num_dns_not_appear'] - frequent_pairs['freq_next_appear_dns_not']

		# Calculate the desired percentages
		frequent_pairs['count_percentage'] = frequent_pairs['count'] / frequent_pairs['total_occurrences_dns'] * 100
		frequent_pairs['freq_dns_appear_next_not_percentage'] = frequent_pairs['freq_dns_appear_next_not'] / frequent_pairs['total_occurrences_dns'] * 100
		frequent_pairs['freq_next_appear_dns_not_percentage'] = frequent_pairs['freq_next_appear_dns_not'] / frequent_pairs['num_dns_not_appear'] * 100
		frequent_pairs['count_pair_not_occur_percentage'] = frequent_pairs['count_pair_not_occur'] / frequent_pairs['num_dns_not_appear'] * 100

		# Drop the total count columns
		frequent_pairs.drop(columns=['total_occurrences_dns', 'total_occurrences_next', 'num_dns_not_appear'], inplace=True)

		return frequent_pairs
	
	def parse_raw_flow_data(self, outfn):
		# idk when final_flow_info is from. I think April
		fs_to_read = list([os.path.join(DATA_DIR, fn) for fn in ['final_flow_info.csv', 'March23_flow_info_1.csv', 'March23_flow_info_2.csv']])
		with open(outfn, 'w') as outf:
			outf.write("id,frame_time,frame_time_end,unit_ip,nbytes,dns_name\n")
			for f in fs_to_read:
				i=0
				for row in tqdm.tqdm(open(f,'r'), desc="Reading file : {}".format(f)):
					if i ==0:
						i+=1 
						continue
					fields = row.strip().split(',')
					if len(fields) == 13:
						uid,ts,te,unit_ip,ip,nbytes,dns_name,_,sni,_,_,_,_ = fields
					else:
						uid,ts,te,unit_ip,ip,nbytes,dns_name,_,sni,_ = fields
					if dns_name == "" and sni == "": continue
					dns_out = dns_name + UNIQUE_SEPARATOR_DOMAIN + sni

					outf.write("{},{},{},{},{},{}\n".format(uid,ts,te,unit_ip,nbytes,dns_out))

	def lookup_cluster(self, uid):
		service = self.uid_to_service_mapping.get(uid)
		if service is None:
			return self.keyword_map_to_service(uid)
		info = {'ignore': False}

		info['service'] = service
		info['used_field'] = 'cluster'
		info['mapped_to_service'] = True

		return info

	def map_uid_to_service(self, uid):
		try:
			return self.lookup_cluster(uid)
		except AttributeError:
			pass # need to load everything
		print("Loading cluster information...")
		cluster_service_mapping_cache_fn = os.path.join(CACHE_DIR, 'cluster_domain_to_service_mapping.csv')
		if not os.path.exists(cluster_service_mapping_cache_fn):
			print("Clustered information not yet computed, computing correlations, scores, and clusters...")
			print("(May take a minute or two)")
			correlated_traffic_cache_fn = os.path.join(CACHE_DIR, "correlated_traffic_{}_{}.csv".format(NUM_THRESHOLD, TIME_THRESHOLD))
			domain_to_nbytes_fn = os.path.join(CACHE_DIR, "domain_to_nbytes.csv")
			if not os.path.exists(correlated_traffic_cache_fn):
				### 73M flows total
				all_flows_fn = os.path.join(DATA_DIR, 'combine_data_service.csv')
				if not os.path.exists(all_flows_fn):
					self.parse_raw_flow_data(all_flows_fn)
				self.all_flows = pd.read_csv(all_flows_fn)#, nrows=10000000)
				self.domain_to_nbytes = self.all_flows[['dns_name','nbytes']].groupby('dns_name').sum()
				self.domain_to_nbytes.to_csv(domain_to_nbytes_fn)
				correlated_traffic = self.find_correlated_traffic(NUM_THRESHOLD, TIME_THRESHOLD)
				scored_correlated_traffic = self.compute_score(correlated_traffic)
				scored_correlated_traffic.to_csv(correlated_traffic_cache_fn, index=False)
			drcsv = csv.DictReader(open(correlated_traffic_cache_fn, 'r'))
			self.scored_correlated_traffic = {}
			for row in drcsv:
				self.scored_correlated_traffic[tuple(row['dns_name'].split(UNIQUE_SEPARATOR_DOMAIN)), tuple(row['next_dns'].split(UNIQUE_SEPARATOR_DOMAIN))] = {'score': float(row['score'])}
			self.domain_to_nbytes = {}
			for row in open(domain_to_nbytes_fn, 'r'):
				if row.startswith('dns_name'): continue
				domain,nbytes = row.strip().split(',')
				self.domain_to_nbytes[tuple(domain.split(UNIQUE_SEPARATOR_DOMAIN))] = float(nbytes)

			self.cluster_domains(self.scored_correlated_traffic)

			with open(cluster_service_mapping_cache_fn, 'w') as f:
				for uid, service in self.uid_to_service_mapping.items():
					f.write("{},{}\n".format(UNIQUE_SEPARATOR_DOMAIN.join(uid),service))
		else:
			self.uid_to_service_mapping = {}
			for row in open(cluster_service_mapping_cache_fn, 'r'):
				uidstr,service = row.strip().split(',')
				self.uid_to_service_mapping[tuple(uidstr.split(UNIQUE_SEPARATOR_DOMAIN))] = service

		return self.lookup_cluster(uid)

	def summarize_cluster_scores(self, domain_scores, clusters, cid):
		### Look at items in a cluster --- what are their pairwise scores with each other?
		cluster_of_interest = clusters[cid]
		all_pairwise_scores = {(domainx,domainy): domain_scores.get((domainx,domainy), {'score':0})['score'] for domainx in cluster_of_interest for domainy in cluster_of_interest}

		sorted_pairwise_scores = sorted(all_pairwise_scores.items(), key = lambda el : -1 * el[1])

		for k,v in sorted_pairwise_scores[0:100]:
			print("{}, {} -- {}".format(k[0],k[1], round(v,2)))
		exit(0)

	def cluster_domains(self, domain_scores):
		for resolution in [10]:#[.0001,.0001,.001,.01,.1,1,10]:
			print("Resolution: {}".format(resolution))
			G = nx.Graph()
			# Create the weighted graph
			G.add_edges_from([(k1,k2,{'score':v['score']}) for (k1,k2),v in domain_scores.items()])
			# Use the Louvain method for community detection
			partition = community_louvain.best_partition(G, resolution=resolution, weight='score')

			# Print clusters
			clusters = {}
			for node, cluster_id in partition.items():
				try:
					clusters[cluster_id]
				except KeyError:
					clusters[cluster_id] = []
				clusters[cluster_id].append(node)
			print("Mean cluster length: {} ".format(np.mean([len(v) for v in clusters.values()])))

			cluster_id_to_service_pct, cluster_id_to_known_service_pct, cluster_to_volume, cluster_to_known_service_volume = {}, {}, {}, {}
				
			max_service, max_known_service = {}, {}
			for cluster_id, domains in clusters.items():
				total_bytes_this_cluster = sum(self.domain_to_nbytes[domain] for domain in domains)
				cluster_to_volume[cluster_id] = total_bytes_this_cluster
				total_bytes_known_service_this_cluster = sum(self.domain_to_nbytes[domain] for domain in domains if self.keyword_map_to_service(domain)['mapped_to_service'])
				cluster_to_known_service_volume[cluster_id] = total_bytes_known_service_this_cluster
				cluster_id_to_service_pct[cluster_id] = {'NO_SERVICE': (total_bytes_this_cluster - total_bytes_known_service_this_cluster) / total_bytes_this_cluster}
				cluster_id_to_known_service_pct[cluster_id] = {}
				if total_bytes_known_service_this_cluster == 0: continue
				for domain in domains:
					serviceinfo = self.keyword_map_to_service(domain)
					if not serviceinfo['mapped_to_service']:
						continue
					service = serviceinfo['service']
					try:
						cluster_id_to_service_pct[cluster_id][service] += (self.domain_to_nbytes[domain] / total_bytes_this_cluster)
					except KeyError:
						cluster_id_to_service_pct[cluster_id][service] = (self.domain_to_nbytes[domain] / total_bytes_this_cluster)
					try:
						cluster_id_to_known_service_pct[cluster_id][service] += (self.domain_to_nbytes[domain] / total_bytes_known_service_this_cluster)
					except KeyError:
						cluster_id_to_known_service_pct[cluster_id][service] = (self.domain_to_nbytes[domain] / total_bytes_known_service_this_cluster)

				# print(cluster_id_to_service_pct[cluster_id])
				for (service, n) in sorted(cluster_id_to_service_pct[cluster_id].items(), key = lambda el : -1 * el[1]):
					try:
						max_service[cluster_id]
					except KeyError:
						max_service[cluster_id] = service
					try:
						max_known_service[cluster_id]
					except KeyError:
						if service != 'NO_SERVICE':
							max_known_service[cluster_id] = service
							break
				# print("{} {} ".format(max_service[cluster_id], max_known_service[cluster_id]))



			total_volume_all_clusters = sum(list(cluster_to_volume.values()))
			total_known_service_volume_all_clusters = sum(list(cluster_to_known_service_volume.values()))

			important_clusters = sorted(cluster_to_volume.items(), key = lambda el : -1 * el[1])
			i=0
			for cid,v in important_clusters[0:40]:
				i += 1
				if max(list(cluster_id_to_known_service_pct[cid].values())) < .8: 

					print("{}th largetst, {} -- {}".format(i, round(v/total_volume_all_clusters,2), clusters[cid]))
					print(cluster_id_to_service_pct[cid])
					# self.summarize_cluster_scores(domain_scores, clusters, cid)
			# 		if np.random.random() > .9:
			# 			exit(0)
				print("\n\n")
			# exit(0)
			

			### Additional things from service mapping
			self.uid_to_service_mapping = {}
			acceptable_confidence = .6 ### above this confidence we map unmapped domains to services


			threshold_values = np.linspace(0,.999)
			tprs, fprs, coverages, precisions, paper_coverages = [], [], [], [], []
			for threshold_value in threshold_values:
				## Get ROC curve, coverage, precision
				total_tpr, total_fpr, total_coverage, total_precision, total_paper_coverage = 0, 0, 0, 0, 0

				classified_volume = 0
				# print(threshold_value)
				for cluster_id in cluster_id_to_service_pct:
					best_service = max_known_service.get(cluster_id, None)
					if best_service is None:
						continue
					conf = cluster_id_to_known_service_pct[cluster_id][best_service]
					not_best_conf = 1 - conf

					### in the paper, we'd map keywords to services and then non-keywords to their best cluster
					### so emulate that here
					## we add known services regardless of threshold
					## unknwon services given the threshold
					total_paper_coverage += cluster_to_known_service_volume[cluster_id] ### Include unknown services


					# if threshold low, this always clicks
					if conf > threshold_value:
						## everything in this cluster is of type "best_service"
						total_coverage += cluster_to_volume[cluster_id] ### Include unknown services
						total_paper_coverage += (cluster_to_volume[cluster_id] - cluster_to_known_service_volume[cluster_id]) ### Include unknown services
						total_precision += conf * cluster_to_known_service_volume[cluster_id] ## exclude unknown services
						classified_volume += cluster_to_known_service_volume[cluster_id]

						if threshold_value >= acceptable_confidence:
							for uid in clusters[cluster_id]:
								info = self.keyword_map_to_service(uid)
								if not info['mapped_to_service']:
									self.uid_to_service_mapping[uid] = best_service
									# if self.domain_to_nbytes[uid] > 1e6:
									# 	print("uid {} ({} MB) now mapped to {}, cluster weight: {}".format(uid, round(self.domain_to_nbytes[uid]/1e6),
									# 		best_service, 
									# 		cluster_id_to_known_service_pct[cluster_id]))
									# 	if np.random.random() > .999:exit(0)
								# else:
								# 	print("uid {} already mapped to {}, skipping".format(uid, info['service']))


						tp = conf ### we got conf percent correct
						tn = 0 ### we're not saying anything is negative
						fp = not_best_conf ### we misclassify this percent
						fn = 0 ### 
					else:
						tp = 0
						tn = not_best_conf
						fp = 0
						fn = conf
					if tp > 0:
						total_tpr += (tp / (tp + fn) * cluster_to_known_service_volume[cluster_id])
					if fp > 0:
						total_fpr += (fp / (fp + tn) * cluster_to_known_service_volume[cluster_id])
					
				total_tpr /= total_known_service_volume_all_clusters
				total_fpr /= total_known_service_volume_all_clusters
				tprs.append(total_tpr)
				fprs.append(total_fpr)
				
				coverages.append(total_coverage / total_volume_all_clusters)
				paper_coverages.append(total_paper_coverage / total_volume_all_clusters)
				if classified_volume > 0:
					precisions.append(total_precision / classified_volume)
				else:
					precisions.append(0)

			import matplotlib.pyplot as plt 
			plt.plot(fprs,tprs)
			plt.xlabel("False Positive Rate")
			plt.ylabel("True Positive Rate")
			plt.grid(True)
			plt.xlim([0,1])
			plt.ylim([0,1])
			plt.savefig('figures/cluster_roc_{}.pdf'.format(resolution))
			plt.clf(); plt.close()

			fig, ax1 = plt.subplots(figsize=(10, 6))
			color = 'tab:red'
			ax1.set_xlabel('Confidence Parameter')
			ax1.set_ylabel('Coverage (fraction of traffic volume)', color=color)
			# ax1.plot(threshold_values, coverages, color=color, label="Pure Cluster")
			ax1.plot(threshold_values, paper_coverages, color=color, label="Paper Algorithm", marker='.')
			ax1.grid(True)
			# ax1.legend()
			ax1.tick_params(axis='y', labelcolor=color)
			ax1.set_ylim([0,1])

			ax2 = ax1.twinx()
			color = 'tab:blue'
			ax2.set_ylabel('Precision of Pure Cluster', color=color)
			ax2.plot(threshold_values, precisions, color=color)
			ax2.tick_params(axis='y', labelcolor=color)
			ax2.set_ylim([0,1])
			fig.tight_layout()
			plt.savefig('figures/coverage_vs_precision_clustering_{}.pdf'.format(resolution))


if __name__ == "__main__":
	dm = Cluster_Domain_Parser()
	print(dm.map_uid_to_service(('fe.apple-dns.net', 'p67-sharedstreams.icloud.com')))
	print(dm.map_hr_str_to_keyword('p67-sharedstreams.icloud.com'))
	print(dm.map_uid_to_service(('cdn2.onlyfans.com', 'cdn2.onlyfans.com')))
