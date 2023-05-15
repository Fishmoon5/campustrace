from constants import *
from helpers import *
import os, numpy as np,tqdm
import matplotlib.pyplot as plt
from domain_metrics import *

class Domain_Analyzer():
	def __init__(self):
		self.dont_map_keywords = ['googleapi']
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

	def map_domain_to_keyword(self, domain):
		# todo -- incorporate priorities
		for dmk in self.dont_map_keywords:
			if dmk in domain: return None
		for priority in self.valid_priorities:
			for kw,prio in self.keywords.items():
				if prio != priority: continue
				if kw in domain:
					return kw
		return None

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

	def compare_building_domains(self, metric, **kwargs):
		domain_bytes_by_building = {}
		for row in open(os.path.join(DATA_DIR, 'topdomains_buildingip_inbytes_outbytes.txt'),'r'):
			domain,building,inb,outb = row.strip().split(',')
			try:
				domain_bytes_by_building[building]
			except KeyError:
				domain_bytes_by_building[building] = {}

			try:
				domain_bytes_by_building[building][domain] += int(inb)
			except KeyError:
				domain_bytes_by_building[building][domain] = int(inb)

		print("{} buildings in Shuyue's data".format(len(domain_bytes_by_building)))
		service_bytes_by_building = {building: {} for building in domain_bytes_by_building}
		for building in domain_bytes_by_building:
			for domain,nb in domain_bytes_by_building[building].items():
				kw = self.map_domain_to_keyword(domain)
				if kw is None:
					service = domain.split('.')[-2]
				else:
					service = self.keyword_to_service[kw]
				try:
					service_bytes_by_building[building][service] += nb
				except KeyError:
					service_bytes_by_building[building][service] = nb

		all_services = list(set(service for building,services in service_bytes_by_building.items()
			 for service in services))
		service_to_i = {service:i for i,service in enumerate(all_services)}


		all_building_subnets = [
			"160.39.40.128", "160.39.41.128", "160.39.61.128", "160.39.61.0", "160.39.62.192", "160.39.62.128", "160.39.62.0", "160.39.63.128", "160.39.63.64", "160.39.63.0", # grad students
		    "160.39.2.0", # undergraduate students in the School of General Studie
		    "160.39.41.0", "160.39.56.128", "160.39.59.0", # students, faculty and staff
		    "128.59.122.128", "160.39.21.128", "160.39.22.0", "160.39.38.128", # postdocs, faculty and staff
		    "160.39.22.128" # faculty and staff
		]
		ncats,cats = [10,1,3,4,1],['grad','stud','studfacstaff','pdocsfacstaff','facstaff']
		cats = [c for i,c in enumerate(cats) for n in range(ncats[i]) ]
		building_subnets = [b for b in all_building_subnets if b in service_bytes_by_building]
		cats = [c for c,b in zip(cats,all_building_subnets) if b in service_bytes_by_building]
		print(cats)


		in_order_dividers = {
			'building': building_subnets,
			'category': ['grad','studfacstaff','pdocsfacstaff','facstaff']
		}

		## aggregate to pseudo buildings, with each category being a building
		service_bytes_by_category = {}
		for bsnet,cat in zip(building_subnets,cats):
			try:
				service_bytes_by_category[cat]
			except KeyError:
				service_bytes_by_category[cat] = {}

			for service,nb in service_bytes_by_building[bsnet].items():
				try:
					service_bytes_by_category[cat][service] += nb
				except KeyError:
					service_bytes_by_category[cat][service] = nb

		for service_bytes_by_divider,divider_type in zip([service_bytes_by_building,service_bytes_by_category], 
				['building','category']):
			print("\n\n-----DIVIDING BY TYPE {}------".format(divider_type))


			divider_to_i = {divider:i for i,divider in enumerate(in_order_dividers[divider_type])}
			for divider in list(service_bytes_by_divider):
				services = list(service_bytes_by_divider[divider])
				for not_inc_service in get_difference(all_services,services):
					service_bytes_by_divider[divider][not_inc_service] = 0

			n_dividers = len(service_bytes_by_divider)

			domains_arr = np.zeros((n_dividers, len(all_services)))
			for divider,services in service_bytes_by_divider.items():
				ranked_services = {service:j for j,(service,nb) in enumerate(sorted(services.items(),
					key = lambda el : -1 * el))}
				for service,nb in services.items():
					domains_arr[divider_to_i[divider],service_to_i[service]] = nb
					# domains_arr[divider_to_i[divider],service_to_i[service]] = np.log10(nb + .00001)
					# domains_arr[divider_to_i[divider],service_to_i[service]] = ranked_services[service]
			
			traffic_by_service = np.sum(domains_arr,axis=0)
			global_domain_traffic = np.sort(traffic_by_service)[::-1]
			ttl_traffic = np.sum(global_domain_traffic)
			global_domain_traffic = global_domain_traffic / ttl_traffic
			global_domain_traffic_dict = {i:traffic_by_service[i] / ttl_traffic for i in range(len(traffic_by_service))}
			kwargs['global_domain_traffic'] = global_domain_traffic
			kwargs['global_domain_traffic_dict'] = global_domain_traffic_dict

			nb_by_divider = np.sum(domains_arr,axis=1)
			domains_arr = domains_arr / nb_by_divider.reshape((-1,1))
			nb_by_divider = nb_by_divider / np.max(nb_by_divider.flatten())



			if divider_type == 'building':
				interesting_prints = [4,5,6,14,15,16]
			else:
				interesting_prints = list(range(n_dividers))

			# for divideri in interesting_prints:
			# 	max_n = np.max(domains_arr[divideri,:])
			# 	print("Divider {}".format(divideri))
			# 	for i in np.argsort(domains_arr[divideri,:])[::-1][0:15]:
			# 		print("{} -- {} {}".format(i,all_services[i],round(domains_arr[divideri,i]*100.0/max_n,4)))


			fig, axs = plt.subplots(n_dividers, n_dividers, figsize=(10, 10))
			dist_mat = np.zeros((n_dividers,n_dividers))
			from sympy.combinatorics.permutations import Permutation
			for divideri in tqdm.tqdm(range(n_dividers),desc="Calculating distances..."):
				for dividerj in range(n_dividers):
					if dividerj>divideri: break
					
					d = metric(domains_arr[divideri,:], domains_arr[dividerj,:], **kwargs)

					dist_mat[divideri,dividerj] = d
					dist_mat[dividerj,divideri] = d

			dist_mat = dist_mat - np.min(dist_mat.flatten())
			dist_mat = dist_mat / np.max(dist_mat.flatten())

			dmat_sum = np.sum(dist_mat, axis=0)
			for divideri in np.argsort(dmat_sum):
				for dividerj in np.argsort(dmat_sum):
					axs[divideri, dividerj].imshow(np.array([[dist_mat[divideri,dividerj]]]), 
						cmap='coolwarm', vmin=0, vmax=1)
					# axs[divideri, dividerj].axis('off')
					axs[divideri, dividerj].set_xticks([])
					axs[divideri, dividerj].set_yticks([])
					axs[divideri, dividerj].set_aspect('equal')

			def divideri_to_lab(divideri):
				if divider_type == 'building':
					return cats[divideri]
				else:
					return in_order_dividers['category'][divideri]

			print(np.argsort(dmat_sum))
			for i,divideri in enumerate(np.argsort(dmat_sum)):
				axs[0,i].set_title(divideri_to_lab(divideri), rotation=45)
			for i,divideri in enumerate(np.argsort(dmat_sum)):
				axs[i,0].set_ylabel(divideri_to_lab(divideri), rotation=45)

			# print(dist_mat.round(2))
			# Add colorbar
			norm = plt.Normalize(0, 1)
			cmap = plt.get_cmap('coolwarm')
			cax = fig.add_axes([0.91, 0.1, 0.02, 0.8])
			cb = fig.colorbar(plt.cm.ScalarMappable(norm=norm, cmap=cmap), cax=cax)
			cb.ax.set_ylabel(kwargs.get('axis_lab'), fontsize=20)
			fig.subplots_adjust(right=.85)
			
			# Adjust spacing and show plot
			# fig.text(0.5, 0.05, 'Differences between top %d owners in dividers'%(ntop), ha='center', fontsize=12)
			# fig.text(0.07, 0.5, 'Differences between top %d owners in dividers'%(ntop), va='center', rotation='vertical', fontsize=12)
			plt.subplots_adjust(wspace=0, hspace=0)
			# plt.show()
			plt.savefig('figures/similarities_across_{}-{}.pdf'.format(
				divider_type, kwargs.get('plt_lab','')))
			plt.clf(); plt.close()




if __name__ == "__main__":
	da = Domain_Analyzer()
	da.create_domain_keywords()
	metrics = [rbo_wrap,spearman, cosine_similarity, weighted_jaccard, jaccard, euclidean]
	labs = ['rbo','spearman', 'cos_sim', 'wjac', 'jac', 'euclidean']
	ax_labs = ['Rank-Biased Overlap', 'Spearman Correlation', 'Cosine Similarity',
		'Weighted Jaccard Index', 'Jaccard Index', 'Euclidean Distance']
	for metric,lab,axis_lab in zip(metrics,labs,ax_labs):
		print("\n\n\nCOMPUTING METRIC {}\n\n\n".format(lab))
		da.compare_building_domains(metric, n_doms=1000, plt_lab=lab, axis_lab=axis_lab)


