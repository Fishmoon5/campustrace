from constants import *
from helpers import *
import os, numpy as np,tqdm, random
from domain_metrics import *
from service_mapping import Service_Mapper



class Service_Demographic_Comparison():
	def __init__(self):
		pass

	def temporal_representativity(self):
		np.random.seed(31415)
		plt_cache_fn = os.path.join(CACHE_DIR, 'temporal_representativity_plot_cache.pkl')
		if not os.path.exists(plt_cache_fn):
			self.setup_service_by_hour_data()
			self.service_bytes_by_divider = self.service_bytes_by_hour
			self.get_dist_mat('hour', euclidean )


			nunits = len(self.service_bytes_by_divider)
			print("{} dividers total".format(nunits))
			units = list(self.service_bytes_by_divider)

			### Q: let x = global service average
			## how does err(mean[included_set] - x) vary as we include more in the set?

			nsim_atmost = 15
			errs_over_n_sim = {}
			global_average = np.mean(self.domains_arr,axis=0).reshape(1,-1)

			for nuniti in tqdm.tqdm(range(1,nunits),
				desc="Predicting hours from hours."):
				these_errs = []
				allunits = np.arange(nunits)
				sampled_already = {}

				for iteri in range(nsim_atmost):
					success = False
					while not success:
						unitset = sorted(random.sample(list(allunits), nuniti))
						try:
							sampled_already[tuple(unitset)]
						except KeyError:
							sampled_already[tuple(unitset)] = True
							success = True

					notunitset = get_difference(allunits, unitset)

					pred = np.mean(self.domains_arr[np.array(unitset),:],axis=0).reshape(1,-1)
					# errs = self.domains_arr[np.array(notunitset),:] - pred
					# total_err = np.sum(np.abs(errs.flatten())) / len(notunitset)
					# errs = pred - global_average
					# total_err = np.sum(np.abs(errs.flatten()))
					total_err = 1 - pdf_distance(pred,global_average)
					these_errs.append(total_err)
				errs_over_n_sim[nuniti] = these_errs
			pickle.dump({
				'errs_over_n_sim': errs_over_n_sim,
				'nunits':nunits,
				}, open(plt_cache_fn,'wb'))
		else:
			d = pickle.load(open(plt_cache_fn,'rb'))
			errs_over_n_sim = d['errs_over_n_sim']
			nunits = d['nunits']


		plt_arr = {k: np.zeros(nunits-1) for k in ['min','med','max', 'std']}
		for nuniti in range(1,nunits):
			## min, med, max
			plt_arr['min'][nuniti-1] = np.min(errs_over_n_sim[nuniti])
			plt_arr['med'][nuniti-1] = np.median(errs_over_n_sim[nuniti])
			plt_arr['max'][nuniti-1] = np.max(errs_over_n_sim[nuniti])
			plt_arr['std'][nuniti-1] = np.sqrt(np.var(errs_over_n_sim[nuniti]))

		overall_max = np.max(plt_arr['max'])

		import matplotlib
		matplotlib.rcParams.update({'font.size': 18})
		import matplotlib.pyplot as plt
		f,ax = plt.subplots(1,1)
		f.set_size_inches(12,6)
		ax.plot(np.arange(1,nunits), plt_arr['med']/overall_max)
		ax.fill_between(np.arange(1,nunits), (plt_arr['med'] - plt_arr['std'])/overall_max,
			(plt_arr['med'] + plt_arr['std']) / overall_max, alpha=.3, color='red')
		ax.grid(True)
		ax.set_xlabel("Number of Hours for Comparison",fontsize=20)
		ax.set_ylabel("Normalized Median Comparison Error",fontsize=20)
		ax.set_ylim([0,1.0])
		plt.savefig("figures/hour_representativeness.pdf")

	def unit_representativity(self):
		np.random.seed(31415)
		plt_cache_fn = os.path.join(CACHE_DIR, 'unit_representativity_plot_cache.pkl')
		if not os.path.exists(plt_cache_fn):
			# self.setup_service_by_unit_data()
			self.setup_service_data()
			self.service_bytes_by_divider = self.service_bytes_by_building
			self.get_dist_mat('building', euclidean )


			nunits = len(self.service_bytes_by_divider)
			units = list(self.service_bytes_by_divider)

			### Q: let x = global service average
			## how does err(mean[included_set] - x) vary as we include more in the set?

			nsim_atmost = 15
			errs_over_n_sim = {}
			global_average = np.mean(self.domains_arr,axis=0).reshape(1,-1)

			for nuniti in tqdm.tqdm(range(1,nunits),
				desc="Predicting units from units."):
				these_errs = []
				allunits = np.arange(nunits)
				sampled_already = {}

				for iteri in range(nsim_atmost):
					success = False
					while not success:
						unitset = sorted(random.sample(list(allunits), nuniti))
						try:
							sampled_already[tuple(unitset)]
						except KeyError:
							sampled_already[tuple(unitset)] = True
							success = True

					notunitset = get_difference(allunits, unitset)

					pred = np.mean(self.domains_arr[np.array(unitset),:],axis=0).reshape(1,-1)
					# errs = self.domains_arr[np.array(notunitset),:] - pred
					# total_err = np.sum(np.abs(errs.flatten())) / len(notunitset)
					# errs = pred - global_average
					# total_err = np.sum(np.abs(errs.flatten()))
					total_err = pdf_distance(pred,global_average)
					these_errs.append(total_err)
				errs_over_n_sim[nuniti] = these_errs
			pickle.dump({
				'errs_over_n_sim': errs_over_n_sim,
				'nunits':nunits,
				}, open(plt_cache_fn,'wb'))
		else:
			d = pickle.load(open(plt_cache_fn,'rb'))
			errs_over_n_sim = d['errs_over_n_sim']
			nunits = d['nunits']


		plt_arr = {k: np.zeros(nunits-1) for k in ['min','med','max', 'std']}
		for nuniti in range(1,nunits):
			## min, med, max
			plt_arr['min'][nuniti-1] = np.min(errs_over_n_sim[nuniti])
			plt_arr['med'][nuniti-1] = np.median(errs_over_n_sim[nuniti])
			plt_arr['max'][nuniti-1] = np.max(errs_over_n_sim[nuniti])
			plt_arr['std'][nuniti-1] = np.sqrt(np.var(errs_over_n_sim[nuniti]))

		overall_max = np.max(plt_arr['max'])

		import matplotlib
		matplotlib.rcParams.update({'font.size': 18})
		import matplotlib.pyplot as plt
		f,ax = plt.subplots(1,1)
		f.set_size_inches(12,6)
		ax.plot(np.arange(1,nunits), plt_arr['med']/overall_max)
		ax.fill_between(np.arange(1,nunits), (plt_arr['med'] - plt_arr['std'])/overall_max,
			(plt_arr['med'] + plt_arr['std']) / overall_max, alpha=.3, color='red')
		ax.grid(True)
		ax.set_xlabel("Number of Buildings for Comparison",fontsize=20)
		ax.set_ylabel("Normalized Median Comparison Error",fontsize=20)
		ax.set_ylim([0,1.0])
		plt.savefig("figures/building_representativeness.pdf")


	def setup_service_by_unit_data(self):
		print("Setting up service by unit data...")
		try:
			self.all_services
			return
		except AttributeError:
			pass
		sm = Service_Mapper()
		self.service_bytes_by_unit = sm.get_service_bytes_by_separator(by='unit')

		self.all_services = list(set(service for unit,services in self.service_bytes_by_unit.items()
			 for service in services))


		self.units = sorted(list(self.service_bytes_by_unit))

		self.in_order_dividers = {
			'unit': self.units,
		}

	def setup_service_by_hour_data(self):
		print("Setting up service by hour data...")
		try:
			self.all_services
			return
		except AttributeError:
			pass
		sm = Service_Mapper()
		self.service_bytes_by_hour = sm.get_service_bytes_by_separator(by='hour')

		self.all_services = list(set(service for hour,services in self.service_bytes_by_hour.items()
			 for service in services))


		self.hours = sorted(list(self.service_bytes_by_hour))

		self.in_order_dividers = {
			'hour': sorted(self.hours),
		}

	def get_dist_mat(self, divider_type, metric, **kwargs):
		print("Computing distance matrix...")
		divider_to_i = {divider:i for i,divider in enumerate(self.in_order_dividers[divider_type])}
		n_dividers = len(self.service_bytes_by_divider)
		print("{} dividers, {} services".format(n_dividers, len(self.all_services)))
		self.bytes_by_service = {}
		for div in self.service_bytes_by_divider:
			for s,nb in self.service_bytes_by_divider[div].items():
				try:
					self.bytes_by_service[s] += nb
				except KeyError:
					self.bytes_by_service[s] = nb

		for divider in list(self.service_bytes_by_divider):
			services = list(self.service_bytes_by_divider[divider])
			for not_inc_service in get_difference(self.all_services,services):
				self.service_bytes_by_divider[divider][not_inc_service] = 0

		self.all_services = sorted(self.all_services, key = lambda s : -1*self.bytes_by_service[s])
		service_to_i = {service:i for i,service in enumerate(self.all_services)}
		self.domains_arr = np.zeros((n_dividers, len(self.all_services)))
		for divider,services in self.service_bytes_by_divider.items():
			for service,nb in services.items():
				self.domains_arr[divider_to_i[divider],service_to_i[service]] = nb
		
		traffic_by_service = np.sum(self.domains_arr,axis=0)
		global_domain_traffic = np.sort(traffic_by_service)[::-1]
		ttl_traffic = np.sum(global_domain_traffic)
		global_domain_traffic = global_domain_traffic / ttl_traffic
		global_domain_traffic_dict = {i:traffic_by_service[i] / ttl_traffic for i in range(len(traffic_by_service))}
		kwargs['global_domain_traffic'] = global_domain_traffic
		kwargs['global_domain_traffic_dict'] = global_domain_traffic_dict

		nb_by_divider = np.sum(self.domains_arr,axis=1)
		self.domains_arr = self.domains_arr / nb_by_divider.reshape((-1,1))
		nb_by_divider = nb_by_divider / np.max(nb_by_divider.flatten())

		# print(self.domains_arr[:,0:10])
		# exit(0)



		if divider_type == 'building':
			interesting_prints = []
		elif divider_type == 'category':
			interesting_prints = list(range(n_dividers))
		else:
			interesting_prints = []

		for divideri in interesting_prints:
			max_n = np.max(self.domains_arr[divideri,:])
			print("Divider {}".format(divideri))
			for i in np.argsort(self.domains_arr[divideri,:])[::-1][0:15]:
				print("{} -- {} {}".format(i,self.all_services[i],round(self.domains_arr[divideri,i]*100.0/max_n,4)))


		dist_mat = np.zeros((n_dividers,n_dividers))
		from sympy.combinatorics.permutations import Permutation
		for divideri in tqdm.tqdm(range(n_dividers),desc="Calculating distances..."):
			for dividerj in range(n_dividers):
				if dividerj>divideri: break
				
				d = metric(self.domains_arr[divideri,:], self.domains_arr[dividerj,:], **kwargs)

				dist_mat[divideri,dividerj] = d
				dist_mat[dividerj,divideri] = d


		dist_mat = dist_mat - np.min(dist_mat.flatten())
		dist_mat = dist_mat / np.max(dist_mat.flatten())

		return dist_mat

	def setup_service_data(self):
		try:
			self.all_services
			return
		except AttributeError:
			pass
		sm = Service_Mapper()
		self.service_bytes_by_building = sm.get_service_bytes_by_separator()

		self.all_services = list(set(service for building,services in self.service_bytes_by_building.items()
			 for service in services))


		all_building_subnets = [
			"160.39.40.128", "160.39.41.128", "160.39.61.128", "160.39.61.0", "160.39.62.192", "160.39.62.128", "160.39.62.0", "160.39.63.128", "160.39.63.64", "160.39.63.0", # grad students
		    "160.39.2.0", # undergraduate students in the School of General Studies
		    "160.39.41.0", "160.39.56.128", "160.39.59.0", # students, faculty and staff
		    "128.59.122.128", "160.39.21.128", "160.39.22.0", "160.39.38.128", # postdocs, faculty and staff
		    "160.39.22.128" # faculty and staff
		]
		ncats,cats = [10,1,3,4,1],['grad','undergrad','grad\nfacstaff','pdocs\nfacstaff','facstaff']
		cats = [c for i,c in enumerate(cats) for n in range(ncats[i]) ]
		building_subnets = [b for b in all_building_subnets if b in self.service_bytes_by_building]
		self.cats = [c for c,b in zip(cats,all_building_subnets) if b in self.service_bytes_by_building]


		self.in_order_dividers = {
			'building': building_subnets,
			'category': ['grad','grad\nfacstaff','pdocs\nfacstaff','facstaff','global']
		}

		## aggregate to pseudo buildings, with each category being a building
		self.service_bytes_by_category = {'global': {}}
		for bsnet,cat in zip(building_subnets,self.cats):
			try:
				self.service_bytes_by_category[cat]
			except KeyError:
				self.service_bytes_by_category[cat] = {}

			for service,nb in self.service_bytes_by_building[bsnet].items():
				try:
					self.service_bytes_by_category[cat][service] += nb
				except KeyError:
					self.service_bytes_by_category[cat][service] = nb
				try:
					self.service_bytes_by_category['global'][service] += nb
				except KeyError:
					self.service_bytes_by_category['global'][service] = nb


	def compare_building_domains(self, metric, **kwargs):
		self.setup_service_data()		

		for service_bytes_by_divider,divider_type in zip([self.service_bytes_by_building,self.service_bytes_by_category], 
				['building','category']):
			print("\n\n-----DIVIDING BY TYPE {}------".format(divider_type))
			if divider_type == 'building': continue

			self.service_bytes_by_divider = service_bytes_by_divider
			dist_mat = self.get_dist_mat(divider_type, metric, **kwargs)
			dmat_sum = np.sum(dist_mat, axis=0)

			import matplotlib.pyplot as plt
			n_dividers = len(self.service_bytes_by_divider)
			fig, axs = plt.subplots(n_dividers, n_dividers, figsize=(10, 10))
			sorted_rows = list(reversed(np.argsort(dmat_sum)))
			for divideri in range(n_dividers):
				for dividerj in range(n_dividers):

					axs[divideri, dividerj].imshow(np.array([[dist_mat[sorted_rows[divideri],
						sorted_rows[dividerj]]]]), 
						cmap='coolwarm', vmin=0, vmax=1)
					# axs[divideri, dividerj].axis('off')
					axs[divideri, dividerj].set_xticks([])
					axs[divideri, dividerj].set_yticks([])
					axs[divideri, dividerj].set_aspect('equal')

			def divideri_to_lab(divideri):
				if divider_type == 'building':
					return self.cats[divideri]
				else:
					return self.in_order_dividers['category'][divideri]

			for i,divideri in enumerate(sorted_rows):
				axs[0,i].set_title(divideri_to_lab(divideri), rotation=45, fontsize=18)
			for i,divideri in enumerate(sorted_rows):
				axs[i,0].set_ylabel(divideri_to_lab(divideri), rotation=45, fontsize=18)

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

	def crosswise_comparisons(self):
		metrics = [pdf_distance,weighted_jaccard, euclidean,rbo_wrap,spearman, cosine_similarity, jaccard]
		labs = ['bc','wjac', 'euclidean','rbo','spearman', 'cos_sim', 'jac']
		ax_labs = ['Bhattacharyya Distance', 'Weighted Jaccard Index', 'Euclidean Distance','Rank-Biased Overlap', 'Spearman Correlation', 'Cosine Similarity',
			 'Jaccard Index']
		for metric,lab,axis_lab in zip(metrics,labs,ax_labs):
			print("\n\n\nCOMPUTING METRIC {}\n\n\n".format(lab))
			self.compare_building_domains(metric, n_doms=1000, plt_lab=lab, axis_lab=axis_lab)
			exit(0)


if __name__ == "__main__":
	sdc = Service_Demographic_Comparison()
	# sdc.unit_representativity()
	# sdc.temporal_representativity()
	sdc.crosswise_comparisons()

