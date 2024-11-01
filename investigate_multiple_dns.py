import os, numpy as np, gzip, multiprocessing, glob, pickle, tqdm, time
import pytricia
import datetime
from subprocess import call
from helpers import *
from constants import *
from google_utilities import *


## for each group, tabulate time at which you see main flow shifts 
# - something like, in past N seconds, 90% of the volume was primarily in one flow
## then tabulate a rolling average of retransmits per 10s / (on the main flow?)

## then you'd want to do some sort of correltion between the delta series indicating main flow shifts, and the retransmits
## something like, distance between them in time. maybe # of times you see them happen within X seconds of each other

## want to sort this by service


def pull_and_packet_files(start_date, end_date):

	print("Fetching all results between {} and {}".format(
		start_date, end_date))
	fmt = '%Y-%m-%d-%H%M'
	start_date = datetime.datetime.strptime(start_date, fmt)
	end_date = datetime.datetime.strptime(end_date, fmt)

	parent_id = "1OXeMRAe4g2Swv1TwSAv8fgm6NNn6Mkm1"
	# parent_id = "1A4LfWLyZDm4rXbtrfEDxHX4Nc3rlY5LG"

	RAW_DNS_DIR = os.path.join(DATA_DIR, 'raw_dns')
	RAW_PCAP_DIR = os.path.join(DATA_DIR, 'raw_flow_info')

	have_results = [el.split('.')[0] for d in [RAW_DNS_DIR, RAW_PCAP_DIR] for el in os.listdir(d)] 
	gdrive = get_gdrive()
	t=time.time()
	files = get_file_list(gdrive, parent_id)

	#dns1-2024-09-26-2200.csv
	#columbia2-2024-09-19-1500.tar

	to_dl = []
	for fn in files:
		try:
			dlfn = fn['originalFilename']
		except KeyError:
			print("couldn't find filename for {}".format(fn))
			continue
		if dlfn.split('.')[0] not in have_results:
			if 'dns' in dlfn and ".csv" in dlfn:
				try:
					capture_date = re.search("dns\d\-(.+)\.csv", dlfn).group(1)
				except AttributeError:
					print("RE failed on {}".format(dlfn))
					continue
				out_fn = os.path.join(RAW_DNS_DIR, dlfn)
			elif 'columbia' in dlfn and 'tar' in dlfn:
				try:
					capture_date = re.search("columbia\d\-(.+)\.tar", dlfn).group(1)
				except AttributeError:
					print("RE failed on {}".format(dlfn))
					continue
				out_fn = os.path.join(RAW_PCAP_DIR, dlfn)
			else:
				continue
			capture_date = datetime.datetime.strptime(capture_date, fmt)

			if not (capture_date >= start_date and capture_date <= end_date): 
				continue
			to_dl.append((fn, out_fn))
	if len(to_dl) == 0:
		print("No results to download in the specified time range")
		return
	for fn,out_fn in tqdm.tqdm(to_dl, desc="downloading files from cloud..."):
		print("Downloading into {}".format(out_fn))
		download_file_by_id(gdrive, fn['id'], out_fn)

in_columbia_check = pytricia.PyTricia()
in_columbia_check['160.39.0.0/16'] = 1

T_FMT_FLOW_FILE = '%b %d, %Y %H:%M:%S.%f000 EDT'

multi_dns_file = os.path.join(DATA_DIR, 'parsed_raw_dns', 'multidns_responses.csv')
# multi_dns_file = os.path.join(DATA_DIR, 'parsed_raw_dns', 'multidns_responses_subset.csv')

def read_flow_tuple(fields):
	#### parses packet (sample headers below) and returns 5 tuple representing flow if it's a valid TCP/UDP flow
	#### else returns None

	if fields[0] == 'ip.src':
		### header, ignore
		return None

	# ip.src	tcp.srcport	udp.srcport	eth.src	ip.dst	tcp.dstport	udp.dstport	eth.dst	tcp.seq_raw	tcp.ack_raw	tcp.flags	tcp.len	frame.len	ip.proto	frame_number	frame_time	protocol	ip_src	ip_dst	mac_src_oui	mac_dst_oui	tls_handshake_extensions_server_name
	# 162.102.157.66		16393	ba:58:c2:96:6b:aa	95.229.190.46		3491	5a:1e:20:21:d5:75					1009	17	1	Sep  3, 2024 03:53:06.903536000 EDT	UDP	160.39.59.0	17.249.117.155	14698222	12	

	try:
		### ip.src is the anonymized IP address but that anonymization stays consistent across all instances
		### ip_dst is the unanonymized ip destination address
		### ip_src is a subnetted-out columbia address, in the subnet 160.39.0.0 
		# but there's a possibility that src and dst are backwards, which we check below with our trie
		src,dst = fields[0],fields[18] ### 0 -> ip.src, 18 -> ip_dst
	except IndexError:
		# if 'ARP' not in row and 'ICMP' not in row:
		# 	print("Malformed row : {}".format(row))
		return None
	sport,dport = fields[1], fields[5]
	tcp=1
	if sport=='' or dport=='': 
		sport,dport = fields[2], fields[6]
		tcp=0
		if sport == '' or dport == '': 
			return None

	try:
		try: ## swap if needed
			in_columbia_check[fields[17]]
		except KeyError: 
			### need to switch roles of src and dst
			### this is a packet from outside to inside
			### so dst should be ip_src and src should be ip.dst
			tmpport = dport
			dport = sport
			sport = tmpport

			src,dst = fields[4], fields[17]
	except ValueError:
		# print("Invalid prefix.... {}".format(fields[17]))
		# print(fields)
		return None
	try:
		nbytes = int(fields[12])
	except ValueError:
		print("Invalid nbytes.... {}".format(fields[11]))
		return None

	dtstr = fields[15]

	return src,dst,sport,dport,tcp,nbytes,dtstr

def find_high_retransmit_dns_groups(*args):
	worker_i, out_dir, fns, = args[0]
	np.random.seed(31415 + worker_i)

	nfns = len(fns)

	with open(os.path.join(out_dir, 'worker_{}.csv'.format(worker_i)),'w') as out_fp:
		for i, fn in enumerate(fns):
			# problem file
			try:
				## parse this dns file, and then the coresponding flow file
				dns_re = re.search('dns(\d)\-(.+).csv\.gz', fn)
				file_number = dns_re.group(1)
				date_string = dns_re.group(2)
				fmt = '%Y-%m-%d-%H%M'
				dns_dt = datetime.datetime.strptime(date_string, fmt)

				flow_dt = dns_dt + datetime.timedelta(hours=5)
				flow_fn = os.path.join(DATA_DIR, 'raw_flow_info', 'columbia{}-{}.tar.gz'.format(
					file_number, flow_dt.strftime(fmt)))
				print("worker {} parsing {}".format(worker_i, fn))
				if np.random.random() > .99:
					print("{} pct. done parsing in worker {}".format(round(i * 100 / nfns, 2), worker_i))

				## unzip flow fn and populate packet files we need to read
				tmp_out_dir = os.path.join(TMP_DIR, 'tmp-flow-out-worker-{}'.format(worker_i))
				if os.path.exists(tmp_out_dir):
					call('rm -rf {}'.format(tmp_out_dir),shell=True)
				call("mkdir {}".format(tmp_out_dir), shell=True)
				call('tar -xzf {} -C {}'.format(flow_fn,
					tmp_out_dir), shell=True)
				all_dfs = []
				def add_files(p): ## finds all subfiles in the folder
					for _fn in os.listdir(p):
						new_p = os.path.join(p,_fn)
						if os.path.isdir(new_p):
							add_files(new_p)
						else:
							all_dfs.append(new_p)
				add_files(tmp_out_dir) # populate packet files

				### populate src,dsts for which we saw > N TCP retransmits
				print("Looking for high retransmit flows")
				flow_seq_ack_tracker = {}
				flow_size = {}
				n_retransmit = {}
				flow_dtstr_bytes_tracker = {}
				flow_to_start_time = {}
				for ffi,flow_fn in enumerate(all_dfs):
					for row in open(flow_fn,'r'):
						fields = row.strip().split('\t')
						ret = read_flow_tuple(fields)
						if ret is not None:
							src,dst,sport,dport,tcp,nbytes,dtstr = ret
						else:
							continue

						flow = (src,dst,sport,dport,tcp)

						try:
							flow_seq_ack_tracker[flow]
						except KeyError:
							flow_seq_ack_tracker[flow] = {}
						try:
							flow_size[flow] += nbytes
						except KeyError:
							flow_size[flow] = nbytes
						seq,ack = fields[8], fields[9]
						try:
							flow_seq_ack_tracker[flow][seq,ack]
							## retransmission
							try:
								n_retransmit[flow] += 1
							except KeyError:
								n_retransmit[flow] = 1
						except KeyError:
							flow_seq_ack_tracker[flow][seq,ack] = None # new flow

						try:
							flow_dtstr_bytes_tracker[flow]
							flow_dtstr_bytes_tracker[flow].append((int((datetime.datetime.strptime(dtstr, T_FMT_FLOW_FILE) - flow_to_start_time[flow]).total_seconds()), nbytes))
						except KeyError:
							flow_to_start_time[flow] = datetime.datetime.strptime(dtstr, T_FMT_FLOW_FILE)
							flow_dtstr_bytes_tracker[flow] = [(0,nbytes)]

						if np.random.random() > .9999:break
				print("worker {} : {} flows, {} had at least 1 retransmission".format(worker_i, len(flow_seq_ack_tracker), len(n_retransmit)))
				### infer a cutoff, i.e., to get rid of 99% of the shit
				all_n_retransmit = list(n_retransmit.values())
				cutoff_retransmit = np.percentile(all_n_retransmit, 90)
				print("worker {} : Looking specifically at flows with >= {} retransmits".format(worker_i, cutoff_retransmit))
				### save interesting src,dst pairs
				interesting_tups = {(src,dst): None for (src,dst,_,_,_), v in n_retransmit.items() if v >= cutoff_retransmit}
				### also randomly save non-problematic flows
				### idea is to compare distributions of things between high loss and not high loss flows 
				not_interesting_tups = {}
				for src,dst,_,_,_ in n_retransmit:
					try:
						interesting_tups[src,dst]
					except KeyError:
						not_interesting_tups[src,dst] = None
				not_interesting_tups = list(not_interesting_tups)
				np.random.shuffle(not_interesting_tups)
				not_interesting_tups = {(src,dst):None for src,dst in not_interesting_tups[0:10*len(interesting_tups)]}

				print("worker {} : Found {} interesting (and thus 10x noninteresting) tups".format(worker_i, len(interesting_tups)))
				print("worker {} : Examples: {}".format(worker_i, list(interesting_tups)[0:50]))

				

				# f,ax = get_figure()
				# x,cdf_x = get_cdf_xy(all_n_retransmit,logx=True)
				# ax.semilogx(x,cdf_x)
				# ax.set_xlabel("Number of retransmissions")
				# ax.set_ylabel("CDF of Flows")
				# ax.grid(True)
				# save_figure('multidns/number_retransmissions_over_flows.pdf')

				### extend the list of interesting src,dst pairs to include dsts that also appear in multidns
				print("Extending list of interesting tuples...")
				ri = -1
				ip_tups_of_interest ={}
				all_dns_src_dst = {}
				for row in gzip.open(fn):
					row=row.decode().strip()
					fields = row.split('\t')
					ri += 1
					# if ri == 0 or ri <= 5:
					# 	for _i,_f in enumerate(fields):
					# 		if _i in [0,4,17]:
					# 			print("Worker {} : {} -> {}".format(worker_i, _i,_f))
					try:
						fields[17]
					except IndexError:
						# print("Error on row : {}".format(row))
						continue
					src = fields[4]
					ip_anses = list(fields[17].split(','))
					interesting = False
					for ip_ans in ip_anses:
						try:
							interesting_tups[src,ip_ans]
							interesting = True
							break
						except KeyError:
							pass
					if interesting:
						for ip_ans in ip_anses:
							interesting_tups[src,ip_ans] = None
					else: ## add to "not interesting" cases if that's the case
						for ip_ans in ip_anses:
							try:
								not_interesting_tups[src,ip_ans]
								interesting = True
								break
							except KeyError:
								pass
						if interesting:
							for ip_ans in ip_anses:
								not_interesting_tups[src,ip_ans] = None
					if np.random.random() > .999999:break
				print("worker {} : By pairing with other DNS answers ({} lines read), observed {} interesting tups, {} not interesting tups".format(
					worker_i, ri, len(interesting_tups), len(not_interesting_tups)))
				print("Examples: {}".format(list(interesting_tups)[0:50]))

				print("Now adding those interesting dns tuples to file...")
				for row in gzip.open(fn):
					row=row.decode().strip()
					fields = row.split('\t')
					try:
						fields[17]
					except IndexError:
						continue
					src = fields[4]
					ip_anses = fields[17].split(',')
					for ip_ans in ip_anses:
						all_dns_src_dst[src,ip_ans] = None
						all_dns_src_dst[ip_ans,src] = None
					interesting = False
					for ip_ans in ip_anses:
						try:
							interesting_tups[src,ip_ans]
							interesting = True
							break
						except KeyError:
							pass
					if interesting:
						row = ('dns', 'interesting', src, "--".join(ip_anses), fields[11])
						out_fp.write("\t".join(row) + '\n')
					else:
						for ip_ans in ip_anses:
							try:
								not_interesting_tups[src,ip_ans]
								interesting = True
								break
							except KeyError:
								pass
						if interesting:
							row = ('dns', 'not_interesting', src, "--".join(ip_anses), fields[11])
							out_fp.write("\t".join(row) + '\n')
					if np.random.random() > .999999:break
				print("Done! Now going through flows...")
				
				all_src_dst = {}
				wrote_flow = {}
				for ffi,flow_fn in enumerate(all_dfs):
					ri=-1
					for row in open(flow_fn,'r'):
						fields = row.strip().split('\t')
						ret = read_flow_tuple(fields)
						if ret is not None:
							src,dst,sport,dport,tcp,_,_ = ret
						else:
							continue
						flow = (src,dst,sport,dport,tcp)
						try:
							## just write the flow summary
							## this will also be the first instance of the flow, so should record flow start well
							wrote_flow[flow] 
							continue
						except KeyError:
							wrote_flow[flow] = None
						ri += 1
						# if (ri == 0 or ri == 1) and ffi == 0:
						# 	for _i,_f in enumerate(fields):
						# 		print("{} -> {}".format(_i,_f))
						all_src_dst[src,dst] = None

						try:
							flow_bytes_times_delta = flow_dtstr_bytes_tracker[flow] 
						except KeyError:
							continue
						flow_bytes_times_delta_str = ":".join([str(el[0]) + ";" + str(el[1]) for el in flow_bytes_times_delta])

						try:
							interesting_tups[src,dst] ## enough retransmits?
							row = ('flow', 'interesting', src, dst, sport, dport,str(tcp),str(n_retransmit.get(flow,0)),
								str(flow_size.get(flow,0)), fields[15], flow_bytes_times_delta_str)
							out_fp.write("\t".join(row) + '\n')
						except KeyError:
							pass
						try:
							not_interesting_tups[src,dst] ## enough retransmits?
							row = ('flow', 'not_interesting', src, dst, sport,dport,str(tcp),str(n_retransmit.get(flow,0)),
								str(flow_size.get(flow,0)), fields[15], flow_bytes_times_delta_str)
							out_fp.write("\t".join(row) + '\n')
						except KeyError:
							pass
						if np.random.random() > .999999:break


				in_both = get_intersection(list(all_src_dst), list(all_dns_src_dst))
				print("worker {} IN DNS: {}, IN FLOW: {}, IN BOTH: {}".format(worker_i, len(all_dns_src_dst), len(all_src_dst), len(in_both)))
				call('rm -rf {}'.format(tmp_out_dir),shell=True)


				### GAHBAGE
				del all_src_dst
				del wrote_flow
				del ip_tups_of_interest
				del all_dns_src_dst
				del not_interesting_tups
				del interesting_tups
				del n_retransmit
				del flow_seq_ack_tracker
				del flow_size
				del flow_dtstr_bytes_tracker
				del flow_to_start_time

			except:
				print("Exception while work on file {}".format(fn))
				import traceback
				traceback.print_exc()
	return 'ok'

def find_t_pointer_boundary(*args):
	worker_i, t_pointer, = args[0]

	this_interval_start = None
	t_pointer_to_line_start = []
	i=0
	print("Scrolling through t pointer lines in worker {}".format(worker_i))
	for row in open(multi_dns_file, 'r'):
		# need src,dst -> most recent dns flow with that <src,dst> -> group id for that <src,dst> -> increment which A record was used
		# as a start tabulate number of nonzero A record uses per group ID
		fields = row.strip().split('\t')
		dts = fields[-1]
		t_occurred = datetime.datetime.strptime(dts, T_FMT_FLOW_FILE)
		if t_occurred - t_pointer < datetime.timedelta(hours=0) or t_occurred - t_pointer >= datetime.timedelta(hours=6):
			if this_interval_start is not None:
				t_pointer_to_line_start.append((this_interval_start, i))
				this_interval_start = None
		else:
			if this_interval_start is None:
				this_interval_start = i
		i += 1
	return {t_pointer: t_pointer_to_line_start}

class Multiple_DNS:
	def __init__(self):
		pass


	# - make sure you get rid of single-answer stuff in the fraction graph

	def run(self):
		all_dns_fs = glob.glob(os.path.join(DATA_DIR, 'raw_dns', '*.gz'))
		if not os.path.exists(multi_dns_file):
			parsed_dns_dir = os.path.join(DATA_DIR, 'parsed_raw_dns')
			if not os.path.exists(parsed_dns_dir):
				call('mkdir {}'.format(parsed_dns_dir), shell=True)
			# multiprocses these because there's going to be a ton
			# save output results (just pick out the ones with multiple entries in a particular column)
			
			nworkers = 4 #multiprocessing.cpu_count() // 2
			args = []
			dns_f_chunks = split_seq(all_dns_fs, nworkers)
			for i in range(nworkers):
				args.append((i,parsed_dns_dir,dns_f_chunks[i],))
			ppool = multiprocessing.Pool(processes=nworkers)
			print("Launching workers")
			all_rets = ppool.map(find_high_retransmit_dns_groups, args)
			ppool.close()
			with open(multi_dns_file, 'w') as f:
				for i in range(nworkers):
					for row in open(os.path.join(parsed_dns_dir, 'worker_{}.csv'.format(i)),'r'):
						f.write(row)
			call('rm {}'.format(os.path.join(parsed_dns_dir, "worker*")), shell=True)


		self.time_deltas = {} #### PLOT OBJECTS
		self.time_delta_retransmit_scatter = {}
		self.frac_reached_out = {}
		self.kl_divergence_uniform = {}
		self.kl_divergence_delta = {}
		for interesting in ['interesting', 'not_interesting']:
			self.time_deltas[interesting] = {'max': [], 'min': [], 'med': [], 'mean': []}
			self.time_delta_retransmit_scatter[interesting] = [[],[]]
			self.frac_reached_out[interesting] = []
			self.kl_divergence_uniform[interesting] = []
			self.kl_divergence_delta[interesting] = []

		all_t_pointers = []
		fmt = '%Y-%m-%d-%H%M'
		for fn in all_dns_fs:
			date_string = re.search('dns\d\-(.+).csv\.gz', fn).group(1)
			dns_dt = datetime.datetime.strptime(date_string, fmt)
			all_t_pointers.append(dns_dt)
		all_t_pointers = sorted(list(set(all_t_pointers)))

		## First, pass through the entire file to find the pertinent line numbers for each t_pointer
		cache_fn = os.path.join(CACHE_DIR, 't_pointer_to_line_start.pkl')
		self.flow_file_t_fmt = T_FMT_FLOW_FILE  # '%Y-%m-%d-%H%M' # May 13, 2024 21:00:05.877432000 EDT
		if not os.path.exists(cache_fn):
			nworkers = len(all_t_pointers)
			args = []
			for i in range(nworkers):
				args.append((i,all_t_pointers[i],))
			ppool = multiprocessing.Pool(processes=nworkers)
			print("Launching workers to find t pointer boundaries")
			all_rets = ppool.map(find_t_pointer_boundary, args)
			t_pointer_to_line_start = {t_pointer: [] for t_pointer in all_t_pointers}
			for ret in all_rets:
				for k,v in ret.items():
					t_pointer_to_line_start[k] = v
			pickle.dump(t_pointer_to_line_start, open(cache_fn, 'wb'))
		else:
			t_pointer_to_line_start = pickle.load(open(cache_fn, 'rb'))


		## sort them so we know which t_pointer we're looking at at each time line of the file
		t_pointer_to_line_start = list([(k,vel) for k,v in t_pointer_to_line_start.items() for vel in v])
		t_pointer_to_line_start = sorted(t_pointer_to_line_start, key = lambda el : el[1][0])

		rowi = 0
		self.init_plot_objs()
		for row in tqdm.tqdm(open(multi_dns_file, 'r'),desc="Scrolling through DNS queries"):
			if rowi > t_pointer_to_line_start[0][1][1]: ## if we've passed the interval end, clear the objects and continue
				last_t_pointer = t_pointer_to_line_start[0][0]
				del t_pointer_to_line_start[0]
				this_t_pointer = t_pointer_to_line_start[0][0]
				if last_t_pointer != this_t_pointer:
					print("Line {}, switching t pointer from {} to {}".format(rowi, last_t_pointer, this_t_pointer))
					## Plot everything, and reset objects
					self.make_plots()
					self.init_plot_objs()
			# need src,dst -> most recent dns flow with that <src,dst> -> group id for that <src,dst> -> increment which A record was used
			# as a start tabulate number of nonzero A record uses per group ID

			fields = row.strip().split('\t')
			if row[0] == 'd':
				_,interesting,src,dsts,dts = fields
				# if dts == 'frame_time': continue # header
				if dsts == '': 
					rowi += 1
					continue

				t_occurred = datetime.datetime.strptime(dts, self.flow_file_t_fmt)
				dsts = get_difference(dsts.split('--'), '')
				for dst in dsts:
					if dst == '': continue
					try:
						self.srcdst_to_dns_times[interesting][src,dst].append((len(self.srcdst_to_dns_times[interesting][src,dst]), t_occurred)) 
					except KeyError:
						self.srcdst_to_dns_times[interesting][src,dst] = [(0,t_occurred)]
					try:
						self.srcdst_dns_id_to_group_id[interesting][src,dst]
					except KeyError:
						self.srcdst_dns_id_to_group_id[interesting][src,dst] = {}
					self.srcdst_dns_id_to_group_id[interesting][src,dst][self.srcdst_to_dns_times[interesting][src,dst][-1][0]] = self.gid_ctr[interesting]
				self.group_id_to_dns[interesting][self.gid_ctr[interesting]] = (src,dsts)
				self.gid_ctr[interesting] += 1
			if row[0] == 'f':
				if not self.sorted_dns_times:
					for interesting in ['interesting', 'not_interesting']:
						for k,v in tqdm.tqdm(self.srcdst_to_dns_times[interesting].items(),desc="Sorting times..."): # sort in time
							self.srcdst_to_dns_times[interesting][k] = sorted(v, key = lambda el : el[1])
					self.sorted_dns_times = True
				self.parse_flow_row(row)

			rowi += 1
			
		self.make_plots()


	def kl_divergence(self, p, q):
		## sum(p_i * log (p_i / q_i))
		return np.sum(p * np.log(p / q + .00001))


	def make_plots(self):
		### makes all plots of interest for multi DNS analysis
		print("\n\nMAKING PLOTS\n")
		for interesting in ['interesting', 'not_interesting']:
			for gid in tqdm.tqdm(self.group_id_to_dns[interesting], desc="Calcing DNS Answer Stats"):
				if len(self.srcdst_dns_group_id_to_a_ctr[interesting].get(gid,[])) == 0: continue
				all_times = []
				src,dsts = self.group_id_to_dns[interesting][gid]
				if len(dsts) <= 1: continue

				## TODO -- need fraction of dns queries used, but weighted by traffic
				## i.e., uniform distribution should be 1, delta should be 0
				## idea -- KL divergence between this pdf and a uniform pdf
				for dst in dsts:
					try:
						self.srcdst_dns_group_id_to_bytes_ctr[interesting][gid][dst]
					except KeyError:
						self.srcdst_dns_group_id_to_bytes_ctr[interesting][gid][dst] = 0.0


				flow_volumes = np.array(list(self.srcdst_dns_group_id_to_bytes_ctr[interesting][gid].values()))
				if np.sum(flow_volumes) > 0:
					flow_volumes = flow_volumes / np.sum(flow_volumes)
					uniform_flow_volumes = np.ones(len(flow_volumes)) / len(flow_volumes)
					maxf = np.argmax(flow_volumes)
					delta_flow_volumes = .00001 * np.ones(len(flow_volumes))
					delta_flow_volumes[maxf] = 1.0
					self.kl_divergence_uniform[interesting].append(self.kl_divergence(flow_volumes, uniform_flow_volumes))
					self.kl_divergence_delta[interesting].append(self.kl_divergence(flow_volumes, delta_flow_volumes))
					if self.kl_divergence_delta[interesting][-1] > 3:
						print('\n')
						print("{} {} {} {}".format(interesting,  self.kl_divergence_delta[interesting][-1], np.round(flow_volumes,3), np.round(delta_flow_volumes,3)))
						print(" {} {}".format(src,dsts))
						print('\n')
						if np.random.random() > .999:exit(0)

				## Populate the fraction of DNS records for which we start a flow
				self.frac_reached_out[interesting].append(len(self.srcdst_dns_group_id_to_a_ctr[interesting][gid]) / len(dsts))

				## Populate connection start delta times
				for i,dst in enumerate(dsts):
					for _,t in self.srcdst_to_dns_times[interesting][src,dst]:
						all_times.append((i,t))
				last_t = None
				these_time_deltas = []
				all_times = sorted(all_times, key = lambda el : el[1])
				for i,t in all_times:
					if last_t is None:
						last_t = t
						last_i = i
						continue
					if last_i != i: ### CHECK FOR HOUR+ DELTAS
						these_time_deltas.append((t-last_t).total_seconds())
						# if these_time_deltas[-1] <= 0: ### confirmed, looks like happy eyeballs
						# 	if these_time_deltas[-1] < 0:
						# 		print("Negative delta!!!!!")
						# 	elif these_time_deltas[-1] == 0:
						# 		print("Absolutely 0 delta!!!")
						# 	print("{} vs {}".format(t, last_t))
						# 	print(all_times)
						# 	print("{} -> {}".format(src,dsts))
						# 	exit(0)
					last_t = t
					last_i = i
				for k,f in zip(['max','min','med','mean'], [np.max, np.min, np.median, np.mean]):
					if len(these_time_deltas) > 0:
						if k == 'mean':
							self.time_delta_retransmit_scatter[interesting][0].append(f(these_time_deltas))
							self.time_delta_retransmit_scatter[interesting][1].append(self.group_id_to_n_retransmit[interesting].get(gid, 0))
						self.time_deltas[interesting][k].append(f(these_time_deltas))
					else:
						# if k == 'mean':
						# 	time_delta_retransmit_scatter[0].append(10000000)
						# 	time_delta_retransmit_scatter[1].append(group_id_to_n_retransmit.get(gid, 0))
						self.time_deltas[interesting][k].append(10000000)

		# if len(self.time_deltas['interesting']['med']) == 0:
		# 	return
		f,ax = get_figure()

		plot_every = 10

		markers = {'interesting':'x', 'not_interesting': 'D'}
		colors = {'interesting': 'red', 'not_interesting': 'blue'}

		for interesting in ['interesting', 'not_interesting']:
			for k in ['max', 'min', 'med']:
				if len(set(self.time_deltas[interesting][k])) == 1:
					x = np.ones(100)
					cdf_x = np.ones(100)
				else:
					x,cdf_x = get_cdf_xy(self.time_deltas[interesting][k], logx=True)
				ax.semilogx(x[::plot_every],cdf_x[::plot_every], label="{} {}".format(k,interesting), marker=markers[interesting])
		ax.set_xlabel('Time Between Requests for Different DNS Records from Same Query (s)', fontsize=6)
		ax.set_ylabel("CDF of DNS Answers")
		ax.set_ylim([0,1.0])
		ax.set_xlim([.1,10000])
		ax.grid(True)
		ax.legend()

		save_figure('multidns/time_between_requests.pdf')

		f,ax = get_figure()
		for interesting in ['interesting', 'not_interesting']:
			ax.scatter(self.time_delta_retransmit_scatter[interesting][0],self.time_delta_retransmit_scatter[interesting][1],
				marker=markers[interesting], label=interesting,color=colors[interesting])
		ax.set_xlabel("Average Time Delta Between Flow Starts")
		ax.set_xscale('log')
		ax.set_ylabel("Number of Retransmits")
		ax.legend()
		save_figure("multidns/scatter_td_vs_rex.pdf")

		f,ax = get_figure()
		for interesting in ['interesting', 'not_interesting']:
			x,cdf_x = get_cdf_xy(self.frac_reached_out[interesting])
			ax.plot(x[::plot_every],cdf_x[::plot_every],marker=markers['interesting'],label=interesting,color=colors[interesting])
		ax.set_xlabel("Fraction of A Records in Answer Used")
		ax.set_ylabel("CDF of Answers")
		ax.set_ylim([0,1.0])
		ax.legend()
		ax.grid(True)
		save_figure("multidns/fraction_answers_used.pdf")

		f,ax = get_figure()
		for interesting in ['interesting', 'not_interesting']:
			x,cdf_x = get_cdf_xy(self.kl_divergence_uniform[interesting])
			ax.plot(x[::plot_every],cdf_x[::plot_every],marker=markers['interesting'],label=interesting,color=colors[interesting])
		ax.set_xlabel("KL Divergences From Uniform")
		ax.set_ylabel("CDF of Answers")
		ax.set_ylim([0,1.0])
		ax.legend()
		ax.grid(True)
		save_figure("multidns/kl_divergence_from_uniform.pdf")

		f,ax = get_figure()
		for interesting in ['interesting', 'not_interesting']:
			x,cdf_x = get_cdf_xy(self.kl_divergence_delta[interesting])
			ax.plot(x[::plot_every],cdf_x[::plot_every],marker=markers['interesting'],label=interesting,color=colors[interesting])
		ax.set_xlabel("KL Divergences From Delta")
		ax.set_ylabel("CDF of Answers")
		ax.set_ylim([0,1.0])
		ax.legend()
		ax.grid(True)
		save_figure("multidns/kl_divergence_from_delta.pdf")

	def init_plot_objs(self):
		### For tracking statistics while parsing hte file
		self.srcdst_to_dns_times = {k:{} for k in ['interesting', 'not_interesting']}
		self.srcdst_dns_id_to_group_id = {k:{} for k in ['interesting', 'not_interesting']}
		self.srcdst_dns_group_id_to_a_ctr = {k:{} for k in ['interesting', 'not_interesting']}
		self.srcdst_dns_group_id_to_bytes_ctr = {k:{} for k in ['interesting', 'not_interesting']}
		self.group_id_to_dns = {k:{} for k in ['interesting', 'not_interesting']}
		self.group_id_to_n_retransmit = {k:{} for k in ['interesting', 'not_interesting']}
		self.gid_ctr = {k:0 for k in ['interesting', 'not_interesting']} # group id for a records returned in the same dns answer
		self.sorted_dns_times = False

	def parse_flow_row(self, row):
		#### Adds flow stats for this DNS group ID


		fields = row.strip().split('\t')
		_,interesting,src,dst,sport,dport,proto,n_retransmit,flow_size,dts = fields
		t_occurred = datetime.datetime.strptime(dts, self.flow_file_t_fmt)

		flow = (src,dst,sport,dport,proto)

		## most recent dns flow with this src,dst
		found=False
		for i,dns_time in self.srcdst_to_dns_times[interesting].get((src,dst), []): # pre-sorted
			if t_occurred > dns_time:
				found=True
				break
		if not found:
			# print("Didn't find : fields : {}, times : {}".format(fields, srcdst_to_dns_times[src,dst]))
			return
		# elif len(srcdst_to_dns_times[src,dst]) > 1:
		# 	print("Found: {}, fields : {}, times : {}".format(i, fields, srcdst_to_dns_times[src,dst]))
		group_id = self.srcdst_dns_id_to_group_id[interesting][src,dst][i]

		# if np.random.random() > .9999:
		# 	print("Flow {} -> {}".format(src,dst))

		try:
			self.group_id_to_n_retransmit[interesting][group_id] += int(n_retransmit)
		except KeyError:
			self.group_id_to_n_retransmit[interesting][group_id] = int(n_retransmit)

		# increment a record counter for this dst
		try:
			self.srcdst_dns_group_id_to_a_ctr[interesting][group_id]
		except KeyError:
			self.srcdst_dns_group_id_to_a_ctr[interesting][group_id] = {}
		try:
			self.srcdst_dns_group_id_to_a_ctr[interesting][group_id][dst] += 1
		except KeyError:
			self.srcdst_dns_group_id_to_a_ctr[interesting][group_id][dst] = 1

		# increment flow counts
		try:
			self.srcdst_dns_group_id_to_bytes_ctr[interesting][group_id]
		except KeyError:
			self.srcdst_dns_group_id_to_bytes_ctr[interesting][group_id] = {}
		try:
			self.srcdst_dns_group_id_to_bytes_ctr[interesting][group_id][dst] += float(int(flow_size))
		except KeyError:
			self.srcdst_dns_group_id_to_bytes_ctr[interesting][group_id][dst] = float(int(flow_size))

def get_random_subset_file():
	total_lines = 127770159
	n_output_lines = 5000000
	random_prob_keep = n_output_lines / total_lines
	in_fn = os.path.join(DATA_DIR, 'parsed_raw_dns', 'multidns_responses.csv')
	out_fn = os.path.join(DATA_DIR, 'parsed_raw_dns', 'multidns_responses_subset.csv')
	with open(out_fn, 'w') as out_fp:
		for row in tqdm.tqdm(open(in_fn,'r'), desc="Reading input file..."):
			if np.random.random() < random_prob_keep:
				out_fp.write(row)


if __name__ == "__main__":
	# pull_and_packet_files('2024-09-01-0000','2024-09-30-2359')
	# pull_and_packet_files('2024-10-01-0000','2024-10-31-2359')
	# get_random_subset_file()
	md = Multiple_DNS()
	md.run()