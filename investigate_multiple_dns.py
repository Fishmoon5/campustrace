import os, numpy as np, gzip, multiprocessing, glob
import datetime
from subprocess import call
from helpers import *
from constants import *

def find_multi_column(*args):
	worker_i, out_dir, fns, = args[0]
	np.random.seed(31415 + worker_i)

	nfns = len(fns)

	with open(os.path.join(out_dir, 'worker_{}.csv'.format(worker_i)),'w') as out_fp:
		for i, fn in enumerate(fns):

			## parse this dns file, and then the coresponding flow file

			date_string = re.search('dns1\-(.+).csv\.gz', fn).group(1)
			fmt = '%Y-%m-%d-%H%M'
			dns_dt = datetime.datetime.strptime(date_string, fmt)

			flow_dt = dns_dt + datetime.timedelta(hours=5)
			flow_fn = os.path.join(DATA_DIR, 'raw_flow_info', 'columbia1-{}.tar.gz'.format(
				flow_dt.strftime(fmt)))

			if np.random.random() > .99:
				print("{} pct. done parsing in worker {}".format(round(i * 100 / nfns, 2), worker_i))
			ri = -1
			ip_tups_of_interest ={}
			all_dns_src_dst = {}
			for row in gzip.open(fn):
				row=row.decode().strip()
				fields = row.split('\t')
				ri += 1
				# if ri == 0 or ri == 1:
				# 	for _i,_f in enumerate(fields):
				# 		print("{} -> {}".format(_i,_f))
				try:
					fields[17]
				except IndexError:
					# print("Error on row : {}".format(row))
					continue
				ip_anses = fields[17].split(',')
				row = ('dns', fields[4], "--".join(ip_anses), fields[11])
				out_fp.write("\t".join(row) + '\n')
				for ip_ans in ip_anses:
					ip_tups_of_interest[fields[4], ip_ans] = None
				for ip_ans in ip_anses:
					all_dns_src_dst[fields[4],ip_ans] = None
					all_dns_src_dst[ip_ans,fields[4]] = None

				# if np.random.random() > .99999:break
			print(list(ip_tups_of_interest)[0:100])
			# unzip flow fn
			tmp_out_dir = os.path.join(TMP_DIR, 'tmp-flow-out-worker-{}'.format(worker_i))
			# if os.path.exists(tmp_out_dir):
			# 	call('rm -rf {}'.format(tmp_out_dir),shell=True)
			# call("mkdir {}".format(tmp_out_dir), shell=True)
			# call('tar -xzf {} -C {}'.format(flow_fn,
			# 	tmp_out_dir), shell=True)

			all_dfs = []
			def add_files(p): ## finds all subfiles in the folder
				for _fn in os.listdir(p):
					new_p = os.path.join(p,_fn)
					if os.path.isdir(new_p):
						add_files(new_p)
					else:
						all_dfs.append(new_p)
			add_files(tmp_out_dir)
			all_src_dst = {}
			for ffi,flow_fn in enumerate(all_dfs):
				ri=-1
				for row in open(flow_fn,'r'):
					fields = row.strip().split('\t')
					ri += 1
					# if (ri == 0 or ri == 1) and ffi == 0:
					# 	for _i,_f in enumerate(fields):
					# 		print("{} -> {}".format(_i,_f))
					try:
						src,dst = fields[0],fields[18]
					except IndexError:
						if 'ARP' not in row:
							print("Malformed row : {}".format(row))
						continue
					all_src_dst[src,dst] = None
					try:
						ip_tups_of_interest[src,dst]
					except KeyError:
						try:
							ip_tups_of_interest[dst,src]
						except KeyError:
							continue
					row = ('flow', src, dst, row[11])
					out_fp.write("\t".join(row) + '\n')
					# if np.random.random() >.9999:
					# 	break

			in_both = get_intersection(list(all_src_dst), list(all_dns_src_dst))
			# print("IN DNS: {}, IN FLOW: {}, IN BOTH: {}".format(len(all_dns_src_dst), len(all_src_dst), len(in_both)))
			# call('rm -rf {}'.format(tmp_out_dir),shell=True)
	
	return 'ok'

class Multiple_DNS:
	def __init__(self):
		pass

	def run(self):
		multi_dns_file = os.path.join(DATA_DIR, 'parsed_raw_dns', 'multidns_responses.csv')
		if not os.path.exists(multi_dns_file):
			all_dns_fs = glob.glob(os.path.join(DATA_DIR, 'raw_dns', '*.gz'))
			parsed_dns_dir = os.path.join(DATA_DIR, 'parsed_raw_dns')
			if not os.path.exists(parsed_dns_dir):
				call('mkdir {}'.format(parsed_dns_dir), shell=True)
			# multiprocses these because there's going to be a ton
			# save output results (just pick out the ones with multiple entries in a particular column)
			
			nworkers = multiprocessing.cpu_count()
			args = []
			dns_f_chunks = split_seq(all_dns_fs, nworkers)
			for i in range(nworkers):
				args.append((i,parsed_dns_dir,dns_f_chunks[i],))
			ppool = multiprocessing.Pool(processes=nworkers)
			print("Launching workers")
			all_rets = ppool.map(find_multi_column, args)
			ppool.close()
			with open(multi_dns_file, 'w') as f:
				for i in range(nworkers):
					for row in open(os.path.join(parsed_dns_dir, 'worker_{}.csv'.format(i)),'r'):
						f.write(row)

		def find_mp(arr, v):
			## insert v in log time
			if v < arr[0]:
				return 0
			if v > arr[-1]:
				return len(arr)
			curr_k = len(arr)//2
			if v < arr[curr_k]:
				return find_mp(arr[0:curr_k], v)
			elif v > arr[curr_k]:
				return curr_k + find_mp(arr[curr_k:], v)
			else:
				return curr_k

		srcdst_to_dns_times = {}
		srcdst_dns_id_to_group_id = {}
		srcdst_dns_group_id_to_a_ctr = {}
		gid_ctr = 0 # group id for a records returned in the same dns answer

		t_fmt = '%b %d, %Y %H:%M:%S.%f000 EDT'  # '%Y-%m-%d-%H%M' # May 13, 2024 21:00:05.877432000 EDT
		for row in open(multi_dns_file, 'r'):
			# need src,dst -> most recent dns flow with that <src,dst> -> group id for that <src,dst> -> increment which A record was used
			# as a start tabulate number of nonzero A record uses per group ID

			fields = row.strip().split('\t')
			if fields[0] == 'dns':
				_,src,dsts,dts = fields
				if dts == 'frame_time': continue
				# print(dts)
				# if np.random.random() > .99:exit(0)
				# continue
				dsts = dsts.split('--')
				t_occurred = datetime.datetime.strptime(dts, t_fmt)
				for dst in set(dsts):
					try:
						srcdst_to_dns_times[src,dst] = [(0,t_occurred)]
					except KeyError:
						srcdst_to_dns_times[src,dst].append((len(srcdst_to_dns_times[src,dst]), t_occurred))
					try:
						srcdst_dns_id_to_group_id[src,dst]
					except KeyError:
						srcdst_dns_id_to_group_id[src,dst] = {}
					srcdst_dns_id_to_group_id[src,dst][srcdst_to_dns_times[src,dst][-1][0]] = gid_ctr
				gid_ctr += 1
			# if np.random.random() > .999999:break		
		for k,v in srcdst_to_dns_times.items(): # sort in time
			srcdst_to_dns_times[k] = sorted(v, key = lambda el : el[1])
		
		for row in open(multi_dns_file, 'r'):
			fields = row.strip().split('\t')
			if fields[0] == 'flow':
				_,src,dst,dts = fields
				t_occurred = datetime.datetime.strptime(dts, t_fmt)
				
				## most recent dns flow with this src,dst
				for i,dns_time in srcdst_to_dns_times[src,dst]: # pre-sorted
					if t_occurred > dns_time:
						break
				group_id = srcdst_dns_id_to_group_id[src,dst][i]
				# increment a record counter for this dst
				try:
					srcdst_dns_group_id_to_a_ctr[src,dst]
				except KeyError:
					srcdst_dns_group_id_to_a_ctr[src,dst] = {}
				try:
					srcdst_dns_group_id_to_a_ctr[src,dst][group_id]
				except KeyError:
					srcdst_dns_group_id_to_a_ctr[src,dst][group_id] = {}
				try:
					srcdst_dns_group_id_to_a_ctr[src,dst][group_id][dst] += 1
				except KeyError:
					srcdst_dns_group_id_to_a_ctr[src,dst][group_id][dst] = 1
			# if np.random.random() > .9999:break		

		print(srcdst_dns_group_id_to_a_ctr)


if __name__ == "__main__":
	md = Multiple_DNS()
	md.run()