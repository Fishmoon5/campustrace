import os, time, json, glob, numpy as np
from subprocess import call,check_output
from constants import *

def split_seq(seq, n_pieces):
	# splits seq into n_pieces chunks of approximately equal size
	# useful for splitting things to divide among processors
	newseq = []
	splitsize = 1.0/n_pieces*len(seq)
	for i in range(n_pieces):
		newseq.append(seq[int(round(i*splitsize)):int(round((i+1)*splitsize))])
	return newseq

class Traceroute_Conductor:
	def __init__(self, targets_fn):
		self.trace_msg = "tak2154atcolumbiadotedu"
		self.targets_fn = targets_fn

	def _traceroute(self, outfn):
		targets_fn = os.path.join(TMP_DIR, 'targets.txt')
		# maximum dsts per file
		if len(self.targets) > 50e3:
			targets_sets = split_seq(list(self.targets), int(len(self.targets) // 50e3))
		else:
			targets_sets = [self.targets]
		for i,targets_set in enumerate(targets_sets):
			with open(targets_fn, 'w') as f:
				for t in targets_set:
					f.write(t + "\n")
			scamp_cmd = 'scamper -c "trace -w 2" -M {}'\
				' -l peering_interfaces -f {} -O warts -o {} -p 10000'.format(self.trace_msg, 
					targets_fn, outfn + str(i))
			call(scamp_cmd, shell=True)

	def _ping(self, outfn):
		targets_fn = os.path.join(TMP_DIR, 'targets.txt')
		# maximum dsts per file
		if len(self.targets) > 50e3:
			targets_sets = split_seq(list(self.targets), int(len(self.targets) // 50e3))
		else:
			targets_sets = [self.targets]
		for i,targets_set in enumerate(targets_sets):
			with open(targets_fn, 'w') as f:
				for t in targets_set:
					f.write(t + "\n")
			scamp_cmd = 'scamper -c "ping -c 3" -M {}'\
				' -l peering_interfaces -f {} -O warts -o {} -p 10000'.format(self.trace_msg, 
					targets_fn, outfn + str(i))
			call(scamp_cmd, shell=True)

	def load_targets(self):
		#### Targets fn has format IP, weight (right now nothing is done with weight)
		self.targets = {}
		for row in open(self.targets_fn):
			if row.strip() == "": continue
			ip,nbytes = row.strip().split(',')
			self.targets[ip] = float(nbytes)

	def find_traceroute_targets(self):
		targs = {}
		outdir = os.path.join(MEASUREMENT_DIR, 'traceroute_target_finding')
		for row in open(os.path.join(DATA_DIR, 'routeviews-rv2-20230507-1200.pfx2as'),'r'):
			pfx,pfx_len,asn = row.strip().split('\t')
			targ_to_probe = ".".join(pfx.split('.')[0:3]) + ".1"
			targs[targ_to_probe] = None
		self.targets = list(targs)[0:10000]
		if not os.path.exists(outdir):
			call("mkdir {}".format(outdir), shell=True)
		outfn = os.path.join(outdir, 'all_prefixes_response.warts')
		self._traceroute(outfn)
		warts_out_fns = glob.glob(os.path.join(outdir, "*.warts*"))
		from analyze_results import Campus_Measurement_Analyzer

		cma = Campus_Measurement_Analyzer()
		cma.load_traceroute_helpers()

		all_ips = []
		for waf in warts_out_fns:
			cmd = "sc_warts2json {}".format(waf)
			json_from_warts_out_str = check_output(cmd, shell=True).decode()
			meas_objs = []
			for meas_str in json_from_warts_out_str.split('\n'):
				if meas_str == "": continue
				measurement_obj = json.loads(meas_str)
				if measurement_obj['type'] != 'trace': continue
				all_ips = all_ips + cma.parse_ripe_trace_result(measurement_obj, ret_ips=True)
		cma.lookup_asns_if_needed(list(set(all_ips)))
		good_targets = {}
		for waf in warts_out_fns:
			cmd = "sc_warts2json {}".format(waf)
			json_from_warts_out_str = check_output(cmd, shell=True).decode()
			meas_objs = []
			for meas_str in json_from_warts_out_str.split('\n'):
				if meas_str == "": continue
				measurement_obj = json.loads(meas_str)
				if measurement_obj['type'] != 'trace': continue
				parsed_obj = cma.parse_ripe_trace_result(measurement_obj)
				if parsed_obj['reached_dst_network']:
					good_targets[parsed_obj['dst']] = None
		with open(os.path.join(DATA_DIR, 'whole_ipspace_traceroute_targets.txt'),'w') as f:
			for good_target in good_targets:
				f.write("{}\n".format(good_target))


	def run(self, msmt_type):
		self.load_targets()

		msmt_fn = {
			'traces': self._traceroute,
			'pings': self._ping,
		}[msmt_type]

		tnow = int(time.time())
		out_dir = os.path.join(MEASUREMENT_DIR, "meas-{}".format(tnow))
		if not os.path.exists(out_dir):
			call("mkdir {}".format(out_dir), shell=True)

		out_fns = []
		warts_out_fn = os.path.join(out_dir, '{}.warts'.format(msmt_type))
		msmt_fn(warts_out_fn)
		warts_out_fns = glob.glob(os.path.join(out_dir, '{}.warts*'.format(msmt_type)))
		for fni,waf in enumerate(warts_out_fns):
			cmd = "sc_warts2json {}".format(waf)
			json_from_warts_out_str = check_output(cmd, shell=True).decode()
			meas_objs = []
			for meas_str in json_from_warts_out_str.split('\n'):
				if meas_str == "": continue
				measurement_obj = json.loads(meas_str)
				meas_objs.append(measurement_obj)
			out_fn = os.path.join(out_dir, '{}-{}-{}.json'.format(msmt_type, tnow, fni))
			json.dump(meas_objs, open(out_fn,'w'))

			out_fns.append(out_fn)

		return out_fns

if __name__ == "__main__":
	tc = Traceroute_Conductor("")
	tc.find_traceroute_targets()