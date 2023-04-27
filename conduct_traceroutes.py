import os, time, json, glob
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
		targets_sets = split_seq(self.targets, int(len(self.targets) // 50e3))
		for i,targets_set in enumerate(targets_sets):
			with open(targets_fn, 'w') as f:
				for t in targets_set:
					f.write(t + "\n")
			scamp_cmd = 'scamper -c "trace -w 2" -M {}'\
				' -l peering_interfaces -f {} -O warts -o {} -p 10000'.format(self.trace_msg, 
					targets_fn, outfn + str(i))
			call(scamp_cmd, shell=True)

	def load_targets(self):
		self.targets = {}
		for row in open(self.targets_fn):
			if row.strip() == "": continue
			self.targets[row.strip()] = None
		self.targets = list(self.targets)[0:10000]


	def run(self):
		self.load_targets()

		tnow = int(time.time())
		out_dir = os.path.join(MEASUREMENT_DIR, "meas-{}".format(tnow))
		if not os.path.exists(out_dir):
			call("mkdir {}".format(out_dir), shell=True)

		warts_out_fn = os.path.join(out_dir, 'traces.warts')
		self._traceroute(warts_out_fn)
		warts_out_fns = glob.glob(os.path.join(out_dir, 'traces.warts*'))
		out_fns = []
		for fni,waf in enumerate(warts_out_fns):
			cmd = "sc_warts2json {}".format(waf)
			json_from_warts_out_str = check_output(cmd, shell=True).decode()
			meas_objs = []
			for meas_str in json_from_warts_out_str.split('\n'):
				if meas_str == "": continue
				measurement_obj = json.loads(meas_str)
				meas_objs.append(measurement_obj)
			out_fn = os.path.join(out_dir, 'traces-{}-{}.json'.format(tnow, fni))
			json.dump(meas_objs, open(out_fn,'w'))

			out_fns.append(out_fn)

		return out_fns

if __name__ == "__main__":
	tc = Traceroute_Conductor(targets_fn)
	tc.run()