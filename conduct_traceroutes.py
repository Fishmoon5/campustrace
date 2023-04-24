import os, time, json
from subprocess import call,check_output
from constants import *

class Traceroute_Conductor:
	def __init__(self, targets_fn):
		self.trace_msg = "tak2154atcolumbiadotedu"
		self.targets_fn = targets_fn


	def _traceroute(self, outfn):
		targets_fn = os.path.join(TMP_DIR, 'targets.txt')
		with open(targets_fn, 'w') as f:
			for t in self.targets:
				f.write(t + "\n")
		scamp_cmd = 'scamper -c "trace -w 2" -M {}'\
			' -l peering_interfaces -f {} -O warts -o {} -p 10000'.format(self.trace_msg, 
				targets_fn, outfn)
		return check_output(scamp_cmd, shell=True)

	def load_targets(self):
		self.targets = {}
		for row in open(self.targets_fn):
			if row.strip() == "": continue
			self.targets[row.strip()] = None
		self.targets = list(self.targets)


	def run(self):
		self.load_targets()

		tnow = int(time.time())
		out_dir = os.path.join(MEASUREMENT_DIR, "meas-{}".format(tnow))
		if not os.path.exists(out_dir):
			call("mkdir {}".format(out_dir), shell=True)
		warts_out_fn = os.path.join(out_dir, 'traces.warts')
		self._traceroute(warts_out_fn)

		cmd = "sc_warts2json {}".format(warts_out_fn)
		json_from_warts_out_str = check_output(cmd, shell=True).decode()
		meas_objs = []
		for meas_str in json_from_warts_out_str.split('\n'):
			if meas_str == "": continue
			measurement_obj = json.loads(meas_str)
			meas_objs.append(measurement_obj)
		out_fn = os.path.join(out_dir, 'traces-{}.json'.format(tnow))
		json.dump(meas_objs, open(out_fn,'w'))

		return out_fn

if __name__ == "__main__":
	tc = Traceroute_Conductor(targets_fn)
	tc.run()