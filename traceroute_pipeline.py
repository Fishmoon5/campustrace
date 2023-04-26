from constants import *
from get_top_ips import get_top_ips
from upload_meas import upload_meas
from conduct_traceroutes import Traceroute_Conductor

import time, os


def run_pipeline():

	ip_addrs = get_top_ips(top_ips_folder_id)

	tnow = int(time.time())
	targets_fn = os.path.join(DATA_DIR,'targets_list','targets-{}.txt'.format(tnow))
	with open(targets_fn, 'w') as f:
		for t in ip_addrs:
			f.write(t + "\n")

	tc = Traceroute_Conductor(targets_fn)
	out_fns = tc.run()
	for out_fn in out_fns:
		upload_meas(out_fn,traceroute_meas_folder_id)

if __name__ == "__main__":
	run_pipeline()