from subprocess import call
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
			f.write("{},{}\n".format(t, ip_addrs[t]))

	all_targets_fn = os.path.join(DATA_DIR, 'whole_ipspace_traceroute_targets.txt')

	
	for msmt_type in ['traces-all', 'traces','pings']:
		print("Running measurement type {}".format(msmt_type))

		if msmt_type == 'traces-all':
			fn = all_targets_fn
		else:
			fn = targets_fn
		tc = Traceroute_Conductor(fn)
		out_fns = tc.run(msmt_type)
		for out_fn in out_fns:
			for _try in range(10):
				print("Uploading {}, attempt {}".format(out_fn,_try))
				try:
					upload_meas(out_fn,traceroute_meas_folder_id)
					break
				except:
					import traceback
					traceback.print_exc()
					continue
		out_dir = "/".join(out_fns[0].split("/")[0:-1])

		call("rm -rf {}".format(out_dir), shell=True)
		break
	call("rm {}".format(targets_fn),shell=True)

if __name__ == "__main__":
	run_pipeline()