from google_utilities import *
import tqdm, os
from constants import *
parent_id = "1M5RP4UyKL_3fHzqKLNctEtwG_4A5hhi_"
gdrive = get_gdrive()
files = get_file_list(gdrive, parent_id)

months_of_interest = ['2022-12', '2023-01','2023-02',
			'2023-03','2023-04', '2023-05', '2023-06', '2023-07', 
			'2023-11', '2023-12', '2024-01']
fs_of_interest = list([el + '.tsv' for el in months_of_interest])
# fs_of_interest = ['2022-Oct_hour-10_building-set-0_ip-dns-dnscname-sni-hour-bytes-flows-ports.p']
for fn in tqdm.tqdm(files,desc="Downloading files from cloud."):
	dlfn = fn['title']
	if dlfn in fs_of_interest:
		out_fn = os.path.join(DATA_DIR, 'flow_info', dlfn)
		if dlfn not in os.listdir(os.path.join(DATA_DIR, 'flow_info')):
			print("Downloading {} to {}".format(dlfn,out_fn))
			download_file_by_id(gdrive, fn['id'], out_fn)