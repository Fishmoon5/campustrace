from google_utilities import *
import tqdm, os
from constants import *
parent_id = "1M5RP4UyKL_3fHzqKLNctEtwG_4A5hhi_"
gdrive = get_gdrive()
files = get_file_list(gdrive, parent_id)

times_of_interest = ['1684845466','1684980072']


fs_of_interest = ['2024-01.tsv','2023-12.tsv','2023-11.tsv']
for fn in tqdm.tqdm(files,desc="Downloading files from cloud."):
	dlfn = fn['originalFilename']
	if dlfn in fs_of_interest:
		out_fn = os.path.join(DATA_DIR, 'flow_info', dlfn)
		download_file_by_id(gdrive, fn['id'], out_fn)