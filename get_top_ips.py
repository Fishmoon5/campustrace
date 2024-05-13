from google_utilities import *
from constants import *

def get_top_ips_old(parentid, filename='topips_buildingip_inbytes_outbytes.txt'):
    '''
    Return a list of IPs, ordered by the number of bytes being sent to and from.
    '''
    gdrive = get_gdrive()
    gid = get_file_list(gdrive, parentid, name=filename)[0].get('id')
    download_file_by_id(gdrive, gid, filename)
    ips = {}
    with open(filename, 'r') as file:
        for line in file:
            ip,buildingip,nin,nout = line.strip().split(",")
            try:
                ips[ip]
            except KeyError:
                ips[ip] = 0
            ips[ip] += (float(nin) + float(nout))
    return ips

def get_top_ips(parentid, filename='data/flow_info/2024-01.tsv'):
    cache_fn = os.path.join(CACHE_DIR, 'top_ips_cache_list.csv')
    if not os.path.exists(cache_fn):
        import numpy as np, tqdm
        ips = {}
        with open(filename, 'r') as file:
            for row in tqdm.tqdm(file,desc="Finding IPs to probe"):
                fields = row.strip().split('\t')
                if fields[0] == "frame_time": continue
                try:
                    ips[fields[5]] += float(fields[7])
                except KeyError:
                    ips[fields[5]] = float(fields[7])

        ### Keep 99.9% of volume
        all_v = sum(list(ips.values()))
        sorted_ks = list(sorted(ips.items(), key = lambda el : -1 * el[1]))
        sorted_vs = np.array([el[1] for el in sorted_ks])
        cs_v = np.cumsum(sorted_vs) / all_v
        keep_upto = np.where(cs_v > .999)[0][0]
        sorted_ks = sorted_ks[0:keep_upto]
        print("Keeping {} out of {} targets".format(keep_upto, len(ips)))

        new_ips = {k[0]:ips[k[0]] for k in sorted_ks}
        with open(cache_fn, 'w') as f:
            for ip,v in new_ips.items():
                f.write("{}\t{}\n".format(ip,v))
    else:
        new_ips = {}
        for row in open(cache_fn, 'r'):
            ip,v = row.strip().split('\t')
            new_ips[ip] = float(v)

    return new_ips

if __name__ == "__main__":
    get_top_ips('1aLwojyfRyFGBlY0eBlzoYpwjHxFedR-1')