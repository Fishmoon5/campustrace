import pickle,csv
from helpers import *
d = pickle.load(open('tmp.pkl','rb'))
org_to_as = d['orgs']
cases = d['cases']


as_classifications_d = list(csv.DictReader(open('data/AS_Features_032022.csv','r')))
as_classifications = {row['asNumber']: row for row in as_classifications_d}

def get_orgname(asn):
	orgname = ""
	for org in org_to_as.get(asn, [asn]):
		try:
			orgname = as_classifications[org]['Organization']
			break
		except KeyError:
			pass
	return orgname

#(is_eyeball, high_port, nodns)
p2p_cases = [(1,1,1),(1,0,1)]
not_p2p_cases = [(0,0,0),(0,0,1),(0,1,0),(0,1,1),(1,0,0),(1,1,0)]



labels = {
	(0,0,0): "likely web",
	(0,0,1): "likely web",
	(0,1,0): "likely web",
	(0,1,1): "likely web",
	(1,0,0): "probably mislabeled eyeball", # only eyeball suggests its p2p
	(1,1,0): "probably mislabeled eyeball" # only eyeball and port sugggests its p2p
}

for_group_labels = {
	(1,1,1): 'very likely p2p',
	(1,0,1): 'very likely p2p',
	(0,0,0): 'very likely not p2p',
	(0,0,1): 'very likely not p2p',
	(0,1,0): 'high port, otherwise not p2p',
	(0,1,1): 'high port and no DNS, but not eyeball',
	(1,0,0): 'low port, eyeball, with DNS',
	(1,1,0): 'eyeball, high port, with DNS',
}

### probabl mislabeled eyeball --- 2 cases, either weird research/university shit (5%)
### or oddness where its genuinely an eyeball, or just too much to go through (3%)

p2p_traffic = 0
bad_traffic = {case: 0 for case in not_p2p_cases}
total_traffic = 0
not_eyeball_nop2p = {}
eyeball_nop2p = {}
maybe_actually_p2p = {}
each_sub = {0:0,1:0,2:0}

for_group_traffic_shares = {l: 0 for l in for_group_labels.values()}

ignore_asns = [15169,714,7224,23468,54113,34850,2906,
63293,30103,16625,36183,11251,38369,22822,395747,6307,132591,
55256,53813,59798,139341,396356,16276,60068,20446,62,62715,202018,209242,139057,39572,
63018,49797,19437,54994]
ignore_asns = [str(el) for el in ignore_asns]
for asn in list(cases):
	if len(get_intersection(org_to_as.get(asn,[asn]), ignore_asns)) > 0:
		for case in list(cases[asn]):
			if case[0]:
				try:
					cases[asn][(0,case[1],case[2])] += cases[asn][case]
				except KeyError:
					cases[asn][(0,case[1],case[2])] = cases[asn][case]
				cases[asn][case] = 0
	for case,nb in cases[asn].items():
		for i in range(3):
			if case[i]:
				each_sub[i] += nb
	for p2p_case in p2p_cases:
		p2p_traffic += cases[asn].get(p2p_case,0)
	for not_p2p_case in not_p2p_cases:
		bad_traffic[not_p2p_case] += cases[asn].get(not_p2p_case,0)
	for case in cases[asn]:
		for_group_traffic_shares[for_group_labels[case]] += cases[asn][case]
	not_eyeball_nop2p[asn] = cases[asn].get((False,1,1),0)
	eyeball_nop2p[asn] = cases[asn].get((True,0,0),0)
	eyeball_nop2p[asn] += cases[asn].get((True,1,0),0)
	maybe_actually_p2p[asn] = cases[asn].get((False,1,1),0)
	total_traffic += sum((cases[asn].values()))


print("P2P:")
print(100*p2p_traffic / total_traffic)


for k in for_group_traffic_shares:
	print("{} -- {}".format(k,100*for_group_traffic_shares[k]/total_traffic))
print({k:round(v*100/total_traffic,2) for k,v in bad_traffic.items()})

by_hr_label = {}
for case,v in bad_traffic.items():
	try:
		by_hr_label[labels[case]] += v
	except KeyError:
		by_hr_label[labels[case]] = v

print({k:round(v*100/total_traffic,2) for k,v in by_hr_label.items()})


print("\n")
print("maybe actually p2p")
for asn,v in sorted(maybe_actually_p2p.items(), key = lambda el : -1 * el[1])[0:20]:
	orgname = get_orgname(asn)
	print("{} {} {} {}".format(asn,org_to_as.get(asn,[]), v*100/total_traffic,orgname))

print("not eyeball no p2p")
for asn,v in sorted(not_eyeball_nop2p.items(), key = lambda el : -1 * el[1])[0:20]:
	orgname = get_orgname(asn)
	print("{} {} {} {}".format(asn,org_to_as.get(asn,[]), v*100/total_traffic,orgname))

print("\nEyeball no p2p")
for asn,v in sorted(eyeball_nop2p.items(), key = lambda el : -1 * el[1])[0:20]:
	orgname = get_orgname(asn)
	print("{} {} {} {}".format(asn,org_to_as.get(asn,[]), v*100/total_traffic,orgname))

print({k:v/total_traffic for k,v in each_sub.items()})