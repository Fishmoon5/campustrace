from helpers import *
import scipy.stats as ss
import rbo

def cosine_similarity(arr1, arr2, **kwargs):
	d = np.sum(arr1 * arr2 / \
		(np.linalg.norm(arr1) * np.linalg.norm(arr2)))
	return d

def weighted_jaccard(arr1, arr2, **kwargs):

	n_doms = kwargs.get('n_doms')
	if n_doms is None:
		raise ValueError("Need to specify number of domains for Jaccard")
	top_n_domsi = np.argsort(arr1[:])[::-1][0:n_doms]
	top_n_domsj = np.argsort(arr2[:])[::-1][0:n_doms]
	i = get_intersection(top_n_domsi, top_n_domsj)
	u = set(list(top_n_domsi) + list(top_n_domsj))

	vbi_inter = sum(arr1[_i] for _i in i)
	vbj_inter = sum(arr2[_i] for _i in i)
	vbi_union = sum(arr1[_i] for _i in top_n_domsi)
	vbj_union = sum(arr2[_i] for _i in top_n_domsj)
	vi = vbi_inter + vbj_inter
	vu = vbi_union + vbj_union
	d = vi/vu
	return d				

def jaccard(arr1, arr2, **kwargs):
	n_doms = kwargs.get('n_doms')
	if n_doms is None:
		raise ValueError("Need to specify number of domains for Jaccard")
	top_n_domsi = np.argsort(arr1[:])[::-1][0:n_doms]
	top_n_domsj = np.argsort(arr2[:])[::-1][0:n_doms]
	i = get_intersection(top_n_domsi, top_n_domsj)
	u = set(list(top_n_domsi) + list(top_n_domsj))

	d = len(i) / len(u)
	return d				

def euclidean(arr1, arr2, **kwargs):
	d = np.linalg.norm(arr1[:]/np.linalg.norm(arr1[:]) - \
			arr2[:]/np.linalg.norm(arr2[:]))
	d = 1 - d
	return d				


### WRONG
def spearman(arr1, arr2, **kwargs):
	ranked_domsi = ss.rankdata(arr1)
	ranked_domsj = ss.rankdata(arr2)

	dists = ranked_domsi - ranked_domsj
	n = len(dists)

	d = 1 - 6 * np.sum(np.square(dists)) / (n * (n**2 - 1))
	return d

def rbo_wrap(arr1, arr2, **kwargs):
	n_doms = kwargs.get('n_doms')
	if n_doms is None:
		raise ValueError("Need to specify number of domains for RBO")
	top_n_domsi = np.argsort(arr1[:])[::-1][0:n_doms]
	top_n_domsj = np.argsort(arr2[:])[::-1][0:n_doms]

	# wts = kwargs.get('global_domain_traffic')
	# d = rbo.RankingSimilarity(top_n_domsi, top_n_domsj).rbo(wts=wts)

	wts = kwargs.get('global_domain_traffic_dict')
	d = rbo.RankingSimilarity(top_n_domsi, top_n_domsj).rbo_wtd(wts=wts)

	return d
