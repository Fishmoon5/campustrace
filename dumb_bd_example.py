from domain_metrics import *
### example I use in the text to explain BC distance
building1 = np.array([.6,.4,0])
building2 = np.array([0,.4,.6])
building3 = np.array([.333,.333,.334])

buildings = [building1,building2,building3]

for i, buildingi in enumerate(buildings):
	for j, buildingj in enumerate(buildings):
		if j >= i: break
		d = 1 - pdf_distance(buildingi,buildingj)
		print("{} vs {} : {}".format(i,j,d))