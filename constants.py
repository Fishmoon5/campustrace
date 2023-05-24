CACHE_DIR = "cache"
DATA_DIR = "data"
MEASUREMENT_DIR = "measurements"
TMP_DIR = "tmp"

## google drive folder IDs
top_ips_folder_id = '1aLwojyfRyFGBlY0eBlzoYpwjHxFedR-1'
traceroute_meas_folder_id = '11b36E_oG1QqsqOMlpWghIjKycHn5mDjm'

private_ips = [("0.0.0.0", 8), ("10.0.0.0", 8), ("100.64.0.0", 10), ("127.0.0.0",8), ("169.254.0.0",16),
	("172.16.0.0", 12), ("192.0.0.0", 24), ("192.0.2.0", 24), ("192.88.99.0", 24), ("192.168.0.0", 16), ("198.18.0.0", 15),
	("198.51.100.0", 24), ("203.0.113.0", 24), ("240.0.0.0",4), ("255.255.255.255", 32), ("224.0.0.0",4),
	("25.0.0.0",8)]

MARKERSTYLES = ['<', 'o', '>', '+', '*' , '2']