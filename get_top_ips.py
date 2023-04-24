from google_utilities import *

def get_top_ips(parentid, filename='top_ips.txt'):
    '''
    Return a list of IPs, ordered by the number of bytes being sent to and from.
    '''
    gdrive = get_gdrive()
    gid = get_file_list(gdrive, parentid, name=filename)[0].get('id')
    download_file_by_id(gdrive, gid, filename)
    ips = []
    with open(filename, 'r') as file:
        for line in file:
            ips.append(line.strip('\n'))
    return ips

if __name__ == "__main__":
    get_top_ips('1aLwojyfRyFGBlY0eBlzoYpwjHxFedR-1')