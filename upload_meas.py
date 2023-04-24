from google_utilities import *

## todo -- get parent id
def upload_meas(fn, parentid):
    gdrive = get_gdrive()
    upload_file_by_parentid(gdrive, parentid, fn)

if __name__ == "__main__":
    upload_meas('test.out')