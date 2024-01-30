import os
from pydrive.drive import GoogleDrive
from pydrive.auth import GoogleAuth
from subprocess import call

## from here https://github.com/Fishmoon5/autofetch_gdrive

def get_gdrive():
	gauth = GoogleAuth()
	gauth.LoadCredentialsFile("mycreds.txt")
	if gauth.credentials is None:
		# Authenticate if they're not there
		gauth.CommandLineAuth()
	elif gauth.access_token_expired:
		# Refresh them if expired
		gauth.Refresh()
	else:
		# Initialize the saved creds
		gauth.Authorize()
	gauth.SaveCredentialsFile("mycreds.txt")
	gdrive = GoogleDrive(gauth)
	return gdrive

def get_file_list(gdrive, parentid, name=None, orderby=None):
	query = f"'{parentid}' in parents and trashed=false"
	if name is not None:
		query += f" and title = '{name}'"
	listdict = {'q': query}
	if orderby is not None:
		listdict['orderBy'] = orderby
	try:
		file_list = gdrive.ListFile(listdict).GetList()
		return file_list
	except:
		import traceback
		traceback.print_exc()
		return []

def download_file_by_id(gdrive, gid, dst, gdl=False):
	''' force write if exists'''
	if gdl:
		dirname = os.path.dirname(dst)
		call(f'gdl -q -o -d {dirname} {gid}', shell=True)
	else:
		downloaded = gdrive.CreateFile({'id': gid}) # adding 'title' parameter does not actually change the title
		downloaded.GetContentFile(dst)

def upload_file_by_parentid(gdrive, parentid, local_path, gupload=False):
	'''force write if exists online'''
	if gupload:
		os.system(f'gupload -q {local_path} -r {parentid}')
	else:
		uploaded = gdrive.CreateFile({'parents': [{'id': parentid}], 'title': os.path.basename(local_path)}) # can add title to edit name; otherwise, title is the name of local file
		uploaded.SetContentFile(local_path)
		uploaded.Upload()

def upload_file_by_id(gdrive, gid, local_path):
	''' force write if exists online'''
	uploaded = gdrive.CreateFile({'id': gid})
	uploaded.SetContentFile(local_path)
	uploaded.Upload()

def download_folder_by_id(gdrive, folder_id, folder_name, gdl=False):
	file_list = gdrive.ListFile({'q': "'{}' in parents and trashed=false".format(folder_id)}).GetList()
	for file in file_list: 
		title = file.get('title')
		download_file_by_id(gdrive, file.get('id'), f'data/{folder_name}/{title}', gdl)