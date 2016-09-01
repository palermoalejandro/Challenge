#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Usage:
        challenge.py -h
        challenge.py -v
        challenge.py [--c=<cookies>] --u=<url> --t=<trheads> 


    Options:
        -h,--help                     : show this help message
        -v, --version                 : show code version

    Arguments:
        [--c=<cookies>]        					: Dict of cookies 
        --u=<url>           					: Url to processed
        --t=<nthreads>                    		: Max amount of simultaneous threads to create
"""


from docopt import docopt
from threading import Thread, Lock, Semaphore
from urllib.parse import urlparse
from tld.utils import update_tld_names
from bs4 import BeautifulSoup
from tld import get_tld
from tabulate import tabulate
import urllib
import threading
import requests
import sys
import hashlib
import sqlite3




#define global semaphores
l = threading.Lock() 
sem = threading.Semaphore()

#shared list with the hash of the analized urls
urls = []

def save_url(row, database):
	conn = sqlite3.connect(database)
	c = conn.cursor()
	c.execute("create table IF NOT EXISTS vulnerable_xss (domain TEXT, url TEXT, variable TEXT, data TEXT) ")
	c.execute("INSERT INTO vulnerable_xss (domain, url, variable, data) VALUES (?,?,?,?)", row)
	conn.commit()
	conn.close()

#checks for posible xss vulnerabiltys on the string parameter
#searching for kwnown dangerous characters.
def check4xss(parameter, tags):
	res = False
	aux = ''
	soup = BeautifulSoup(parameter, 'html.parser')
	if soup.find_all(True):
		#search for every tag an check if it is allowed
		for foundtag in soup.find_all(True):
			if foundtag.name not in tags.keys():
				res = True
			else:
				attributes = []
				attributes = tags[foundtag.name]
				#for every allowed tag, check its attributes
				for attr in foundtag.attrs:
					if attr not in attributes:
						res = True
					else:
						#save a copy of the original value
						aux = foundtag.attrs[attr]
						#replace every special character and whitespace
						aux = aux.replace(' ', '')
						aux = aux.replace('\t', '')
						aux = aux.replace('\n', '')
						aux = aux.replace('\r', '')
						aux = aux.replace('\0', '')
						aux = aux.replace('\x0b', '') 
						aux = aux.replace('\x0c', '')
						#turn value to upper case
						aux = aux.upper()
						#check for javaScript, VBscript tags in the url
						if 'JAVASCRIPT' in aux:
							res = True
						if 'VBSCRIPT' in aux:
							res = True
						if 'LIVESCRIPT' in aux:
							res = True			
	else:
		#save a copy of the original value
		aux = parameter
		#replace every special character and whitespace
		aux = aux.replace(' ', '')
		aux = aux.replace('\t', '')
		aux = aux.replace('\n', '')
		aux = aux.replace('\r', '')
		aux = aux.replace('\0', '')
		aux = aux.replace('\x0b', '') 
		aux = aux.replace('\x0c', '')		
		#turn value to upper case
		aux = aux.upper()

		#check for javaScript, VBscript tags in the url
		if 'JAVASCRIPT' in aux:
			res = True
		if 'VBSCRIPT' in aux:
			res = True
		if 'LIVESCRIPT' in aux:
			res = True		
	return res


#
def analize_url(url, cookies ,database, tags):
	#initialize check to request web
	safe = False
	global urls
	threads = []
   	
   	#save domain
	domain = get_tld(url)

	parsedurl = urlparse(url)
	#parse every parameter in the url
	params = urllib.parse.parse_qsl(parsedurl.query)

	if not params:
		row = (domain ,url, 'path', parsedurl.path) 
		if check4xss(parsedurl.path, tags):
			save_url(row, database)
		else:
			#if no xss found, request web
			safe = True
	else:
		for parameter in params:
			#parameter is a tuple (param, value)
			row = (domain ,url, parameter[0], parameter[1])	

			if check4xss(parameter[1],tags):
				#save to database	
				save_url(row,database)
			else:
				#if no xss found, request web
				safe = True

	#after checking parameters and path its safe to continue		
	if safe:
		if(cookies):
			#load cookies as a cookie jar	
			cookiejar = requests.utils.cookiejar_from_dict(cookies)
			request = requests.get(url, cookies = cookiejar)
		else:
			request = requests.get(url)

		#Parse the html response 
		parsedHtml = BeautifulSoup(request.text, 'html.parser')

		links = []

		#find all links on the web
		for link in parsedHtml.find_all('a'):
			links.append(link.get('href'))
		for link in links:
			if link:
				if domain == get_tld(link,fail_silently=True):
					#check if the url was alredy analized
					l.acquire()
					hashurl = (hashlib.md5(link.encode('UTF-8'))).hexdigest()
					if(hashurl not in urls):
			    		#add link to urls
						urls.append(hashurl)
						l.release()
						#check semaphore count
						sem.acquire()
						#create a new thread and analize the url
						t = threading.Thread(target=analize_url,  args=(link,cookies,database,tags))
				    	
						#save created thread
						threads.append(t)
						t.start()
					else :
						l.release()	

	#wait for every thread to finish before closing main.
	for t in threads:
		t.join()

	#realease semaphore 
	sem.release()

def main(docopt_args):
	cookies				= docopt_args['--c']
	url 				= docopt_args['--u']
	nthreads         	= docopt_args['--t']

	#config for white-list HTML tags and Attributes
	tags = {'a' : ['href'] , 'b': ['font-weight'] , 
	'br': ['class','id', 'style', 'hidden'], 
	'em': ['class','id', 'style', 'hidden'], 
	'i': ['class','id', 'style', 'hidden'], 
	'mark': ['class','id', 'style', 'hidden'], 
	'p': ['class','id', 'style', 'hidden'], 
	'span': ['class','id', 'style', 'hidden'], 
	'strong': ['class','id', 'style', 'hidden'] }

    #update tld names
	update_tld_names()
	
	#assing value to the semaphore.
	global sem
	sem = Semaphore(int(nthreads))
	#save to url 
	global urls
	urls.append((hashlib.md5(url.encode('UTF-8'))).hexdigest())
	#conect to database
	database = 'vulnerablexss.db'
	conn = sqlite3.connect(database)
	if not conn:
		print('Error conectando a base de datos.')
		sys.exit(1)
	conn.close()
	sem.acquire()
	#analize main url
	analize_url(url, cookies,database, tags)
	
	#print stored results
	conn = sqlite3.connect(database)
	cursor = conn.cursor()

	domain = get_tld(url)
	cursor.execute("select * from vulnerable_xss where domain = '%s'" % domain )

	col_names = [cn[0] for cn in cursor.description]
	rows = cursor.fetchall()

	print('Results:\n')
	print(tabulate(rows, headers = col_names))
	conn.close()



if __name__ == "__main__":
  args = docopt(__doc__, version='Version 1.0')
  main(args)
