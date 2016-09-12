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
from vectors import vectors
import urllib
import datetime
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
	c.execute("create table IF NOT EXISTS vulnerable_xss (domain TEXT, url TEXT, variable TEXT, payload TEXT, method TEXT) ")
	c.execute("INSERT INTO vulnerable_xss (domain, url, variable, payload, method) VALUES (?,?,?,?,?)", row)
	conn.commit()
	conn.close()


def check4xss(req, key):
	#check the Status on web response
	#200 = OK
	if req.status_code == 200:  
		#find the hashed key in the web content
		#to ensure that atack was successful
		if key in req.text:
			return True
		else:
			return False
	else:
		return False


#
def analize_url(url, cookies ,database):
	#initialize check to request web
	safe = True
	global urls
	threads = []
	parsedurl = urlparse(url)
	print('--------------------------------------------------\n')
	print('Analyzing url: ', url)
	print('--------------------------------------------------\n')	

	#check if it is a valid url to analize
	if parsedurl.scheme == "http" or parsedurl.scheme == "https":
	
		#generate a hashed key to identify if the atack was successful
	   	
		hashed_key =  hashlib.md5((str(datetime.datetime.now()) + 'XSS').encode('UTF-8')).hexdigest()
		#save domain
		domain = get_tld(url)


		#parse every parameter in the url
		params = urllib.parse.parse_qsl(parsedurl.query)

		if not params:
			#no parameters to analyze
			print('No parameters to analyze found for ', url)
		else:
			if len(params) == 1:
				#only one parameter in the URL 
				parameter = params[0]
				#parameter is a tuple (param, value)

				#atack the url changing the value for the parameter using method GET
				for vector in vectors:
					#every vector has a payload, and information about the vulnerable browser
					#example:
					#{ 'payload':'''">PAYLOAD''','browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""}
					
					#prepare the atack payload
					atack = vector['payload'].strip()

					#replace "payload" with hashed key
					atack = atack.replace("PAYLOAD", hashed_key)
					plain_url = parsedurl.scheme + '://'+ parsedurl.netloc + parsedurl.path
					
					#Method: GET 
					#send request using GET
					payload = {parameter[0]: atack}
					
					if cookies:
						req = requests.get(plain_url, params=payload, cookies=cookies)
					else:
						req = requests.get(plain_url, params=payload) 					

					#print(req.text)
					#check if the result was a sucessfull atack 
					if check4xss(req, hashed_key):
						#save to database	
						row = (domain ,plain_url, parameter[0], atack, 'GET')	
						save_url(row,database)

					#Method: POST

					#send request using POST			
					payload = {parameter[0]: atack}

					if cookies:
						req = requests.post(plain_url, params=payload, cookies=cookies)
					else:
						req = requests.post(plain_url, params=payload) 					
					#check if the result was a sucessfull atack 

					if check4xss(req, hashed_key):
						#save to database	
						row = (domain ,plain_url, parameter[0], atack, 'POST')	
						save_url(row,database)
			

			else:
				#check for every parameter in the url			
				for parameter in params:
					#copy original parameters and values
					params2 = params
					#get the index in the list
					i = params.indexof(parameter)

					#atack the url changing the value for the parameter using method GET
					for vector in vectors:
						#every vector has a payload, and information about the vulnerable browser
						#example:
						#{ 'payload':'''">PAYLOAD''','browser':"""[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"""}
						
						#prepare the atack payload
						atack = vector['payload'].strip()

						#replace "payload" with hashed key
						atack = atack.replace("PAYLOAD", hashed_key)
						plain_url = parsedurl.scheme + '://'+ parsedurl.netloc + parsedurl.path
						parameter[1] = atack
						params2[i] = parameter
						
						
						#prepare the payload
						payload = {}
						for parameter2 in params2:
							
							payload.update({parameter2[0]:parameter[1]})

						#Method: GET 
						#send request using GET
						

						if cookies:
							req = requests.get(plain_url, params=payload, cookies=cookies)
						else:
							req = requests.get(plain_url, params=payload) 					

						#print(req.text)
						#check if the result was a sucessfull atack 
						if check4xss(req, hashed_key):
							#save to database	
							row = (domain ,plain_url, parameter[0], atack, 'GET')	
							save_url(row,database)


						#Method: POST

						#send request using POST			
						if cookies:
							req = requests.post(plain_url, params=payload, cookies=cookies)
						else:
							req = requests.post(plain_url, params=payload) 					
						#check if the result was a sucessfull atack 

						if check4xss(req, hashed_key):
							#save to database	
							row = (domain ,plain_url, parameter[0], atack, 'POST')	
							save_url(row,database)
			
		#check the vulnerabily in the rest of the links	
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
					#print('L acquire')
					l.acquire()
					hashurl = (hashlib.md5(link.encode('UTF-8'))).hexdigest()
					if(hashurl not in urls):
			    		#add link to urls
						urls.append(hashurl)
						#print('L release')
						l.release()
						#check semaphore count
						#print('sem acquire')
						sem.acquire()
						#create a new thread and analize the url
						t = threading.Thread(target=analize_url,  args=(link,cookies,database))
				    	
						#save created thread
						threads.append(t)
						t.start()
					else :
						#print('L acquire')
						l.release()	

	#wait for every thread to finish before closing main.
	for t in threads:
		t.join()
	
	#realease semaphore 
	#print('sem release')
	sem.release()

def main(docopt_args):
	cookies				= docopt_args['--c']
	url 				= docopt_args['--u']
	nthreads         	= docopt_args['--t']

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
		print('Error conecting to database.')
		sys.exit(1)
	conn.close()
	#print('sem acquire')
	sem.acquire()
	#analize main url
	analize_url(url, cookies, database)
	
	#print stored results
	conn = sqlite3.connect(database)
	cursor = conn.cursor()

	domain = get_tld(url)
	cursor.execute("create table IF NOT EXISTS vulnerable_xss (domain TEXT, url TEXT, variable TEXT, payload TEXT, method TEXT) ")
	cursor.execute("select domain, url, variable, payload, method from vulnerable_xss where domain = '%s'" % domain )

	col_names = [cn[0] for cn in cursor.description]
	rows = cursor.fetchall()

	print('Results:\n')
	print(tabulate(rows, headers = col_names))
	conn.close()



if __name__ == "__main__":
  args = docopt(__doc__, version='Version 1.0')
  main(args)
