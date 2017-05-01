#!/usr/bin/python
import requests, sys

# enter the API key provided by your API gateway
k 		= {'x-api-key': 'YOUR_API_KEY'}
# enter the URL used by your API gateway
u		= 'https://xxz6rzgcn6.execute-api.us-east-1.amazonaws.com/prod/DevelopmentFirewallUpdater'
##### do not touch anything below this line #####

def whitelist():
	r 	= requests.get(u, headers = k)
	print r.content

whitelist()
