from flask import Flask, url_for,request,render_template, redirect, Response, json
from datetime import datetime
from dotenv import load_dotenv
import os
import requests
import urllib
import time
import re
import argparse
import socket

app = Flask(__name__)

# Function mode - [if the function_mode is different from 'On' the proxy will only work in detectionOnly function_mode]
function_mode = 'On'

# Whitelist pages - [on these pages the reverse proxy will work in DetectionOnly function_mode]
# Example of usage:
# whitelist = ['vulnerabilities/fi/','vulnerabilities/xss_r/']
whitelist = ['']

# port of the site on which to configure the reverse proxy
site_port = 9000

# path of the log files where HTTP requests are saved
ACCESS_LOG = '/var/www/flaskapp/log/access.log'
TRAPS_LOG = '/var/www/flaskapp/log/traps.log'

# Reverse Proxy Address
proxyaddress = 'http://192.168.75.141'

# Reverse Proxy Domain
proxydomain = 'http://application.protected'

# Site Default Folder
indexfolder = 'index.php'

# Trap Page Template Name
honeytrap_template = 'proxy.php'

# Custom variables for the template trap
title_tab = 'Welcome :: Damn Vulnerable Web Application'
title_page = 'Welcome to Damn Vulnerable Web Application!'
image_trap = 'images/logo.jpeg'

# Seconds of sleep
sleep_seconds = 10

sitename = 'http://127.0.0.1:' + str(site_port)

def save_access_log(request, filetype="access"):
    if filetype == 'access':
        LOG_FILE = ACCESS_LOG
    else: 
        LOG_FILE = TRAPS_LOG

    with open(LOG_FILE, 'a+', encoding='UTF-8') as access_file:
            datetime_ = datetime.now().strftime("%d/%b/%Y %H:%M:%S")
            if request.method == 'GET':
                print(f'{request.remote_addr} - - [{datetime_}] "{request.method} {request.url}" Cookies: {dict(request.cookies)}', file=access_file)
            elif request.method == 'POST':
                args = request.form
                dict_args = args.to_dict(flat=False) 
                print(f'{request.remote_addr} - - [{datetime_}] "{request.method} {request.url} data={dict_args} Cookies: {dict(request.cookies)}"', file=access_file)
            else:
                print(f'{request.remote_addr} - - [{datetime_}] "{request.method} {request.url}" {request.form} Cookies: {dict(request.cookiers)}', file=access_file)


@app.route('/', defaults={'path': indexfolder}, methods=['POST', 'GET'])
@app.route('/<path:path>', methods=['POST', 'GET'])
def routing_proxy(path):
    
    add_csp = False
    
    headers={
            "User-Agent": f"{request.user_agent}",
            "Content-Type": "application/x-www-form-urlencoded",
            }

    if request.method == 'GET':
        args = request.args    
    else:
        args = request.form
    
    dict_args = args.to_dict(flat=False)

    with app.open_resource('traps/payloads.json') as file:
        data = json.load(file)
        for key_json in data.keys():
            for vulnerabilities,info in data[key_json].items():
                regexp = re.compile(info['pattern'],re.IGNORECASE)
                for key_param, value_param in dict_args.items():
                    for single_parameter in value_param:
                        if regexp.search(single_parameter):
                            save_access_log(request, filetype='traps')
                            if function_mode == 'On':
                                if path in whitelist:
                                    break
                                else:    
                                    if vulnerabilities == 'Cross-Site-Scripting (XSS)':
                                        #add_csp = True
                                        return render_template(honeytrap_template, payload=single_parameter, title=title_tab, title_page=title_page, image_url=image_trap)
                                        #break
                                    elif vulnerabilities == 'Timing Attack':
                                        time.sleep(sleep_seconds)
                                    return render_template(honeytrap_template, payload=info['content'], title=title_tab, title_page=title_page, image_url=image_trap)
                                
    if request.method == 'GET':
        if(proxyaddress in request.url):
            address = (request.url).replace(proxyaddress,sitename)
        if(proxydomain in request.url):
            address = (request.url).replace(proxydomain,sitename)
        resp = requests.get(address, headers=headers)

    else:
        json_str = json.dumps(dict_args).replace('[','').replace(']','')
        data = json.loads(json_str)        
        dataenc = urllib.parse.urlencode(data)
        resp = requests.post(f'{sitename}/{path}',data=dataenc, headers=headers)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in  resp.raw.headers.items() if name.lower() not in excluded_headers]
    response = Response(resp.content, resp.status_code, headers)
    
    if (add_csp):
        response.headers['Content-Security-Policy'] = "script-src 'self'"
    else:
        save_access_log(request)

    return (response)
    
    
if __name__ == '__main__':
    app.run()
