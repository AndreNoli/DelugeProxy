# DelugeProxy
**DelugeProxy** is a *defence reverse proxy* server with the aim of deceiving these security scanners into thinking that the attack was successful for each tentative.

**DelugeProxy** is configured to detect some attacks that aim to exploit some of the most common web vulnerabilities.

The web vulnerabilities covered by **DelugeProxy** are:
- **SQL Injection**
- **Cross-Site Scripting**
- **Path Traversal**
- **Command Injection**
- **Local File Inclusion**

Once configured on a web application, for each incoming request, **DelugeProxy** will perform a security check on each parameter of the request before redirecting it to the web application. These checks are performed using **RegEx** (specified in  *`traps/payloads.json`*) specially developed to catch many of the web attacks listed above. Using these RegEx, **DelugeProxy** can distinguish requests that could be malicious from safe ones.

![Steps_Proxy](https://user-images.githubusercontent.com/50990652/202847321-faba10d8-1593-4234-8a90-0adc0e510422.jpeg)

This behavior is very similar to the general approach of WAFs (Web Application Firewalls). The difference is that, instead of blocking "malicious" requests, **DelugeProxy** responds with pages containing trap data, that aim to fool automated security analysis tools.

Well-formed requests and those deemed "*malicious*" are logged in the *`logs/access.log`* and *`logs/malicious.log`* files, respectively.

# Configuration
**DelugeProxy** configuration is done server-side.

For the configuration, it is necessary to expose it as a service on the same port as the web application, that you want to protect, to replace it for external users. Then change that of the web application to another port (*specifying to listen only locally*).

### An example of Apache2 configuration in an operating system based on the Linux kernel

#### **`/etc/apache2/site-enables/000-default.conf`**

```
<VirtualHost *:80>
        ServerName webapp.name
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/flaskapp
	WSGIDaemonProcess flaskapp threads=5
        WSGIScriptAlias / /var/www/flaskapp/flaskapp.wsgi
        WSGIApplicationGroup %{GLOBAL}
        <Directory flaskapp>
             WSGIProcessGroup flaskapp
             WSGIApplicationGroup %{GLOBAL}
             Order deny,allow
             Allow from all 
        </Directory>
	ErrorLog ${APACHE_LOG_DIR}/error.log
        Header set Access-Control-Allow-Origin "*"
</VirtualHost>

<VirtualHost 127.0.0.1:9000>
	ServerName webapplocal.name
	DocumentRoot /var/www/webapp
	<Directory /var/www/webapp>
		Options Indexes MultiViews FollowSymLinks
		AllowOverride Limit Options FileInfo
		DirectoryIndex index.php
	</Directory>
</VirtualHost>
```

#### **`/etc/apache2/ports.conf`**
```
# If you just change the port or add more ports here, you will likely also
# have to change the VirtualHost statement in
# /etc/apache2/sites-enabled/000-default.conf

Listen 80
Listen 127.0.0.1:9000

<IfModule ssl_module>
        Listen 443
</IfModule>

<IfModule mod_gnutls.c>
        Listen 443
</IfModule>
```

In **`flaskapp.py`**, is necessary to set the value of the following variables:

- *`site_port`* : with the value of the new site port
- *`proxyaddress`* : with ip address of the server where it is hosted
- *`proxydomain`* : with the name specified by *`ServerName`*
- *`function_mode`* :
    - "*`On`*" if **DelugeProxy** should respond to fake data requests it deems malicious.
    - "*`Off`*" if **DelugeProxy** should only log requests it deems malicious to separate files.
- *`whitelist`* : with the path of the web pages where **DelugeProxy** must not block requests by responding with fake data
