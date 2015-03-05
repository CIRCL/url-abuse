#URL Abuse

URL Abuse is a versatile free software for URL review, analysis and black-list reporting. URL Abuse is composed of a web interface where requests are submitted asynchronously and a back-end system to process the URLs into features modules.

## Features

 - HTTP redirects analysis and follows
 - [Google Safe-Browsing](https://developers.google.com/safe-browsing/) lookup
 - [Phishtank](http://www.phishtank.com/api_info.php) lookup
 - [VirusTotal](https://www.virustotal.com/en/documentation/public-api/) lookup and submission
 - [URL query](https://github.com/CIRCL/urlquery_python_api/) lookup
 - [CIRCL Passive DNS](http://www.circl.lu/services/passive-dns/) lookup
 - [CIRCL Passive SSL](http://www.circl.lu/services/passive-ssl/) lookup
 - [Universal WHOIS](https://github.com/Rafiot/uwhoisd) lookup for abuse contact
 - Sphinx search interface to RT/RTIR ticketing systems. The functionality is disabled by default but can be used to display information about existing report of malicious URLs.

Please note that some of the API services will require an API key. The API keys should be located in the root of the URL Abuse directory.

## Demo

[CIRCL URL Abuse](https://www.circl.lu/urlabuse/) is online.

## Install

Install the requirements

~~~
pip install -r requirements.txt
~~~

Copy and review the configuration:

~~~
cp config.ini.sample config.ini
~~~

Install Redis and update the configuration.

Start the Redis back-end

~~~
./run_redis.sh
~~~

Start the workers (at least 10)

~~~
seq 10 | parallel -u -j 10 ./worker.py
~~~

Start the web interface

~~~
python runapp.py
~~~

## Contributing

We welcome pull requests for new extensions, bug fixes.

### Add a new module

Look at the existings functions/modules. The changes will have to be made in the following files:

* Add the function you want to execure in url\_abuse\_async.py
* Add a route in web/\_\_init\_\_.py. This route will do an async call to the function defined in url\_abuse\_async.py. The parameter of the function is sent in an POST object
* Add a statement in web/templates/url-report.html. The data option is the parameter to pass to the javascript directive
* Add a directive in web/static/main.js, it will take care of passing the parameter to the backend and regularly pull for the response of the async call

## Partner

URL Abuse is being developed as part of the [“European Union anti-Phishing Initiative”](http://phishing-initiative.eu/) (EU PI) project. This project is coordinated by Cert-Lexsi and co-funded by the Prevention of and Fight against Crime programme of the European Union.

