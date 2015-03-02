Add a new module
================

Look at the existings functions/modules. The changes will have to be made in the following files:

* Add the function you want to execure in url\_abuse\_async.py
* Add a route in web/\_\_init\_\_.py. This route will do an async call to the function defined in url\_abuse\_async.py. The parameter of the function is sent in an POST object
* Add a statement in web/templates/url-report.html. The data option is the parameter to pass to the javascript directive
* Add a directive in web/static/main.js, it will take care of passing the parameter to the backend and regularly pull for the response of the async call
