#!/usr/bin/env python
# -*-coding:utf-8 -*

import os

from web import create_app

# create an app instance
abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)
app = create_app()
app.run(host='0.0.0.0', port = 5100, debug=False, threaded=True)
