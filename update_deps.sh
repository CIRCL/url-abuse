#!/bin/bash

set -e
set -x

DEST_DIR="web/static/"

ANGULAR='1.3.14'
ANGULAR_BOOTSTRAP='0.12.1'

wget https://ajax.googleapis.com/ajax/libs/angularjs/${ANGULAR}/angular.min.js -O ${DEST_DIR}/angular.min.js
wget https://angular-ui.github.io/bootstrap/ui-bootstrap-tpls-${ANGULAR_BOOTSTRAP}.min.js -O ${DEST_DIR}/ui-bootstrap-tpls.min.js

wget https://sphinxsearch.googlecode.com/svn/trunk/api/sphinxapi.py -O sphinxapi.py



