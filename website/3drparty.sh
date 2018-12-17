#!/bin/bash

set -e
set -x

DEST_DIR="web/static/"

ANGULAR='1.7.4'
ANGULAR_BOOTSTRAP='2.5.0'

wget https://ajax.googleapis.com/ajax/libs/angularjs/${ANGULAR}/angular.min.js -O ${DEST_DIR}/angular.min.js
wget https://angular-ui.github.io/bootstrap/ui-bootstrap-tpls-${ANGULAR_BOOTSTRAP}.min.js -O ${DEST_DIR}/ui-bootstrap-tpls.min.js

wget https://raw.githubusercontent.com/sphinxsearch/sphinx/master/api/sphinxapi.py -O sphinxapi.py



