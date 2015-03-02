#!/bin/bash

set -e
set -x

if [ ! -d virtenv ]; then
    virtualenv virtenv
fi

. ./virtenv/bin/activate

pip install --upgrade -r requirements.txt
