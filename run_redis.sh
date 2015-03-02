#!/bin/bash

set -e
set -x

REDIS_HOME='/change/me/'

${REDIS_HOME}/redis-server ./redis.conf

