#!/usr/bin/env bash

echo hey there
sleep 1

echo INIT_COMMAND=/bin/sh >> $ENVBUILDER_ENV
echo INIT_ARGS="-c /bin/bash" >> $ENVBUILDER_ENV