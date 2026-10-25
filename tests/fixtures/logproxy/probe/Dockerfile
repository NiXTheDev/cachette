# Build context for the B4 probe (plan task 27).
#
# Deliberately trivial and offline-buildable: `scratch` needs no base image
# pull, and the single COPY still produces a config + layer blob, so
# `--cache-to type=gha` has real cache data to export to the cachette server
# through the logging proxy. Nothing here is meant to run.
FROM scratch
COPY payload.txt /payload.txt
LABEL org.cachette.probe="b4" org.cachette.task="27"
