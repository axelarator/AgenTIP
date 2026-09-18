# The analysis container. Built and run on the PROBE VM, never here.
#
# Threat model: the input is a file downloaded from an adversary's open
# directory. It is parsed, hashed and pattern-matched - never executed -
# but a parser is still attack surface, so the container is the boundary:
#
#   --network=none            nothing it does can reach the network
#   --read-only               the image is immutable at runtime
#   --cap-drop=ALL            no capabilities at all
#   --security-opt=no-new-privileges
#   --memory / --pids-limit   a decompression bomb costs one container
#   -v <dir>:/in:ro           the samples are read-only, and not in this image
#   --user nobody             no root inside either
#
# Output is a JSON document on stdout. That document is the only thing
# that crosses the SSH channel back to the cti host, which is what keeps
# sample bytes off the analyst's machine and out of the repo entirely.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends file libmagic1 \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir yara-python==4.5.1 python-magic==0.4.27

COPY analyze.py /opt/analyze.py
COPY rules /opt/rules

USER nobody
ENTRYPOINT ["python", "/opt/analyze.py"]
CMD ["/in"]
