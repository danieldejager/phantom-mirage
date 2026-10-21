# Phantom Mirage Regression Test Suite
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
# Python 3 (#36), deterministic over a veth pair (#74). Needs root,
# NET_ADMIN, python3-dpkt and iproute2.
# Exit status of each script: 0 = all match, 3 = output mismatch,
# anything else = the harness itself broke.

PYTHON3 = python3
TESTS_PY = general.py detect.py routing.py nmap.py

all:
	@echo "To run the regression tests: cd regress && make test"

test: check
	@rc=0; for t in $(TESTS_PY); do $(PYTHON3) $$t || rc=1; done; exit $$rc

check:
	@[ "`id -u`" -eq 0 ] || { echo "Need to run the test suite as root!"; exit 1; }
	@command -v $(PYTHON3) >/dev/null || { echo "No $(PYTHON3) interpreter, tests will not work"; exit 1; }
	@$(PYTHON3) -c 'import dpkt' 2>/dev/null || { echo "Need python3-dpkt"; exit 1; }
	@command -v nmap >/dev/null || { echo "Need nmap (nmap.py)"; exit 1; }

# Generate output for all tests
generate: check
	@for t in $(TESTS_PY); do $(PYTHON3) $$t -g || exit 1; done

# Run tests in debug mode
debug: check
	@for t in $(TESTS_PY); do $(PYTHON3) $$t -d; done

# Clean out auto-generated files
clean-local:
	rm -rf config.nmap nmap.log *~ __pycache__

EXTRA_DIST = config.1 config.2 detect.py general.py nmap.py \
	regress.py dnet_compat.py routing.py detect.output.1 detect.output.2 \
	detect.output.3 detect.output.4 \
	gen.output.1 gen.output.2 route.output.1 nmap.output.1 \
	IMPORTANT_NOTES.txt
