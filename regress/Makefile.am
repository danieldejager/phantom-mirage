# Honeyd Regression Test Suite
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
# Python 3 (#36). Needs root, python3-dpkt and iproute2.
# Exit status of each script: 0 = all match, 3 = output mismatch (the
# suite is known failing, see IMPORTANT_NOTES.txt), anything else = the
# harness itself broke.

PYTHON3 = python3
TESTS_PY = general.py detect.py routing.py

all:
	@echo "To run the regression tests: cd regress && make test"

test: check
	@rc=0; for t in $(TESTS_PY); do \
	  $(PYTHON3) $$t; r=$$?; \
	  if [ $$r -eq 3 ]; then [ $$rc -ne 0 ] || rc=3; \
	  elif [ $$r -ne 0 ]; then rc=$$r; fi; \
	done; exit $$rc

check:
	@[ "`id -u`" -eq 0 ] || { echo "Need to run the test suite as root!"; exit 1; }
	@command -v $(PYTHON3) >/dev/null || { echo "No $(PYTHON3) interpreter, tests will not work"; exit 1; }
	@$(PYTHON3) -c 'import dpkt' 2>/dev/null || { echo "Need python3-dpkt"; exit 1; }

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
	gen.output.1 gen.output.2 route.output.1 IMPORTANT_NOTES.txt
