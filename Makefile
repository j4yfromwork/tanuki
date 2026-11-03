# tanuki — developer Makefile
# Kali note: Python is externally managed (PEP 668), so everything runs inside a
# project venv. `make venv` then `make install` once, then the rest.

VENV   := venv
PY     := $(VENV)/bin/python
PIP    := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest

LAB_HOST ?= 127.0.0.1
LAB_PORT ?= 5000

.PHONY: help venv install deps lab site lab-noexposedkey test clean

help:
	@echo "targets:"
	@echo "  make venv     - create the project virtualenv ($(VENV)/)"
	@echo "  make install  - install tanuki (editable) + dev/test deps (incl. gmpy2)"
	@echo "  make deps     - install gmpy2's C build prerequisites via apt (only if a"
	@echo "                  pip wheel isn't available for your platform)"
	@echo "  make lab      - run the deliberately-vulnerable Flask lab (localhost only)"
	@echo "  make site     - run the lab and point you at the browsable web app URL"
	@echo "  make lab-noexposedkey - run the 'no exposed key' scenario on :5001 (key recovery)"
	@echo "  make test     - run the pytest suite (verbose)"
	@echo "  make clean    - remove caches and the lab's generated keys"

venv:
	python3 -m venv $(VENV)
	@echo "[+] venv ready — now run: make install"

install:
	$(PIP) install --upgrade pip
	@# gmpy2 normally installs from a manylinux wheel that bundles GMP/MPFR/MPC
	@# (no system libs needed). If that fails, it's a source build missing the
	@# dev headers — fall back to `make deps`, then retry.
	$(PIP) install -r requirements-dev.txt || { \
		echo "[!] a dependency failed to install (likely gmpy2 needing a source build)."; \
		echo "    installing its C prerequisites, then retrying ..."; \
		$(MAKE) deps && $(PIP) install -r requirements-dev.txt; }
	$(PIP) install -e .
	@$(PY) -c "import gmpy2; print('[+] gmpy2', gmpy2.version(), '- fast e=65537 key derivation enabled')" \
		|| echo "[!] gmpy2 not importable - key derivation will use the slow pure-Python path (run 'make deps' then 'make install')"
	@echo "[+] installed. tanuki console script: $(VENV)/bin/tanuki"

# Install gmpy2's C build prerequisites (libgmp/libmpfr/libmpc). Only needed when
# pip can't fetch a prebuilt wheel for your platform and must compile from source.
deps:
	@if [ "$$(id -u)" = 0 ]; then APT=""; \
	elif command -v sudo >/dev/null 2>&1; then APT="sudo"; \
	else \
		echo "ERROR: gmpy2 needs libgmp-dev libmpfr-dev libmpc-dev to build from source,"; \
		echo "       and this shell has neither root nor sudo. Install them manually, then"; \
		echo "       re-run 'make install':"; \
		echo "         sudo apt-get install -y libgmp-dev libmpfr-dev libmpc-dev"; \
		exit 1; \
	fi; \
	echo "[*] installing gmpy2 build prerequisites via apt ..."; \
	$$APT apt-get update && $$APT apt-get install -y libgmp-dev libmpfr-dev libmpc-dev || { \
		echo "ERROR: could not install prerequisites via apt. Install them manually:"; \
		echo "         sudo apt-get install -y libgmp-dev libmpfr-dev libmpc-dev"; \
		exit 1; }
	@echo "[+] gmpy2 build prerequisites installed"

lab:
	$(PY) lab/app.py

# Same process as `make lab`; this just reminds you where the browsable UI lives.
site:
	@echo "[*] browsable web app:  http://$(LAB_HOST):$(LAB_PORT)/login-page   (james / peter)"
	@echo "[*] raw API index:      http://$(LAB_HOST):$(LAB_PORT)/"
	$(PY) lab/app.py

# The "algorithm confusion, NO exposed key" scenario on its own origin (port 5001,
# no JWKS) so tanuki is forced down its key-recovery path. Run alongside the main
# lab if you want both.
lab-noexposedkey:
	@echo "[*] no-exposed-key endpoint: http://127.0.0.1:5001/api/noexposedkey"
	@echo "[*] two logins -> recover key -> bypass (see lab/README.md)"
	$(PY) lab/app.py noexposedkey

test:
	$(PYTEST) -v

clean:
	rm -rf .pytest_cache **/__pycache__ *.egg-info build dist
	rm -rf lab/keys
	@echo "[+] cleaned"
