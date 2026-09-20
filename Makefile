# Zero-dependency project: every target is standard library Python.
PYTHON ?= python3

.DEFAULT_GOAL := help
.PHONY: help demo test bench bench-fast trace experiment screenshots invariants clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

demo: ## Run the full demonstration (add TRACE=1 for per-decision explanations)
	$(PYTHON) -m ais demo $(if $(TRACE),--trace,)

test: ## Run the whole test suite
	$(PYTHON) -m unittest discover -s tests -t . -v

bench: ## Run every benchmark and write results.json
	$(PYTHON) -m ais benchmark --out results.json

bench-fast: ## Run benchmarks without the parameter sweeps
	$(PYTHON) -m ais benchmark --no-sweeps

trace: ## Render a reviewable HTML trace (SCENARIO=key|collusion|gradual-drift|population)
	$(PYTHON) -m ais trace --scenario $(or $(SCENARIO),key) --html trace.html --json trace.json

experiment: ## Run one named experiment (NAME=learning-adversary, cross-process, ...)
	$(PYTHON) -m ais experiment $(or $(NAME),key)

screenshots: ## Regenerate docs/assets/*.png from real runs
	$(PYTHON) scripts/make_screenshots.py

invariants: ## Check P1-P8 over a standard population run
	@$(PYTHON) -c "from ais.simulation.ecosystem import build_default_ecosystem; \
from ais.control_plane.invariants import InvariantChecker; \
eco = build_default_ecosystem(); checker = InvariantChecker(eco.plane).bind(); eco.run(20); \
import json; print(json.dumps(checker.summary(), indent=2))"

clean: ## Remove build and cache artefacts
	rm -rf .build trace.html trace.json graph.dot
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
