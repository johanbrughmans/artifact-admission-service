# Artifact Admission Service

Independent Consumer #2 for Semanti-piler EPIC-66 product-level portability verification.

## Purpose

The Artifact Admission Service models release governance and admission decisions for third-party plugins in an isolated WebAssembly (WASM) runtime environment.

Admission requires:
1. Static security audit verification (`static-security-scanner`).
2. Digital signature verification (`cosign-verifier`).
3. Transition admissibility from `CANDIDATE` to `VERIFIED` to `RELEASED`.
4. Runtime capability coverage for WASM sandbox isolation (`capability://plugin-sandbox-isolation@v1`).

The service defines its own domain contracts, evidence bindings, and capability coverage declarations without importing Semanti-piler internal modules or using any OMV concepts.

## How to Replay the Conformance Proof

### Prerequisites
- Python >= 3.11
- An installed Semanti-piler wheel (`semanti-piler >= 0.1.0rc1`)

### Replay Steps

1. Create a clean virtual environment and install the Semanti-piler wheel:
   ```bash
   python -m venv .venv
   .venv/bin/pip install path/to/semanti_piler-0.1.0rc1-py3-none-any.whl
   .venv/bin/pip install pytest
   ```

2. Execute strict CLI conformance evaluation:
   ```bash
   .venv/bin/semanti-piler conformance semantipiler-profile.json --strict
   ```

3. Run the automated positive and adversarial conformance test suite:
   ```bash
   .venv/bin/pytest
   ```
