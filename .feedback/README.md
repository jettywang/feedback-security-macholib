# Feedback task starting environment

Upstream: https://github.com/ronaldoussoren/macholib
Upstream commit: `9c2da6781c61b51bb209345a05157a79758d13d6`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= macholib_tests/test_MachO.py macholib_tests/test_mach_o.py macholib_tests/test_dyld.py macholib_tests/test_MachOGraph.py macholib_tests/test_ptypes.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-13): `21 passed, 1 xfailed, 12 subtests passed in 0.05s`
Whole-command wall time: 0.179 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
