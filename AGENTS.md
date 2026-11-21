# AGENTS.md

Guidance for AI agents working in or with this repository.

## Using the tool on someone's machine

- Run `dbx-rollback guide` and follow its walkthrough in order. Stop and ask the person at every firmware step.
- Never tell anyone to use **Clear TPM** or a "restore security settings" firmware option. It destroys the TPM
  protector.
- Only advise clearing Secure Boot keys once you have checked the firmware can load its factory keys afterwards, and
  say plainly that this is the one step that can end the no key route.
- Never boot Windows until `rebuild.sh verify` prints VERIFIED.
- Treat recovery keys, key IDs, serial numbers and firmware dumps as private. Never put them in issues, commits or
  logs you share.

## Working on the code

- `make checks` must pass: isort, black, editorconfig-checker, darglint, flake8, mypy strict, bandit, the man page
  check and pytest.
- `docs/MANUAL.md` is the one source of the manual; run `python scripts/build_man.py` after editing it.
- Tests use synthetic data only. Never add a Microsoft binary, a real firmware dump or a real BitLocker metadata
  file to the repository.

## ruru

`make ruru` (part of `make checks` and CI) reviews your branch against main with
[ruru](https://github.com/jpsanders/ruru-review): a tamper audit of the tests, fail first for new tests, and mutants
on the changed lines. Write a test for each survivor; never weaken, skip or delete a test to make it pass.
