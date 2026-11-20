# Contributing

Issues and pull requests are welcome. Reports from other firmware (which factory key options exist, whether signed
dbx appends from Linux were accepted, how the lists came out) are especially useful. Never post a recovery key, key
ID, serial number or raw firmware dump.

## Set up

```sh
git clone https://github.com/jpsanders/bitlocker-dbx-rollback && cd bitlocker-dbx-rollback
python3.15 -m venv .venv && . .venv/bin/activate
make init-dev
```

## Before a pull request

```sh
make format      # black and isort
make checks      # every check CI runs, in the same order
```

Tests use synthetic data only; never add Microsoft binaries or real machine data.
