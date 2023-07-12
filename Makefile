MODULE_big = pg_keyring
OBJS = pg_keyring.o keyssl.o
SHLIB_LINK = -lssl -lcrypto


EXTENSION = pg_keyring
DATA = pg_keyring--1.0.sql
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
