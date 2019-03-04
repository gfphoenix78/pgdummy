# contrib/pg_dummy/Makefile

MODULE_big = pgdummy
OBJS = pgdummy.o $(WIN32RES)

EXTENSION = pgdummy
DATA = pgdummy--1.0.0.sql
PGFILEDESC = "pgAudit - An dummy logging extension for PostgreSQL"

REGRESS = pgdummy
REGRESS_OPTS = --temp-config=$(top_srcdir)/contrib/pgdummy/pgdummy.conf

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pgdummy
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
