## Process this file with automake to produce Makefile.in

SUBDIRS = xdr libnfs ugidd mountd nfsd util doc

MAINTAINERCLEANFILES =  aclocal.m4 config.h.in configure Makefile.in

# Custom subir list for static analysis via splint
SPLINT_SUBDIRS = libnfs ugidd mountd nfsd util

# Custom targets for static analysis via splint
.PHONY: splint splint-recursive

splint: splint-recursive

splint-recursive:
	@failcom='exit 1'; \
	for f in x $$MAKEFLAGS; do \
		case $$f in \
			*=* | --[!k]*);; \
			*k*) failcom='fail=yes';; \
		esac; \
	done; \
        target=`echo $@ | sed s/-recursive//`; \
	list='$(SPLINT_SUBDIRS)'; for subdir in $$list; do \
		echo "Making $$target in $$subdir"; \
		(cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$target) \
			|| eval $$failcom; \
	done; \
	test -z "$$fail"

