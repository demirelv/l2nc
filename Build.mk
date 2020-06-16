
PROJECT_DIR     ?= $(CURDIR)
DISTDIRS		:= ${PROJECT_DIR}/build
OUTDIR		    := ${DISTDIRS}
DESTDIR		    ?= ${PROJECT_DIR}/install
PROJECT_NAME    ?= $(subst /,_, ${PROJECT_DIR})
PROJECT_PACKAGE ?= ${PROJECT_NAME}.tar.bz2

CC         := $(CROSS_COMPILE_PREFIX)gcc
LD         := $(CROSS_COMPILE_PREFIX)ld
AR         := $(CROSS_COMPILE_PREFIX)ar
Q          := @
RM         := rm -rf
MKDIR      := mkdir -p
CP         := cp -rf
TAR        := tar
CCS        := checkpatch.pl --no-tree -f

_CFLAGS    := -Wall -Wextra -Werror -pipe -g3 -O2 -fsigned-char -fno-strict-aliasing -fPIC -Werror=unused-result $(CFLAGS) $(EXTRA_CFLAGS) -I.
_LDFLAGS   := $(LDFLAGS) $(EXTRA_LDFLAGS) -L.

MAKE       := CFLAGS="$(CFLAGS)" EXTRA_CFLAGS="$(EXTRA_CFLAGS)" LDFLAGS="$(LDFLAGS)" EXTRA_LDFLAGS="$(EXTRA_LDFLAGS)" PROJECT_DIR="$(PROJECT_DIR)" DESTDIR="$(DESTDIR)" $(MAKE) --no-print-directory

define dir-define
$(addsuffix _all, $1):
	@+ $(MAKE) OUTDIR=${OUTDIR}/$1 -C '$1' all
$(addsuffix _build, $1):
	@+ $(MAKE) OUTDIR=${OUTDIR}/$1 -C '$1' build
$(addsuffix _clean, $1):
	@+ $(MAKE) OUTDIR=${OUTDIR}/$1 -C '$1' clean
$(addsuffix _install, $1):
	@+ $(MAKE) OUTDIR=${OUTDIR}/$1 -C '$1' install
$(addsuffix _uninstall, $1):
	@+ $(MAKE) OUTDIR=${OUTDIR}/$1 -C '$1' uninstall
$(addsuffix _codestyle, $1):
	@+ $(MAKE) OUTDIR=${OUTDIR}/$1 -C '$1' checkstyle
endef

define header-define
${OUTDIR}:
	$(Q)$(MKDIR) $$@
$(addsuffix _header, $1): ${OUTDIR}
	$(Q) echo HEADER $1; $(CP) $1 ${OUTDIR}/
endef

define code-style-define
$(addsuffix _codestyle, $1):
	$(Q) echo CCS $1; $(CCS) $1;
endef

define base-define
$(eval $(foreach H,$($1-header-y), $(eval $(call header-define,$H))))
$(eval $(foreach S,$($1-source-y), $(eval $(call code-style-define,$S))))

$(eval $1-objs		= $(patsubst %.c,${OUTDIR}/.$1/%.o,$($1-source-y)))
$(eval $1-incs		= $(addprefix -I, $($1-include-y)))
$(eval $1-libps		= $(addprefix -L, ./ $($1-library-path-y)))

${OUTDIR}/.$1:
	$(Q)$(MKDIR) $$@
${OUTDIR}/.$1/%.o: %.c
	$(Q) echo CC $$<; $(MKDIR) $$(dir $$@); $(CC) $(_CFLAGS) $($1-cflags-y) $($1-incs) -c $$< -o $$@
$(addsuffix _all, $1): ${OUTDIR}/$1 $(addsuffix _header, $1)
	@true
$(addsuffix _build, $1): ${OUTDIR}/$1 $(addsuffix _header, $1)
	@true
$(addsuffix _clean, $1):
	$(RM) ${OUTDIR}
$(addsuffix _header, $1): $(addsuffix _header, $($1-header-y))
	@true
$(addsuffix _codestyle, $1): $(addsuffix _codestyle, $($1-source-y))
	@true
endef

define target-define
$(eval $(call base-define,$1))   
${OUTDIR}/$1: ${OUTDIR}/.$1 $($1-objs)
	$(Q) echo CC $$@; $(CC) $($1-objs) -o $$@ ${_LDFLAGS} $($1-ldflags-y) $($1-libps) $($1-library-y)
endef

define library-define
$(eval $(call base-define,$1))
${OUTDIR}/$1: ${OUTDIR}/.$1 $($1-objs)
	$(Q) echo CC $$@; $(CC) -shared $($1-objs) -o $$@ ${_LDFLAGS} $($1-ldflags-y) $($1-libps) $($1-library-y)
endef

define install-define
$(subst /,-, $(dir $(word 2, $(subst :, ,$1)))):
	$(Q)$(MKDIR) ${DESTDIR}${PREFIX}/$(dir $(word 2, $(subst :, ,$1)))
$(addsuffix _install, $(subst /,-, $(subst :,-, $1))):$(subst /,-, $(dir $(word 2, $(subst :, ,$1))))
	$(Q) echo INSTALL $(word 1, $(subst :, ,$1)); $(if $(wildcard ${OUTDIR}/$(word 1, $(subst :, ,$1))), $(CP) ${OUTDIR}/$(word 1, $(subst :, ,$1)) ${DESTDIR}${PREFIX}/$(word 2, $(subst :, ,$1)), $(CP) ${PROJECT_DIR}/$(word 1, $(subst :, ,$1)) ${DESTDIR}${PREFIX}/$(word 2, $(subst :, ,$1)))
$(addsuffix _uninstall, $(subst /,-, $(subst :,-, $1))):
	$(Q) echo REMOVE $(word 1, $(subst :, ,$1)); $(RM) ${DESTDIR}${PREFIX}/$(word 2, $(subst :, ,$1))/$(word 1, $(subst :, ,$1))
endef

$(eval $(foreach D,$(dir-y),$(eval $(call dir-define,$D))))
$(eval $(foreach T,$(target-y), $(eval $(call target-define,$T))))
$(eval $(foreach L,$(library-y), $(eval $(call library-define,$L))))
$(eval $(foreach V,$(install-y), $(eval $(call install-define,$V))))

${PROJECT_PACKAGE}:
	$(Q) ${TAR} -C ${DESTDIR} -cjvf $@ .

all: $(addsuffix _all, $(dir-y))
all: $(addsuffix _all, $(library-y))
all: $(addsuffix _all, $(target-y))
	@true
build: $(addsuffix _build, $(dir-y))
build: $(addsuffix _build, $(library-y))
build: $(addsuffix _build, $(target-y))
	@true
clean: $(addsuffix _clean, $(target-y))
clean: $(addsuffix _clean, $(library-y))
clean: $(addsuffix _clean, $(dir-y))
	@true
install: $(addsuffix _install, $(dir-y)) $(addsuffix _install, $(subst /,-, $(subst :,-,$(install-y))))
	@true
uninstall: $(addsuffix _uninstall, $(dir-y)) $(addsuffix _uninstall, $(subst /,-, $(subst :,-,$(install-y))))
	@true
package: ${PROJECT_PACKAGE}
	@true
checkstyle: $(addsuffix _codestyle, $(dir-y))
checkstyle: $(addsuffix _codestyle, $(library-y))
checkstyle: $(addsuffix _codestyle, $(target-y))
	@true
