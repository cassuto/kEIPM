MODNAME		?= keipm

obj-m		+= $(MODNAME).o
$(MODNAME)-y	+= \
	main.o \
	watcher/watcher.o \
	watcher/ksyms.o \
    cert/asn1-oid.o \
    cert/asn1-parser.o \
    cert/asn1-types.o \
    cert/x509-name.o \
    cert/x509-path.o \
    cert/x509-pubkey.o \
    cert/x509.o

ccflags-y	+= -Wall -Wno-unused-parameter -Wextra -W -fno-stack-protector
#-Werror

KBUILD_CFLAGS	:= $(filter-out -pg,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	:= $(filter-out -mfentry,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	+= -I$(src)/include
