MODNAME		?= keipm

obj-m		+= $(MODNAME).o
$(MODNAME)-y	+= \
	main.o \
	watcher/watcher.o \
	watcher/ksyms.o \
    validator/validator.o \
    utils/reader.o \
    elf/elf-op.o \
    crypto/sha256.o \
    crypto/rsa.o \
    crypto/pkcs1.o \
    cert/base64.o \
    cert/asn1-oid.o \
    cert/asn1-parser.o \
    cert/asn1-types.o \
    cert/x509-name.o \
    cert/x509-path.o \
    cert/x509-pubkey.o \
    cert/x509.o \
    cert/pem-parser.o \
    cert/cert-validator.o

ccflags-y	+= -Wall -Wno-unused-parameter -Wextra -W -fno-stack-protector
#-Werror

KBUILD_CFLAGS	:= $(filter-out -pg,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	:= $(filter-out -mfentry,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	+= -I$(src)/include
