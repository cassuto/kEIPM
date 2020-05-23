MODNAME		?= keipm

obj-m		+= $(MODNAME).o
$(MODNAME)-y	+= main.o

ccflags-y	+= -Werror -fno-stack-protector -fomit-frame-pointer

KBUILD_CFLAGS	:= $(filter-out -pg,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	:= $(filter-out -mfentry,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	+= -I$(src)/include