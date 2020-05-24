MODNAME		?= keipm

obj-m		+= $(MODNAME).o
$(MODNAME)-y	+= \
	main.o \
	watcher/watcher.o \
	watcher/ksyms.o \
	utils/string.o

ccflags-y	+= -Wall -fno-stack-protector
#-Werror

KBUILD_CFLAGS	:= $(filter-out -pg,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	:= $(filter-out -mfentry,$(KBUILD_CFLAGS))
KBUILD_CFLAGS	+= -I$(src)/include