CC ?= gcc
TARGETS = ca.h

.PHONY: all clean
all: bin2c $(TARGETS)

bin2c: bin2c.c
	$(CC) $< -o $@

%.h: %.crt bin2c
	./bin2c $(notdir $(basename $<)) $< $@

clean:
	-rm bin2c $(TARGETS)
