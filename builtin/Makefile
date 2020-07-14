CC ?= gcc
TARGETS = ca.h client.h public_pkcs1.h

.PHONY: all clean
all: bin2c $(TARGETS)

bin2c: bin2c.c
	$(CC) $< -o $@

%.h: %.der bin2c
	./bin2c $(notdir $(basename $<)) $< $@
%.h: %.pem bin2c
	./bin2c $(notdir $(basename $<)) $< $@

clean:
	-rm bin2c $(TARGETS)
