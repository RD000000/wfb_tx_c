 CROSS_COMPILE=arm-openipc-linux-musleabi-
 CC=$(CROSS_COMPILE)gcc

_LDFLAGS := $(LDFLAGS) -lrt -lpcap -lsodium
_CFLAGS := $(CFLAGS) -Wall -O2 -DWFB_VERSION='"$(VERSION)-$(shell /bin/bash -c '_tmp=$(COMMIT); echo $${_tmp::8}')"'

all: all_bin 

all_bin: wfb_tx_c

src/%.o: src/%.c src/*.h
	$(CC) $(_CFLAGS) -std=gnu99 -c -o $@ $<

wfb_tx_c: src/tx.o src/fec.o
	$(CC) -o $@ $^ $(_LDFLAGS)

clean:
	rm -rf env wfb_rx wfb_tx wfb_keygen dist deb_dist build wfb_ng.egg-info wfb-ng-*.tar.gz _trial_temp *~ src/*.o

