CC ?= cc
CFLAGS ?= -Wall -Wextra -O2

ifdef OPENSSL_DIR
  OPENSSL_CFLAGS = -I$(OPENSSL_DIR)/include
  OPENSSL_LDFLAGS = -L$(OPENSSL_DIR)/lib64 -L$(OPENSSL_DIR)/lib \
                    -Wl,-rpath,$(OPENSSL_DIR)/lib64 -Wl,-rpath,$(OPENSSL_DIR)/lib
endif

TARGET = ml_dsa_cross_check

.PHONY: all clean

all: $(TARGET)

$(TARGET): ml_dsa_cross_check.c
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $< $(OPENSSL_LDFLAGS) -lcrypto

clean:
	rm -f $(TARGET)
