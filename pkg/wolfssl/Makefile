PKG_NAME=wolfssl
PKG_URL=https://github.com/wolfssl/wolfssl.git
# v5.5.4
#PKG_VERSION=4fbd4fd36a21efd9d1a7e17aba390e91c78693b1
# v5.7.2
#PKG_VERSION=00e42151ca061463ba6a95adb2290f678cbca472
# v5.9.2
PKG_VERSION=ac01707f552c611fbd135cc723b2682b3e7f80f2

#PKG_VERSION=2b62c848329af59a746206a1fb0b891ca6c7d251
PKG_LICENSE=GPLv2

include $(RIOTBASE)/pkg/pkg.mk

# some variable seem uninitialized to gcc with -Og but are not
# https://gcc.gnu.org/bugzilla/buglist.cgi?quicksearch=may%20be%20used%20uninitialized
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=42145
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90710#c1
CFLAGS += -Wno-maybe-uninitialized

# wolfcrypt uses uint8_t for block buffers, on which fast
# 32 bit operations are performed. From a quick peek at the
# code it looks like the buffers are correctly aligned, so
# this is a false positive.
CFLAGS += -Wno-cast-align

.PHONY: wolfcrypt%

all: $(filter wolfcrypt wolfcrypt-test wolfcrypt-benchmark,$(USEMODULE))
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/src -f $(CURDIR)/Makefile.wolfssl

wolfcrypt:
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/wolfcrypt/src -f $(CURDIR)/Makefile.wolfcrypt

wolfcrypt-%:
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/wolfcrypt/$* -f $(CURDIR)/Makefile.wolfcrypt-$*
