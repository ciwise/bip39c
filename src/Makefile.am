bin_PROGRAMS=bip39c
bip39c_SOURCES = bip39c.c crypto.c print_util.c conversion.c

bip39c_CFLAGS = -I$(top_srcdir) $(MY_CFLAGS) 

bip39c_LDFLAGS	= @LDFLAGS@
bip39c_LDADD	= -lssl -lcrypto
