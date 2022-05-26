ACVP_PATH = /usr/local/acvp

INCLUDES = -I $(ACVP_PATH)/include -L $(ACVP_PATH)/lib
CFLAGS = -Wall -O2 $(INCLUDES)
LDLIBS = -lacvp -lisal_crypto

ACVP_MODULES += acvp_app_isal_gcm.c
ACVP_MODULES += acvp_app_isal_xts.c
ACVP_MODULES += acvp_app_isal_cbc.c
ACVP_MODULES += acvp_app_isal_sha.c

acvp_app_isal: acvp_app.c $(ACVP_MODULES)
	$(CC) -o $@ $(CFLAGS) $^ $(LDLIBS)

clean:
	$(RM) acvp_app_isal
