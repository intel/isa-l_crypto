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

IVECTS=$(wildcard inv/*.req.json)
OVECTS=$(patsubst inv/%.req.json,out/%.resp.json,$(IVECTS))

FORCE:
run:  out acvp_app_isal $(OVECTS)
	diff -w -r -s -q out cmp && echo pass

out: ; mkdir -p out

$(OVECTS): out/%.resp.json : inv/%.req.json | acvp_app_isal
	./acvp_app_isal -r $< -p $@

clean:
	$(RM) -r acvp_app_isal out
