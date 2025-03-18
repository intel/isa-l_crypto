CFLAGS = -I ../../include -DNO_COMPAT_ISAL_CRYPTO_API_2_24
LDLIBS = -L../../bin -lisal_crypto

FUZZ_APP := isal-fuzz-api

FUZZ_CFLAGS = $(CFLAGS) -g -fsanitize=fuzzer,address,leak
FUZZ_SOURCES := fuzz_test.c

$(FUZZ_APP): $(FUZZ_SOURCES)
ifneq (, $(shell which clang))
	clang $(FUZZ_CFLAGS) $(FUZZ_SOURCES) $(LDLIBS) -o $@
else
	@echo "Clang is not installed. $(FUZZ_APP) is not built"
endif

clean:
	$(RM) *.o $(FUZZ_APP)

