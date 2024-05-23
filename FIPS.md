# FIPS Mode on ISA-L Crypto

## Compilation

FIPS mode is disabled in the library by default.
In order to enable it, the library needs to be compiled as follows:

- Using autotools:

```
    ./autogen.sh
    ./configure --enable-fips-mode
    make
```

- Standard makefile:

```
    make -f Makefile.unx FIPS_MODE=y
```

- Windows Makefile:

```
    make /f Makefile.nmake FIPS_MODE=y
```

## Covered API by this mode

Only the "isal_" prefixed API is in the scope of this mode
(e.g. `isal_aes_cbc_enc_128()`).

isal_crypto.h or isal_crypto_api.h must be included in the application/framework
calling this API.

After the first call on this API, crypto self tests will be run.
If any of the tests fail, no crypto operation will be performed
and the API will return ISAL_CRYPTO_ERR_SELF_TEST.
Subsequent calls will return this error too.

The self tests can also be run at the application level by
calling explicitly `isal_self_tests()`.

The validation of self tests is executed only once, either by invoking
the `isal_self_tests()` function or by invoking a covered crypto function,
such as `isal_aes_cbc_enc_128()`. After the tests have been run once,
they will not be executed again, and subsequent API calls will use the previous test result.

If an algorithm is not NIST approved (e.g. SM3), calling the
crypto function will return ISAL_CRYPTO_ERR_FIPS_INVALID_ALGO.

## Example of usage

```
#include <isal_crypto_api.h>
#include <aes_cbc.h>

...

int ret = isal_aes_cbc_enc_128(pt, iv, expkey_enc, ct, pt_len);
if (ret != 0)
        exit(1);

```

## Considerations

- This library does not check for uniqueness on AES-GCM key/IV pair.
- FIPS mode is supported from ISA-L Crypto version v2.25.
- FIPS mode has only been tested on Intel x86 architecture.
