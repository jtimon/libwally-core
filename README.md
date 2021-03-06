# libwally-core

Useful primitives for wallets.

Please report bugs and submit patches to https://github.com/jgriffiths/libwally-core.

[![Build Status](https://travis-ci.org/jgriffiths/libwally-core.svg?branch=master)](https://travis-ci.org/jgriffiths/libwally-core)

## Building

```
$ ./tools/cleanup.sh
$ ./tools/autogen.sh
$ ./configure <options - see below>
$ make
$ make check
```

### configure options

- `--enable-debug`. Enables debugging information and disables compiler
   optimisations (default: no).
- `--enable-export-all`. Export all functions from the wally shared library.
   Ordinarily only API functions are exported. (default: no). Enable this
   if you want to test the internal functions of the library or are planning
   to submit patches.
- `--enable-swig-python`. Enable the [SWIG](http://www.swig.org/) python
   interface. The resulting shared library can be directly imported from
   Python. (default: no).
- `--enable-swig-java`. Enable the [SWIG](http://www.swig.org/) Java (JNI)
   interface. After building, see `src/swig_java/src/com/blockstream/libwally/Wally.java`
   for the Java interface definition (default: no).
- `--enable-coverage`. Enables code coverage (default: no) Note that you will
   need [lcov](http://ltp.sourceforge.net/coverage/lcov.php) installed to
   build with this option enabled and generate coverage reports.

NOTE: If you wish to run the python tests you currently need to pass
      the `--enable-swig-python` option. This requirement will be removed
      in a future release.

### Recommended development configure options

```
$ ./configure --enable-debug --enable-export-all --enable-swig-python --enable-coverage
```

## Cleaning

```
$ ./tools/cleanup.sh
```

## Submitting patches

Please use pull requests on github to submit. Before producing your patch you
should format your changes using [uncrustify](https://github.com/uncrustify/uncrustify.git)
version 0.60 or later. The script `./tools/uncrustify` will reformat all C
sources in the library as needed, with the currently chosen uncrustify options.

The version of uncrustify in Debian is unfortunately out of date and buggy. If
you are using Debian this means you will need to download and build uncrustify
from source using something like:

```
$ git clone --depth 1 https://github.com/uncrustify/uncrustify.git
$ cd uncrustify
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

You should also make sure the existing tests pass and if possible write tests
covering any new functionality, following the existing style.

## Generating a coverage report

To generate an HTML coverage report, use:

```
$ ./tools/cleanup.sh
$ ./tools/autogen.sh
$ ./configure --enable-debug --enable-export-all --enable-swig-python --enable-swig-java --enable-coverage
$ make
$ ./tools/coverage.sh clean
$ make check
$ ./tools/coverage.sh
```

The coverage report can then be viewed at `src/lcov/index.html`. Patches to
increase the test coverage are welcome.
