# Compiling libpcap on Haiku

## 64-bit x86 R1/beta4

* Autoconf 2.71 works.
* CMake 3.24.2 works.
* GCC 11.2.0 works.
* Clang 12.0.1 works with the latest llvm12_clang-12.0.1-5 version.
* flex 2.6.4 works.
* bison 3.8.2 works.

The following command will install respective non-default packages:
```
pkgman install libpcap_devel cmake llvm12_clang
```

For reference, the tests were done using a system installed from
`haiku-r1beta4-x86_64-anyboot.iso`.
