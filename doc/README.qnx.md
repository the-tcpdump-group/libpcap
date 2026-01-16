# Compiling libpcap for QNX

It is possible to cross-compile libpcap from this source tree on a Linux host
for a QNX 8.0 target as follows:
1. Obtain a licence, download and install QNX Software Center.
2. Using QNX Software Center, install a suitable version of QNX SDP (for
   example, 8.0.3 works) and note the SDP installation directory (for example,
   `~/qnx800`).  There is no need to install the Momentics IDE.
3. Initialize environment variables and cross-compile libpcap for the required
   target.  For example, for AArch64:
   ```
   . ~/qnx800/qnxsdp-env.sh
   ./configure --host=aarch64-unknown-nto-qnx8.0.0
   make
   ```
4. Cross-compile the required software using `libpcap.a` and the headers from
   the libpcap source tree.
