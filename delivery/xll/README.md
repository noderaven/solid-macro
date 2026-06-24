# XLL delivery (future work)

Deferred from v2 scope. Would mirror the macro engine in C as a native
Excel add-in, sharing the AES key/nonce format with `payload/build.py`.

Add an XLL implementation by:

1. Building an x64 DLL with `xlAutoOpen` exported.
2. Replicating `Aes.bas`, the syscall table, and the injection chain in C.
3. Sharing the encrypted shellcode blob with the macro path.
