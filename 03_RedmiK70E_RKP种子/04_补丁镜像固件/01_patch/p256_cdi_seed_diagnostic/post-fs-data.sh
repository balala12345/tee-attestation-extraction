#!/system/bin/sh

# The TA bind now happens in the injected early-init helper. Deliberately do
# not bind again in post-fs-data: KeyMint may already have cached the stock TA.
echo "K70E_BCC_DIAG: late hook intentionally skipped" > /dev/kmsg
exit 0
