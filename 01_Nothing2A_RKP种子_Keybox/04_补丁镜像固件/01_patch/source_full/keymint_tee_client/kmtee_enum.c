#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// KeyMint TA enum-dump client (paired with km.enum.patch.tlbin).
// Dumps all attestation key stores the TA currently holds:
//   EC table (kind 1), RSA table (kind 2), tagged record array (kind 3).
//
// Usage: kmtee_enum [patched_tlbin_path] [outdir]
// Optional pre-step: install factory keybox (guarantees tables populated):
//   KMTEE_INSTALL_KEYBOX=1 kmtee_enum ...

#define MC_DEVICE_ID_DEFAULT 0
#define MC_INFINITE_TIMEOUT (-1)
#define KEYMINT_TL "/data/local/tmp/km.enum.patch.tlbin"
#define ATTEST_KEYBOX "/mnt/vendor/persist/attest_keybox.so"
#define OUTDIR "/data/local/tmp/kmtee_enum_out"

#define CMD_INSTALL_KEYBOX 0x00050202u  // stock cmd: install attest keybox
#define CMD_ENUM_DUMP      0x00050707u  // custom cmd (patched)
#define OUTBUF_LEN 0x2000u

typedef struct { uint32_t sessionId; uint32_t deviceId; } mcSessionHandle_t;
typedef struct { uint32_t sVirtualAddr; uint32_t sVirtualLen; } mcBulkMap_t;

extern uint32_t mcOpenDevice(uint32_t deviceId);
extern uint32_t mcCloseDevice(uint32_t deviceId);
extern uint32_t mcOpenTrustlet(mcSessionHandle_t *session, uint32_t spid, uint8_t *trustlet, uint32_t tLen, uint8_t *tci, uint32_t tciLen);
extern uint32_t mcOpenSession(mcSessionHandle_t *session, const uint8_t *uuid, uint8_t *tci, uint32_t tciLen);
extern uint32_t mcCloseSession(mcSessionHandle_t *session);
extern uint32_t mcMap(mcSessionHandle_t *session, void *buf, uint32_t len, mcBulkMap_t *mapInfo);
extern uint32_t mcUnmap(mcSessionHandle_t *session, void *buf, mcBulkMap_t *mapInfo);
extern uint32_t mcNotify(mcSessionHandle_t *session);
extern uint32_t mcWaitNotification(mcSessionHandle_t *session, int32_t timeout);

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror(path); return -1; }
    fseek(fp, 0, SEEK_END); long n = ftell(fp); fseek(fp, 0, SEEK_SET);
    uint8_t *buf = malloc(n);
    if (fread(buf, n, 1, fp) != 1) { fclose(fp); free(buf); return -1; }
    fclose(fp); *out = buf; *out_len = n; return 0;
}

static void write_file(const char *path, const void *buf, size_t len) {
    int fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, 0600);
    if (fd < 0) { perror(path); return; }
    const uint8_t *p = buf;
    while (len) { ssize_t w = write(fd, p, len); if (w <= 0) break; p += w; len -= w; }
    close(fd);
}

int main(int argc, char **argv) {
    const char *tl_path = (argc > 1) ? argv[1] : KEYMINT_TL;
    const char *outdir = (argc > 2) ? argv[2] : OUTDIR;
    mkdir(outdir, 0700);

    uint8_t *tl = NULL; size_t tl_len = 0;
    if (read_file(tl_path, &tl, &tl_len)) return 2;

    uint8_t *tci = calloc(1, 0x140);
    uint8_t *outbuf = calloc(1, OUTBUF_LEN);
    mcSessionHandle_t s; memset(&s, 0, sizeof(s));

    uint32_t r = mcOpenDevice(MC_DEVICE_ID_DEFAULT);
    printf("mcOpenDevice ret=0x%x\n", r);
    if (getenv("KMTEE_USE_SESSION")) {
        // KeyMint UUID 07060000-0000-0000-0000-00000000004d (MCLF header byte order)
        uint8_t uuid[16] = {0x07,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4d};
        r = mcOpenSession(&s, uuid, tci, 0x140);
        printf("mcOpenSession ret=0x%x sessionId=0x%x\n", r, s.sessionId);
    } else {
        r = mcOpenTrustlet(&s, (uint32_t)-2, tl, (uint32_t)tl_len, tci, 0x140);
        printf("mcOpenTrustlet ret=0x%x sessionId=0x%x\n", r, s.sessionId);
    }
    if (r) return 6;

    // Optional: install factory keybox first (populates EC/RSA tables).
    if (getenv("KMTEE_INSTALL_KEYBOX")) {
        uint8_t *kb = NULL; size_t kb_len = 0;
        if (read_file(ATTEST_KEYBOX, &kb, &kb_len) == 0) {
            mcBulkMap_t map = {0,0};
            r = mcMap(&s, kb, (uint32_t)kb_len, &map);
            memset(tci, 0, 0x140);
            *(uint32_t*)(tci + 0x00) = CMD_INSTALL_KEYBOX;
            memcpy(tci + 0x0c, &map, 8);
            mcNotify(&s); mcWaitNotification(&s, MC_INFINITE_TIMEOUT);
            printf("[install_keybox] tci_ret=0x%x\n", *(uint32_t*)(tci + 4));
            mcUnmap(&s, kb, &map);
            free(kb);
        }
    }

    // Enum dump: map out buffer, cmd at TCI+0, sVA at +0xC, len at +0x10.
    mcBulkMap_t omap = {0,0};
    r = mcMap(&s, outbuf, OUTBUF_LEN, &omap);
    printf("[enum] mcMap ret=0x%x sVA=0x%x sLen=0x%x\n", r, omap.sVirtualAddr, omap.sVirtualLen);
    memset(tci, 0, 0x140);
    *(uint32_t*)(tci + 0x00) = CMD_ENUM_DUMP;
    memcpy(tci + 0x0c, &omap, 8);
    r = mcNotify(&s);
    if (!r) r = mcWaitNotification(&s, MC_INFINITE_TIMEOUT);
    printf("[enum] wait ret=0x%x tci_ret=0x%x\n", r, *(uint32_t*)(tci + 4));

    uint32_t magic = *(uint32_t*)(outbuf + 0);
    uint32_t total = *(uint32_t*)(outbuf + 4);
    printf("[enum] magic=0x%08x total=%u ec=%u rsa=%u rec=%u\n",
           magic, total,
           *(uint32_t*)(outbuf + 8), *(uint32_t*)(outbuf + 0xC), *(uint32_t*)(outbuf + 0x10));
    char path[256];
    snprintf(path, sizeof(path), "%s/enum_dump.bin", outdir);
    write_file(path, outbuf, (total && total <= OUTBUF_LEN) ? total : 0x200);

    // Parse records: from +0x20, each {u32 kind, u32 idx, u32 len, data[len]}
    uint32_t off = 0x20; int n = 0;
    while (magic == 0x4B4D454E && off + 12 <= total && off + 12 <= OUTBUF_LEN) {
        uint32_t kind = *(uint32_t*)(outbuf + off);
        uint32_t idx  = *(uint32_t*)(outbuf + off + 4);
        uint32_t len  = *(uint32_t*)(outbuf + off + 8);
        if (len > 0x2000 || off + 12 + len > OUTBUF_LEN) break;
        snprintf(path, sizeof(path), "%s/kind%u_idx%u.bin", outdir, kind, idx);
        write_file(path, outbuf + off + 12, len);
        printf("  rec kind=%u idx=%u len=%u -> %s\n", kind, idx, len, path);
        off += 12 + len; n++;
    }
    printf("[enum] parsed %d records\n", n);

    mcUnmap(&s, outbuf, &omap);
    mcCloseSession(&s);
    mcCloseDevice(MC_DEVICE_ID_DEFAULT);
    printf("DONE\n");
    return 0;
}
