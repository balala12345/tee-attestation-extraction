#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MC_DEVICE_ID_DEFAULT 0
#define MC_INFINITE_TIMEOUT (-1)
#define KEYMINT_TL "/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin"
#define ATTEST_KEYBOX "/mnt/vendor/persist/attest_keybox.so"
#define ATTEST_IDS "/mnt/vendor/persist/attestation_ids.so"
#define OUTDIR "/data/local/tmp/kmtee_out"

#define CMD_ATTEST_KEYBOX 0x00050202u
#define CMD_ATTEST_IDS    0x00050204u
#define CMD_CLOSE         0x00050016u

// Minimal Trustonic client ABI, enough for libMcClient.so on this device.
typedef struct {
    uint32_t sessionId;
    uint32_t deviceId;
} mcSessionHandle_t;

typedef struct {
    uint32_t sVirtualAddr;
    uint32_t sVirtualLen;
} mcBulkMap_t;

extern uint32_t mcOpenDevice(uint32_t deviceId);
extern uint32_t mcCloseDevice(uint32_t deviceId);
extern uint32_t mcOpenTrustlet(mcSessionHandle_t *session, uint32_t spid, uint8_t *trustlet, uint32_t tLen, uint8_t *tci, uint32_t tciLen);
extern uint32_t mcCloseSession(mcSessionHandle_t *session);
extern uint32_t mcMap(mcSessionHandle_t *session, void *buf, uint32_t len, mcBulkMap_t *mapInfo);
extern uint32_t mcUnmap(mcSessionHandle_t *session, void *buf, mcBulkMap_t *mapInfo);
extern uint32_t mcNotify(mcSessionHandle_t *session);
extern uint32_t mcWaitNotification(mcSessionHandle_t *session, int32_t timeout);

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror(path); return -1; }
    if (fseek(fp, 0, SEEK_END) != 0) { perror("fseek end"); fclose(fp); return -1; }
    long n = ftell(fp);
    if (n <= 0) { fprintf(stderr, "bad size %s: %ld\n", path, n); fclose(fp); return -1; }
    if (fseek(fp, 0, SEEK_SET) != 0) { perror("fseek set"); fclose(fp); return -1; }
    uint8_t *buf = (uint8_t*)malloc((size_t)n);
    if (!buf) { perror("malloc"); fclose(fp); return -1; }
    if (fread(buf, (size_t)n, 1, fp) != 1) { perror("fread"); free(buf); fclose(fp); return -1; }
    fclose(fp);
    *out = buf; *out_len = (size_t)n; return 0;
}

static void write_file(const char *path, const void *buf, size_t len) {
    int fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, 0600);
    if (fd < 0) { perror(path); return; }
    const uint8_t *p = (const uint8_t*)buf;
    while (len) {
        ssize_t w = write(fd, p, len);
        if (w <= 0) { perror("write"); break; }
        p += w; len -= (size_t)w;
    }
    close(fd);
}

static int send_mapped(mcSessionHandle_t *s, uint8_t *tci, uint32_t cmd, uint8_t *buf, uint32_t len, const char *name) {
    mcBulkMap_t map = {0,0};
    memset(tci, 0, 0x140);
    uint32_t r = mcMap(s, buf, len, &map);
    printf("[%s] mcMap ret=0x%x sVA=0x%x sLen=0x%x len=%u\n", name, r, map.sVirtualAddr, map.sVirtualLen, len);
    if (r) return -1;
    *(uint32_t*)(tci + 0x00) = cmd;
    memcpy(tci + 0x0c, &map, 8);
    r = mcNotify(s);
    printf("[%s] mcNotify ret=0x%x\n", name, r);
    if (!r) r = mcWaitNotification(s, MC_INFINITE_TIMEOUT);
    printf("[%s] mcWait ret=0x%x tci_ret=0x%x\n", name, r, *(uint32_t*)(tci + 0x04));
    char path[256];
    snprintf(path, sizeof(path), OUTDIR "/%s_tci.bin", name);
    write_file(path, tci, 0x140);
    snprintf(path, sizeof(path), OUTDIR "/%s_buf_after.bin", name);
    write_file(path, buf, len);
    uint32_t ur = mcUnmap(s, buf, &map);
    printf("[%s] mcUnmap ret=0x%x\n", name, ur);
    return (r || *(uint32_t*)(tci + 0x04)) ? -2 : 0;
}

int main(int argc, char **argv) {
    const char *tl_path = (argc > 1) ? argv[1] : KEYMINT_TL;
    mkdir(OUTDIR, 0700);
    uint8_t *tl=NULL, *kb=NULL, *ids=NULL;
    size_t tl_len=0, kb_len=0, ids_len=0;
    printf("tl_path=%s\n", tl_path);
    if (read_file(tl_path, &tl, &tl_len)) return 2;
    if (read_file(ATTEST_KEYBOX, &kb, &kb_len)) return 3;
    if (read_file(ATTEST_IDS, &ids, &ids_len)) return 4;
    printf("tl=%zu keybox=%zu ids=%zu\n", tl_len, kb_len, ids_len);
    write_file(OUTDIR "/attest_keybox_before.bin", kb, kb_len);
    write_file(OUTDIR "/attestation_ids_before.bin", ids, ids_len);

    uint8_t *tci = (uint8_t*)calloc(1, 0x140);
    if (!tci) { perror("calloc tci"); return 5; }
    mcSessionHandle_t s;
    memset(&s, 0, sizeof(s));
    uint32_t r = mcOpenDevice(MC_DEVICE_ID_DEFAULT);
    printf("mcOpenDevice ret=0x%x\n", r);
    // spid=-2 in HAL, cast to uint32.
    r = mcOpenTrustlet(&s, (uint32_t)-2, tl, (uint32_t)tl_len, tci, 0x140);
    printf("mcOpenTrustlet ret=0x%x sessionId=0x%x deviceId=0x%x\n", r, s.sessionId, s.deviceId);
    if (r) return 6;

    int rc1 = send_mapped(&s, tci, CMD_ATTEST_KEYBOX, kb, (uint32_t)kb_len, "attest_keybox");
    int rc2 = send_mapped(&s, tci, CMD_ATTEST_IDS, ids, (uint32_t)ids_len, "attestation_ids");

    memset(tci, 0, 0x140);
    *(uint32_t*)tci = CMD_CLOSE;
    r = mcNotify(&s);
    if (!r) r = mcWaitNotification(&s, MC_INFINITE_TIMEOUT);
    printf("close cmd ret=0x%x tci_ret=0x%x\n", r, *(uint32_t*)(tci+4));
    write_file(OUTDIR "/close_tci.bin", tci, 0x140);
    r = mcCloseSession(&s);
    printf("mcCloseSession ret=0x%x\n", r);
    r = mcCloseDevice(MC_DEVICE_ID_DEFAULT);
    printf("mcCloseDevice ret=0x%x\n", r);
    printf("DONE rc1=%d rc2=%d\n", rc1, rc2);
    return 0;
}
