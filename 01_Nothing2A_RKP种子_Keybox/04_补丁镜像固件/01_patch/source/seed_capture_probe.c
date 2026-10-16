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
#define OUTDIR "/data/local/tmp/rkptee_out"
#define CMD_RKP_GENERATE_ECDSA_P256_KEY 0x00050401u
#define CMD_CLOSE 0x00050016u

typedef struct { uint32_t sessionId; uint32_t deviceId; } mcSessionHandle_t;
typedef struct { uint32_t sVirtualAddr; uint32_t sVirtualLen; } mcBulkMap_t;
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
    fseek(fp, 0, SEEK_END); long n = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (n <= 0) { fprintf(stderr, "bad size %s %ld\n", path, n); fclose(fp); return -1; }
    uint8_t *buf = (uint8_t*)malloc((size_t)n);
    if (!buf) { perror("malloc"); fclose(fp); return -1; }
    if (fread(buf, (size_t)n, 1, fp) != 1) { perror("fread"); free(buf); fclose(fp); return -1; }
    fclose(fp); *out = buf; *out_len = (size_t)n; return 0;
}
static void write_file(const char *path, const void *buf, size_t len) {
    int fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, 0600);
    if (fd < 0) { perror(path); return; }
    const uint8_t *p=(const uint8_t*)buf;
    while (len) { ssize_t w=write(fd,p,len); if (w<=0) { perror("write"); break; } p+=w; len-=(size_t)w; }
    close(fd);
}
static void put_u32_unaligned(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint32_t get_u32_unaligned(uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

static int send_rkp_gen(mcSessionHandle_t *s, uint8_t *tci, int testMode, const char *tag) {
    const uint32_t pub_cap = 4096;
    const uint32_t priv_cap = 8192;
    uint8_t *pub = (uint8_t*)calloc(1, pub_cap);
    uint8_t *priv = (uint8_t*)calloc(1, priv_cap);
    if (!pub || !priv) { perror("calloc buffers"); return -1; }
    mcBulkMap_t pub_map={0,0}, priv_map={0,0};
    uint32_t r = mcMap(s, pub, pub_cap, &pub_map);
    printf("[%s] pub mcMap ret=0x%x sVA=0x%x sLen=0x%x\n", tag, r, pub_map.sVirtualAddr, pub_map.sVirtualLen);
    if (r) return -2;
    r = mcMap(s, priv, priv_cap, &priv_map);
    printf("[%s] priv mcMap ret=0x%x sVA=0x%x sLen=0x%x\n", tag, r, priv_map.sVirtualAddr, priv_map.sVirtualLen);
    if (r) return -3;
    memset(tci, 0, 0x140);
    put_u32_unaligned(tci+0, CMD_RKP_GENERATE_ECDSA_P256_KEY);
    tci[12] = (uint8_t)(testMode ? 1 : 0);
    put_u32_unaligned(tci+13, pub_map.sVirtualAddr);
    put_u32_unaligned(tci+17, pub_map.sVirtualLen);
    put_u32_unaligned(tci+21, priv_map.sVirtualAddr);
    put_u32_unaligned(tci+25, priv_map.sVirtualLen);
    r = mcNotify(s);
    printf("[%s] mcNotify ret=0x%x\n", tag, r);
    if (!r) r = mcWaitNotification(s, MC_INFINITE_TIMEOUT);
    uint32_t tci_ret = get_u32_unaligned(tci+4);
    uint32_t pub_len = get_u32_unaligned(tci+17);
    uint32_t priv_len = get_u32_unaligned(tci+25);
    printf("[%s] mcWait ret=0x%x tci_ret=0x%x pub_len=%u priv_len=%u\n", tag, r, tci_ret, pub_len, priv_len);
    char path[256];
    snprintf(path, sizeof(path), OUTDIR "/%s_tci.bin", tag); write_file(path, tci, 0x140);
    snprintf(path, sizeof(path), OUTDIR "/%s_pub_full.bin", tag); write_file(path, pub, pub_cap);
    snprintf(path, sizeof(path), OUTDIR "/%s_priv_full.bin", tag); write_file(path, priv, priv_cap);
    snprintf(path, sizeof(path), OUTDIR "/%s_pub_len.bin", tag); write_file(path, pub, pub_len <= pub_cap ? pub_len : pub_cap);
    snprintf(path, sizeof(path), OUTDIR "/%s_priv_len.bin", tag); write_file(path, priv, priv_len <= priv_cap ? priv_len : priv_cap);
    printf("[%s] pub first:", tag); for (int i=0;i<16;i++) printf(" %02x", pub[i]); printf("\n");
    printf("[%s] priv first:", tag); for (int i=0;i<16;i++) printf(" %02x", priv[i]); printf("\n");
    mcUnmap(s, priv, &priv_map);
    mcUnmap(s, pub, &pub_map);
    free(pub); free(priv);
    return (r || tci_ret) ? -4 : 0;
}

int main(int argc, char **argv) {
    const char *tl_path = argc > 1 ? argv[1] : KEYMINT_TL;
    mkdir(OUTDIR, 0700);
    uint8_t *tl=NULL; size_t tl_len=0;
    printf("tl_path=%s\n", tl_path);
    if (read_file(tl_path, &tl, &tl_len)) return 2;
    printf("tl=%zu\n", tl_len);
    uint8_t *tci=(uint8_t*)calloc(1,0x140);
    mcSessionHandle_t s; memset(&s,0,sizeof(s));
    uint32_t r=mcOpenDevice(MC_DEVICE_ID_DEFAULT); printf("mcOpenDevice ret=0x%x\n", r);
    r=mcOpenTrustlet(&s,(uint32_t)-2,tl,(uint32_t)tl_len,tci,0x140);
    printf("mcOpenTrustlet ret=0x%x sessionId=0x%x deviceId=0x%x\n", r,s.sessionId,s.deviceId);
    if (r) return 3;
    int rc0=send_rkp_gen(&s,tci,0,"rkp_gen_prod");
    int rc1=send_rkp_gen(&s,tci,1,"rkp_gen_test");
    memset(tci,0,0x140); put_u32_unaligned(tci, CMD_CLOSE); r=mcNotify(&s); if(!r) r=mcWaitNotification(&s,MC_INFINITE_TIMEOUT);
    printf("close ret=0x%x tci_ret=0x%x\n", r, get_u32_unaligned(tci+4));
    write_file(OUTDIR "/close_tci.bin", tci, 0x140);
    mcCloseSession(&s); mcCloseDevice(MC_DEVICE_ID_DEFAULT);
    printf("DONE rc0=%d rc1=%d\n", rc0, rc1);
    return 0;
}
