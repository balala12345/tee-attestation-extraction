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
#define OUTDIR "/data/local/tmp/rkptee_csr_out"
#define CMD_ATTEST_KEYBOX 0x00050202u
#define CMD_ATTEST_IDS    0x00050204u
#define CMD_RKP_GENERATE_ECDSA_P256_KEY 0x00050401u
#define CMD_RKP_GENERATE_CERTIFICATE_REQUEST 0x00050402u
#define CMD_CLOSE 0x00050016u
#define MAX_RKP_KEYS 20u

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
    if (n < 0) { fprintf(stderr, "bad size %s %ld\n", path, n); fclose(fp); return -1; }
    uint8_t *buf = (uint8_t*)malloc((size_t)n ? (size_t)n : 1);
    if (!buf) { perror("malloc"); fclose(fp); return -1; }
    if (n && fread(buf, (size_t)n, 1, fp) != 1) { perror("fread"); free(buf); fclose(fp); return -1; }
    fclose(fp); *out = buf; *out_len = (size_t)n; return 0;
}
static void write_file(const char *path, const void *buf, size_t len) {
    int fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, 0600);
    if (fd < 0) { perror(path); return; }
    const uint8_t *p=(const uint8_t*)buf;
    while (len) { ssize_t w=write(fd,p,len); if (w<=0) { perror("write"); break; } p+=w; len-=(size_t)w; }
    close(fd);
}
static void put_u32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint32_t get_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

static int send_mapped_cmd(mcSessionHandle_t *s, uint8_t *tci, uint32_t cmd, uint8_t *buf, uint32_t len, const char *name) {
    mcBulkMap_t map = {0,0};
    memset(tci, 0, 0x140);
    uint32_t r = mcMap(s, buf, len, &map);
    printf("[%s] mcMap ret=0x%x sVA=0x%x sLen=0x%x len=%u\n", name, r, map.sVirtualAddr, map.sVirtualLen, len);
    if (r) return -1;
    put_u32(tci + 0x00, cmd);
    memcpy(tci + 0x0c, &map, 8);
    r = mcNotify(s);
    printf("[%s] mcNotify ret=0x%x\n", name, r);
    if (!r) r = mcWaitNotification(s, MC_INFINITE_TIMEOUT);
    uint32_t tci_ret = get_u32(tci + 0x04);
    printf("[%s] mcWait ret=0x%x tci_ret=0x%x\n", name, r, tci_ret);
    char path[256];
    snprintf(path, sizeof(path), OUTDIR "/%s_tci.bin", name);
    write_file(path, tci, 0x140);
    snprintf(path, sizeof(path), OUTDIR "/%s_buf_after.bin", name);
    write_file(path, buf, len);
    uint32_t ur = mcUnmap(s, buf, &map);
    printf("[%s] mcUnmap ret=0x%x\n", name, ur);
    return (r || tci_ret) ? -2 : 0;
}

static int init_keymint_globals(mcSessionHandle_t *s, uint8_t *tci) {
    uint8_t *kb = NULL, *ids = NULL;
    size_t kb_len = 0, ids_len = 0;
    printf("init_keymint_globals CMD_ATTEST_KEYBOX=0x%08x CMD_ATTEST_IDS=0x%08x\n", CMD_ATTEST_KEYBOX, CMD_ATTEST_IDS);
    if (read_file(ATTEST_KEYBOX, &kb, &kb_len)) return -1;
    if (read_file(ATTEST_IDS, &ids, &ids_len)) { free(kb); return -2; }
    printf("init_keymint_globals keybox=%zu ids=%zu\n", kb_len, ids_len);
    write_file(OUTDIR "/attest_keybox_before.bin", kb, kb_len);
    write_file(OUTDIR "/attestation_ids_before.bin", ids, ids_len);
    int rc1 = send_mapped_cmd(s, tci, CMD_ATTEST_KEYBOX, kb, (uint32_t)kb_len, "attest_keybox");
    int rc2 = rc1 ? 0 : send_mapped_cmd(s, tci, CMD_ATTEST_IDS, ids, (uint32_t)ids_len, "attestation_ids");
    free(kb);
    free(ids);
    printf("init_keymint_globals done rc_keybox=%d rc_ids=%d\n", rc1, rc2);
    return rc1 ? rc1 : rc2;
}

struct RkpGenOut {
    uint8_t pub[4096]; uint32_t pub_len;
    uint8_t priv[8192]; uint32_t priv_len;
};

static int send_rkp_gen(mcSessionHandle_t *s, uint8_t *tci, int testMode, const char *tag, struct RkpGenOut *out) {
    const uint32_t pub_cap = sizeof(out->pub);
    const uint32_t priv_cap = sizeof(out->priv);
    memset(out, 0, sizeof(*out));
    mcBulkMap_t pub_map={0,0}, priv_map={0,0};
    uint32_t r = mcMap(s, out->pub, pub_cap, &pub_map);
    printf("[%s] pub mcMap ret=0x%x sVA=0x%x sLen=0x%x\n", tag, r, pub_map.sVirtualAddr, pub_map.sVirtualLen);
    if (r) return -2;
    r = mcMap(s, out->priv, priv_cap, &priv_map);
    printf("[%s] priv mcMap ret=0x%x sVA=0x%x sLen=0x%x\n", tag, r, priv_map.sVirtualAddr, priv_map.sVirtualLen);
    if (r) return -3;
    memset(tci, 0, 0x140);
    put_u32(tci+0, CMD_RKP_GENERATE_ECDSA_P256_KEY);
    tci[12] = (uint8_t)(testMode ? 1 : 0);
    put_u32(tci+13, pub_map.sVirtualAddr);
    put_u32(tci+17, pub_map.sVirtualLen);
    put_u32(tci+21, priv_map.sVirtualAddr);
    put_u32(tci+25, priv_map.sVirtualLen);
    r = mcNotify(s);
    if (!r) r = mcWaitNotification(s, MC_INFINITE_TIMEOUT);
    uint32_t tci_ret = get_u32(tci+4);
    out->pub_len = get_u32(tci+17);
    out->priv_len = get_u32(tci+25);
    printf("[%s] wait ret=0x%x tci_ret=0x%x pub_len=%u priv_len=%u\n", tag, r, tci_ret, out->pub_len, out->priv_len);
    char path[256];
    snprintf(path, sizeof(path), OUTDIR "/%s_tci.bin", tag); write_file(path, tci, 0x140);
    snprintf(path, sizeof(path), OUTDIR "/%s_pub_len.bin", tag); write_file(path, out->pub, out->pub_len <= pub_cap ? out->pub_len : pub_cap);
    snprintf(path, sizeof(path), OUTDIR "/%s_priv_len.bin", tag); write_file(path, out->priv, out->priv_len <= priv_cap ? out->priv_len : priv_cap);
    snprintf(path, sizeof(path), OUTDIR "/%s_priv_full.bin", tag); write_file(path, out->priv, priv_cap);
    mcUnmap(s, out->priv, &priv_map);
    mcUnmap(s, out->pub, &pub_map);
    return (r || tci_ret) ? -4 : 0;
}

static int send_rkp_csr(mcSessionHandle_t *s, uint8_t *tci, const struct RkpGenOut *keys, uint32_t key_count, const uint8_t *endpoint, uint32_t endpoint_len, const uint8_t *challenge, uint32_t challenge_len, int testMode) {
    uint32_t keys_len = 4u;
    for (uint32_t i = 0; i < key_count; i++) keys_len += 4u + keys[i].pub_len;
    uint32_t in_len = keys_len + endpoint_len + challenge_len;
    if (in_len == 0) in_len = 1;
    uint8_t *in = (uint8_t*)calloc(1, in_len);
    uint8_t *devinfo = (uint8_t*)calloc(1, 1024);
    uint8_t *protected_data = (uint8_t*)calloc(1, 4096);
    uint8_t *maced_keys = (uint8_t*)calloc(1, 32);
    if (!in || !devinfo || !protected_data || !maced_keys) { perror("calloc csr buffers"); return -10; }
    put_u32(in, key_count);
    uint32_t pos = 4;
    for (uint32_t i = 0; i < key_count; i++) {
        put_u32(in + pos, keys[i].pub_len);
        pos += 4;
        memcpy(in + pos, keys[i].pub, keys[i].pub_len);
        pos += keys[i].pub_len;
    }
    if (endpoint_len) memcpy(in + keys_len, endpoint, endpoint_len);
    if (challenge_len) memcpy(in + keys_len + endpoint_len, challenge, challenge_len);

    mcBulkMap_t in_map={0,0}, dev_map={0,0}, prot_map={0,0}, mac_map={0,0};
    uint32_t r = mcMap(s, in, in_len, &in_map);
    printf("[csr] in mcMap ret=0x%x sVA=0x%x sLen=0x%x key_count=%u keys_len=%u endpoint_len=%u challenge_len=%u\n", r, in_map.sVirtualAddr, in_map.sVirtualLen, key_count, keys_len, endpoint_len, challenge_len);
    if (r) return -11;
    r = mcMap(s, devinfo, 1024, &dev_map);
    printf("[csr] devinfo mcMap ret=0x%x sVA=0x%x sLen=0x%x\n", r, dev_map.sVirtualAddr, dev_map.sVirtualLen);
    if (r) return -12;
    r = mcMap(s, protected_data, 4096, &prot_map);
    printf("[csr] protected mcMap ret=0x%x sVA=0x%x sLen=0x%x\n", r, prot_map.sVirtualAddr, prot_map.sVirtualLen);
    if (r) return -13;
    r = mcMap(s, maced_keys, 32, &mac_map);
    printf("[csr] maced_keys mcMap ret=0x%x sVA=0x%x sLen=0x%x\n", r, mac_map.sVirtualAddr, mac_map.sVirtualLen);
    if (r) return -14;

    memset(tci, 0, 0x140);
    put_u32(tci+0, CMD_RKP_GENERATE_CERTIFICATE_REQUEST);
    tci[12] = (uint8_t)(testMode ? 1 : 0);
    put_u32(tci+13, in_map.sVirtualAddr);
    put_u32(tci+17, keys_len);
    put_u32(tci+21, in_map.sVirtualAddr + keys_len);
    put_u32(tci+25, endpoint_len);
    put_u32(tci+29, in_map.sVirtualAddr + keys_len + endpoint_len);
    put_u32(tci+33, challenge_len);
    put_u32(tci+37, dev_map.sVirtualAddr);
    put_u32(tci+41, dev_map.sVirtualLen);
    put_u32(tci+45, prot_map.sVirtualAddr);
    put_u32(tci+49, prot_map.sVirtualLen);
    put_u32(tci+53, mac_map.sVirtualAddr);
    put_u32(tci+57, mac_map.sVirtualLen);

    r = mcNotify(s);
    if (!r) r = mcWaitNotification(s, MC_INFINITE_TIMEOUT);
    uint32_t tci_ret = get_u32(tci+4);
    uint32_t dev_len = get_u32(tci+41);
    uint32_t prot_len = get_u32(tci+49);
    uint32_t mac_len = get_u32(tci+57);
    printf("[csr] wait ret=0x%x tci_ret=0x%x dev_len=%u protected_len=%u maced_keys_len=%u\n", r, tci_ret, dev_len, prot_len, mac_len);

    write_file(OUTDIR "/csr_tci.bin", tci, 0x140);
    write_file(OUTDIR "/csr_input_combined.bin", in, in_len);
    write_file(OUTDIR "/csr_device_info_full.bin", devinfo, 1024);
    write_file(OUTDIR "/csr_protected_data_full.bin", protected_data, 4096);
    write_file(OUTDIR "/csr_maced_keys_full.bin", maced_keys, 32);
    write_file(OUTDIR "/csr_device_info_len.bin", devinfo, dev_len <= 1024 ? dev_len : 1024);
    write_file(OUTDIR "/csr_protected_data_len.bin", protected_data, prot_len <= 4096 ? prot_len : 4096);
    write_file(OUTDIR "/csr_maced_keys_len.bin", maced_keys, mac_len <= 32 ? mac_len : 32);

    mcUnmap(s, maced_keys, &mac_map);
    mcUnmap(s, protected_data, &prot_map);
    mcUnmap(s, devinfo, &dev_map);
    mcUnmap(s, in, &in_map);
    free(maced_keys); free(protected_data); free(devinfo); free(in);
    return (r || tci_ret) ? -20 : 0;
}

int main(int argc, char **argv) {
    const char *tl_path = argc > 1 ? argv[1] : KEYMINT_TL;
    uint8_t *endpoint=NULL; size_t endpoint_len=0;
    uint8_t *challenge=NULL; size_t challenge_len=0;
    const uint8_t default_challenge[32] = {
        'c','o','d','e','x','-','r','k','p','-','c','s','r','-','2','0',
        '2','6','0','8','1','5','-','c','t','f','-','0','0','0','1'
    };
    if (argc > 2 && read_file(argv[2], &endpoint, &endpoint_len)) return 4;
    if (argc > 3) {
        if (read_file(argv[3], &challenge, &challenge_len)) return 5;
    } else {
        challenge = (uint8_t*)malloc(sizeof(default_challenge));
        memcpy(challenge, default_challenge, sizeof(default_challenge));
        challenge_len = sizeof(default_challenge);
    }
    int testMode = 0;
    if (argc > 4) testMode = atoi(argv[4]) != 0;
    uint32_t key_count = 1;
    if (argc > 5) {
        long n = strtol(argv[5], NULL, 0);
        if (n < 1 || n > (long)MAX_RKP_KEYS) {
            fprintf(stderr, "invalid key_count %ld, expected 1..%u\n", n, MAX_RKP_KEYS);
            return 6;
        }
        key_count = (uint32_t)n;
    }
    mkdir(OUTDIR, 0700);
    uint8_t *tl=NULL; size_t tl_len=0;
    printf("tl_path=%s testMode=%d key_count=%u\n", tl_path, testMode, key_count);
    if (read_file(tl_path, &tl, &tl_len)) return 2;
    printf("tl=%zu endpoint_len=%zu challenge_len=%zu\n", tl_len, endpoint_len, challenge_len);
    uint8_t *tci=(uint8_t*)calloc(1,0x140);
    mcSessionHandle_t s; memset(&s,0,sizeof(s));
    uint32_t r=mcOpenDevice(MC_DEVICE_ID_DEFAULT); printf("mcOpenDevice ret=0x%x\n", r);
    r=mcOpenTrustlet(&s,(uint32_t)-2,tl,(uint32_t)tl_len,tci,0x140);
    printf("mcOpenTrustlet ret=0x%x sessionId=0x%x deviceId=0x%x\n", r,s.sessionId,s.deviceId);
    if (r) return 3;
    int rc_init = init_keymint_globals(&s, tci);
    struct RkpGenOut *keys = (struct RkpGenOut*)calloc(key_count, sizeof(struct RkpGenOut));
    if (!keys) { perror("calloc keys"); return 7; }
    int rc0=0;
    int rc1=0;
    if (!rc_init) {
        for (uint32_t i = 0; i < key_count; i++) {
            char tag[64];
            snprintf(tag, sizeof(tag), "%s_%02u", testMode ? "rkp_gen_test" : "rkp_gen_prod", i);
            rc0=send_rkp_gen(&s,tci,testMode,tag,&keys[i]);
            if (rc0) break;
        }
        if (!rc0) rc1=send_rkp_csr(&s,tci,keys,key_count,endpoint,(uint32_t)endpoint_len,challenge,(uint32_t)challenge_len,testMode);
    }
    memset(tci,0,0x140); put_u32(tci, CMD_CLOSE); r=mcNotify(&s); if(!r) r=mcWaitNotification(&s,MC_INFINITE_TIMEOUT);
    printf("close ret=0x%x tci_ret=0x%x\n", r, get_u32(tci+4));
    write_file(OUTDIR "/close_tci.bin", tci, 0x140);
    mcCloseSession(&s); mcCloseDevice(MC_DEVICE_ID_DEFAULT);
    printf("DONE rc_init=%d rc_gen=%d rc_csr=%d\n", rc_init, rc0, rc1);
    free(keys); free(tci); free(tl); free(endpoint); free(challenge);
    return (rc_init || rc0 || rc1) ? 10 : 0;
}
