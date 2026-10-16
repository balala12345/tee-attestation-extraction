#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>

#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

static const char* kService =
    "android.hardware.security.keymint.IRemotelyProvisionedComponent/default";
static const char* kDescriptor =
    "android.hardware.security.keymint.IRemotelyProvisionedComponent";
static const uint32_t kTxnGenerateCertificateRequest = 3;

struct Bytes {
    std::vector<int8_t> data;
    bool is_null = false;
};

static bool byte_array_alloc(void* ctx, int32_t length, int8_t** out) {
    Bytes* b = static_cast<Bytes*>(ctx);
    if (length < 0) {
        b->is_null = true;
        b->data.clear();
        *out = nullptr;
        return true;
    }
    b->is_null = false;
    b->data.assign(static_cast<size_t>(length), 0);
    *out = b->data.empty() ? nullptr : b->data.data();
    return true;
}

static std::vector<int8_t> read_file(const char* path) {
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        exit(2);
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "fseek %s failed\n", path);
        exit(2);
    }
    long n = ftell(fp);
    if (n < 0) {
        fprintf(stderr, "ftell %s failed\n", path);
        exit(2);
    }
    rewind(fp);
    std::vector<int8_t> out(static_cast<size_t>(n));
    if (n && fread(out.data(), static_cast<size_t>(n), 1, fp) != 1) {
        fprintf(stderr, "read %s failed\n", path);
        exit(2);
    }
    fclose(fp);
    return out;
}

static void write_file(const char* path, const std::vector<int8_t>& data) {
    FILE* fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "create %s: %s\n", path, strerror(errno));
        exit(3);
    }
    if (!data.empty() && fwrite(data.data(), data.size(), 1, fp) != 1) {
        fprintf(stderr, "write %s failed\n", path);
        exit(3);
    }
    fclose(fp);
}

static void check_status(binder_status_t st, const char* what) {
    if (st != STATUS_OK) {
        fprintf(stderr, "%s failed: binder_status=%d\n", what, st);
        exit(4);
    }
}

static binder_status_t write_sized_byte_array_parcelable(AParcel* p, const std::vector<int8_t>& b) {
    int32_t start = AParcel_getDataPosition(p);
    binder_status_t st = AParcel_writeInt32(p, 0);
    if (st != STATUS_OK) return st;
    st = AParcel_writeByteArray(p, b.empty() ? nullptr : b.data(), static_cast<int32_t>(b.size()));
    if (st != STATUS_OK) return st;
    int32_t end = AParcel_getDataPosition(p);
    st = AParcel_setDataPosition(p, start);
    if (st != STATUS_OK) return st;
    st = AParcel_writeInt32(p, end - start);
    if (st != STATUS_OK) return st;
    return AParcel_setDataPosition(p, end);
}

static binder_status_t read_sized_byte_array_parcelable(const AParcel* p, Bytes* out) {
    int32_t size = 0;
    int32_t start = AParcel_getDataPosition(p);
    binder_status_t st = AParcel_readInt32(p, &size);
    if (st != STATUS_OK) return st;
    if (size < 4) return STATUS_BAD_VALUE;
    st = AParcel_readByteArray(p, out, byte_array_alloc);
    if (st != STATUS_OK) return st;
    return AParcel_setDataPosition(p, start + size);
}

static void* noop_create(void*) {
    return nullptr;
}

static void noop_destroy(void*) {}

static binder_status_t noop_transact(AIBinder*, transaction_code_t, const AParcel*, AParcel*) {
    return STATUS_UNKNOWN_TRANSACTION;
}

int main(int argc, char** argv) {
    if (argc < 5) {
        fprintf(stderr,
                "usage: %s OUTDIR ENDPOINT_CBOR CHALLENGE_BIN MACED_PUBLIC_KEY...\n",
                argv[0]);
        return 1;
    }
    const char* outdir = argv[1];
    std::vector<int8_t> endpoint = read_file(argv[2]);
    std::vector<int8_t> challenge = read_file(argv[3]);
    std::vector<std::vector<int8_t>> keys;
    for (int i = 4; i < argc; ++i) keys.push_back(read_file(argv[i]));

    void* lib = dlopen("libbinder_ndk.so", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "dlopen libbinder_ndk.so failed: %s\n", dlerror());
        return 5;
    }
    typedef AIBinder* (*WaitForServiceFn)(const char*);
    auto wait_for_service = reinterpret_cast<WaitForServiceFn>(
        dlsym(lib, "AServiceManager_waitForService"));
    if (!wait_for_service) {
        fprintf(stderr, "dlsym AServiceManager_waitForService failed: %s\n", dlerror());
        return 5;
    }

    AIBinder* binder = wait_for_service(kService);
    if (!binder) {
        fprintf(stderr, "service not found: %s\n", kService);
        return 6;
    }
    AIBinder_Class* clazz =
        AIBinder_Class_define(kDescriptor, noop_create, noop_destroy, noop_transact);
    if (!clazz || !AIBinder_associateClass(binder, clazz)) {
        fprintf(stderr, "failed to associate binder class\n");
        return 7;
    }

    AParcel* in = nullptr;
    check_status(AIBinder_prepareTransaction(binder, &in), "prepareTransaction");
    check_status(AParcel_writeBool(in, false), "write testMode");
    check_status(AParcel_writeInt32(in, static_cast<int32_t>(keys.size())), "write key count");
    for (const auto& key : keys) {
        check_status(AParcel_writeInt32(in, 1), "write key present");
        check_status(write_sized_byte_array_parcelable(in, key), "write MacedPublicKey");
    }
    check_status(AParcel_writeByteArray(in, endpoint.data(), static_cast<int32_t>(endpoint.size())),
                 "write endpoint");
    check_status(AParcel_writeByteArray(in, challenge.data(), static_cast<int32_t>(challenge.size())),
                 "write challenge");

    AParcel* reply = nullptr;
    binder_status_t tx = AIBinder_transact(
        binder, kTxnGenerateCertificateRequest, &in, &reply, 0);
    if (tx != STATUS_OK) {
        fprintf(stderr, "transact failed: binder_status=%d\n", tx);
        return 8;
    }

    AStatus* status = nullptr;
    check_status(AParcel_readStatusHeader(reply, &status), "read status header");
    if (!AStatus_isOk(status)) {
        fprintf(stderr, "remote exception=%d service_error=%d status=%d\n",
                AStatus_getExceptionCode(status),
                AStatus_getServiceSpecificError(status),
                AStatus_getStatus(status));
        AStatus_delete(status);
        AParcel_delete(reply);
        AIBinder_decStrong(binder);
        return 9;
    }
    AStatus_delete(status);

    Bytes mac;
    check_status(AParcel_readByteArray(reply, &mac, byte_array_alloc), "read maced_keys_mac");
    int32_t present = 0;
    Bytes device;
    Bytes protected_data;
    check_status(AParcel_readInt32(reply, &present), "read DeviceInfo present");
    if (present) check_status(read_sized_byte_array_parcelable(reply, &device), "read DeviceInfo");
    check_status(AParcel_readInt32(reply, &present), "read ProtectedData present");
    if (present) {
        check_status(read_sized_byte_array_parcelable(reply, &protected_data),
                     "read ProtectedData");
    }
    AParcel_delete(reply);
    AIBinder_decStrong(binder);

    std::string base(outdir);
    write_file((base + "/csr_maced_keys_len.bin").c_str(), mac.data);
    write_file((base + "/csr_device_info_len.bin").c_str(), device.data);
    write_file((base + "/csr_protected_data_len.bin").c_str(), protected_data.data);
    fprintf(stdout, "OK keys=%zu mac=%zu device=%zu protected=%zu\n",
            keys.size(), mac.data.size(), device.data.size(), protected_data.data.size());
    return 0;
}
