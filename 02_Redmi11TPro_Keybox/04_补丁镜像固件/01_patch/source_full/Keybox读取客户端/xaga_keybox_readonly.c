#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define KEYBOX_READ_COMMAND 0x64u
#define KEYBOX_PARAM_TYPES 0x662u
#define KEYBOX_PAYLOAD_CAPACITY 0x4000u
#define KEYBOX_DESCRIPTOR_CAPACITY 0xa8u
#define TEEC_SUCCESS 0u
#define TEEC_LOGIN_PUBLIC 0u

typedef uint32_t TEEC_Result;

typedef struct {
    struct {
        int fd;
        bool reg_mem;
        bool memref_null;
    } imp;
} TEEC_Context;

typedef struct {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq_and_node[8];
} TEEC_UUID;

typedef struct {
    TEEC_Context *ctx;
    uint32_t session_id;
} TEEC_SessionImp;

typedef struct {
    TEEC_SessionImp imp;
} TEEC_Session;

typedef struct {
    void *buffer;
    size_t size;
} TEEC_TempMemoryReference;

typedef struct {
    void *parent;
    size_t size;
    size_t offset;
} TEEC_RegisteredMemoryReference;

typedef struct {
    uint32_t a;
    uint32_t b;
} TEEC_Value;

typedef union {
    TEEC_TempMemoryReference tmpref;
    TEEC_RegisteredMemoryReference memref;
    TEEC_Value value;
} TEEC_Parameter;

typedef struct {
    uint32_t started;
    uint32_t param_types;
    TEEC_Parameter params[4];
    struct {
        TEEC_Session *session;
    } imp;
} TEEC_Operation;

_Static_assert(sizeof(TEEC_Context) == 8, "unexpected TEEC_Context ABI");
_Static_assert(sizeof(TEEC_Session) == 16, "unexpected TEEC_Session ABI");
_Static_assert(sizeof(TEEC_Parameter) == 24, "unexpected TEEC_Parameter ABI");
_Static_assert(sizeof(TEEC_Operation) == 112, "unexpected TEEC_Operation ABI");

typedef TEEC_Result (*initialize_context_fn)(const char *, TEEC_Context *);
typedef void (*finalize_context_fn)(TEEC_Context *);
typedef TEEC_Result (*open_session_fn)(TEEC_Context *, TEEC_Session *,
                                       const TEEC_UUID *, uint32_t,
                                       const void *, TEEC_Operation *,
                                       uint32_t *);
typedef void (*close_session_fn)(TEEC_Session *);
typedef TEEC_Result (*invoke_command_fn)(TEEC_Session *, uint32_t,
                                         TEEC_Operation *, uint32_t *);

typedef struct {
    void *handle;
    initialize_context_fn initialize_context;
    finalize_context_fn finalize_context;
    open_session_fn open_session;
    close_session_fn close_session;
    invoke_command_fn invoke_command;
} TeeApi;

static const TEEC_UUID KEYBOX_TA_UUID = {
    0xd91f322a,
    0xd5a4,
    0x41d5,
    {0x95, 0x51, 0x10, 0xed, 0xa3, 0x27, 0x2f, 0xc0},
};

static void *required_symbol(void *handle, const char *name) {
    dlerror();
    void *symbol = dlsym(handle, name);
    const char *error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "dlsym(%s) failed: %s\n", name, error);
        return NULL;
    }
    return symbol;
}

static bool load_tee_api(TeeApi *api) {
    memset(api, 0, sizeof(*api));
    const char *override_path = getenv("XAGA_TEE_LIBRARY");
    const char *library_path =
        override_path != NULL && override_path[0] != '\0'
            ? override_path
            : "/vendor/lib64/libTEECommon.so";
    api->handle = dlopen(library_path, RTLD_NOW | RTLD_LOCAL);
    if (api->handle == NULL) {
        fprintf(stderr, "dlopen(%s) failed: %s\n", library_path, dlerror());
        return false;
    }

    api->initialize_context = (initialize_context_fn)required_symbol(
        api->handle, "TEEC_InitializeContext");
    api->finalize_context = (finalize_context_fn)required_symbol(
        api->handle, "TEEC_FinalizeContext");
    api->open_session = (open_session_fn)required_symbol(
        api->handle, "TEEC_OpenSession");
    api->close_session = (close_session_fn)required_symbol(
        api->handle, "TEEC_CloseSession");
    api->invoke_command = (invoke_command_fn)required_symbol(
        api->handle, "TEEC_InvokeCommand");

    if (api->initialize_context == NULL || api->finalize_context == NULL ||
        api->open_session == NULL || api->close_session == NULL ||
        api->invoke_command == NULL) {
        dlclose(api->handle);
        memset(api, 0, sizeof(*api));
        return false;
    }
    return true;
}

static bool write_binary(const char *path, const void *data, size_t size) {
    FILE *file = fopen(path, "wb");
    if (file == NULL) {
        fprintf(stderr, "fopen(%s) failed: %s\n", path, strerror(errno));
        return false;
    }
    bool ok = fwrite(data, 1, size, file) == size;
    if (fclose(file) != 0) {
        ok = false;
    }
    if (!ok) {
        fprintf(stderr, "write(%s) failed\n", path);
    }
    return ok;
}

static bool build_path(char *path, size_t path_size, const char *directory,
                       const char *name) {
    int written = snprintf(path, path_size, "%s/%s", directory, name);
    return written > 0 && (size_t)written < path_size;
}

static void write_status(const char *directory, TEEC_Result init_result,
                         TEEC_Result open_result, uint32_t open_origin,
                         TEEC_Result invoke_result, uint32_t invoke_origin,
                         const TEEC_Operation *operation,
                         bool payload_saved) {
    char path[512];
    if (!build_path(path, sizeof(path), directory, "调用状态.txt")) {
        return;
    }
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        fprintf(stderr, "fopen(%s) failed: %s\n", path, strerror(errno));
        return;
    }
    fprintf(file,
            "目标TA=d91f322a-d5a4-41d5-9551-10eda3272fc0\n"
            "命令=0x%08x\n参数类型=0x%08x\n"
            "InitializeContext=0x%08x\n"
            "OpenSession=0x%08x\nOpenSession来源=0x%08x\n"
            "InvokeCommand=0x%08x\nInvokeCommand来源=0x%08x\n"
            "TA内部状态_p0_a=0x%08x\nTA输出_p0_b=0x%08x\n"
            "Keybox输出长度=%zu\n描述区输出长度=%zu\n"
            "载荷已保存=%s\n",
            KEYBOX_READ_COMMAND, KEYBOX_PARAM_TYPES, init_result,
            open_result, open_origin, invoke_result, invoke_origin,
            operation->params[0].value.a, operation->params[0].value.b,
            operation->params[1].tmpref.size,
            operation->params[2].tmpref.size,
            payload_saved ? "是" : "否");
    fclose(file);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "用法: %s 输出目录\n", argv[0]);
        return 2;
    }

    const char *output_directory = argv[1];
    if (mkdir(output_directory, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir(%s) failed: %s\n", output_directory,
                strerror(errno));
        return 3;
    }

    TeeApi api;
    if (!load_tee_api(&api)) {
        return 4;
    }

    uint8_t keybox_payload[KEYBOX_PAYLOAD_CAPACITY] = {0};
    uint8_t descriptor[KEYBOX_DESCRIPTOR_CAPACITY] = {0};
    TEEC_Context context = {0};
    TEEC_Session session = {0};
    TEEC_Operation operation = {0};
    uint32_t open_origin = 0;
    uint32_t invoke_origin = 0;
    TEEC_Result open_result = 0xffffffffu;
    TEEC_Result invoke_result = 0xffffffffu;
    bool context_open = false;
    bool session_open = false;
    bool payload_saved = false;

    operation.param_types = KEYBOX_PARAM_TYPES;
    operation.params[1].tmpref.buffer = keybox_payload;
    operation.params[1].tmpref.size = sizeof(keybox_payload);
    operation.params[2].tmpref.buffer = descriptor;
    operation.params[2].tmpref.size = sizeof(descriptor);

    TEEC_Result init_result = api.initialize_context(NULL, &context);
    if (init_result == TEEC_SUCCESS) {
        context_open = true;
        open_result = api.open_session(&context, &session, &KEYBOX_TA_UUID,
                                       TEEC_LOGIN_PUBLIC, NULL, NULL,
                                       &open_origin);
    }
    if (open_result == TEEC_SUCCESS) {
        session_open = true;
        invoke_result = api.invoke_command(&session, KEYBOX_READ_COMMAND,
                                           &operation, &invoke_origin);
    }

    if (invoke_result == TEEC_SUCCESS && operation.params[0].value.a == 0 &&
        operation.params[1].tmpref.size <= sizeof(keybox_payload) &&
        operation.params[2].tmpref.size <= sizeof(descriptor)) {
        char payload_path[512];
        char descriptor_path[512];
        if (build_path(payload_path, sizeof(payload_path), output_directory,
                       "keybox_原始载荷.bin") &&
            build_path(descriptor_path, sizeof(descriptor_path),
                       output_directory, "keybox_描述区.bin")) {
            payload_saved = write_binary(payload_path, keybox_payload,
                                         operation.params[1].tmpref.size) &&
                            write_binary(descriptor_path, descriptor,
                                         operation.params[2].tmpref.size);
        }
    }

    write_status(output_directory, init_result, open_result, open_origin,
                 invoke_result, invoke_origin, &operation, payload_saved);

    printf("InitializeContext=0x%08x\n", init_result);
    printf("OpenSession=0x%08x origin=0x%08x\n", open_result, open_origin);
    printf("InvokeCommand=0x%08x origin=0x%08x\n", invoke_result,
           invoke_origin);
    printf("TA status=0x%08x payload=%zu descriptor=%zu saved=%s\n",
           operation.params[0].value.a, operation.params[1].tmpref.size,
           operation.params[2].tmpref.size, payload_saved ? "yes" : "no");

    if (session_open) {
        api.close_session(&session);
    }
    if (context_open) {
        api.finalize_context(&context);
    }
    dlclose(api.handle);

    return payload_saved ? 0 : 1;
}
