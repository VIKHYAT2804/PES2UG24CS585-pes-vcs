// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

// Write an object to the store.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // 1. Build the header: "<type> <size>\0"
    const char *type_str;
    if      (type == OBJ_BLOB)   type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    // header_len does NOT include the null terminator, but we want it in the object
    // total object = header + '\0' + data
    size_t obj_len = (size_t)header_len + 1 + len;
    uint8_t *obj = malloc(obj_len);
    if (!obj) return -1;

    memcpy(obj, header, (size_t)header_len);
    obj[header_len] = '\0';
    memcpy(obj + header_len + 1, data, len);

    // 2. Compute SHA-256 of the full object
    compute_hash(obj, obj_len, id_out);

    // 3. Deduplication check
    if (object_exists(id_out)) {
        free(obj);
        return 0;
    }

    // 4. Create shard directory
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755);

    // 5. Write to a temp file in the shard directory
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    char tmp_path[520];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path);

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0444);
    if (fd < 0) { free(obj); return -1; }

    size_t written = 0;
    while (written < obj_len) {
        ssize_t n = write(fd, obj + written, obj_len - written);
        if (n < 0) { close(fd); free(obj); return -1; }
        written += (size_t)n;
    }

    // 6. fsync the temp file
    fsync(fd);
    close(fd);
    free(obj);

    // 7. Atomic rename to final path
    if (rename(tmp_path, final_path) != 0) return -1;

    // 8. fsync the shard directory to persist the rename
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    return 0;
}

// Read an object from the store.
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // 1. Build the file path
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open and read the entire file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0) { fclose(f); return -1; }

    uint8_t *raw = malloc((size_t)file_size);
    if (!raw) { fclose(f); return -1; }

    if (fread(raw, 1, (size_t)file_size, f) != (size_t)file_size) {
        fclose(f); free(raw); return -1;
    }
    fclose(f);

    // 4. Verify integrity: recompute hash and compare to filename
    ObjectID computed;
    compute_hash(raw, (size_t)file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(raw);
        return -1;
    }

    // 3. Parse the header: find the '\0' separating header from data
    uint8_t *null_byte = memchr(raw, '\0', (size_t)file_size);
    if (!null_byte) { free(raw); return -1; }

    // Parse type string
    if      (strncmp((char *)raw, "blob ",   5) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char *)raw, "tree ",   5) == 0) *type_out = OBJ_TREE;
    else if (strncmp((char *)raw, "commit ", 7) == 0) *type_out = OBJ_COMMIT;
    else { free(raw); return -1; }

    // Parse size from header
    char *space = memchr(raw, ' ', null_byte - raw);
    if (!space) { free(raw); return -1; }
    size_t data_size = (size_t)strtoul(space + 1, NULL, 10);

    // 6. Allocate and copy the data portion
    uint8_t *data_start = null_byte + 1;
    size_t actual_data_len = (size_t)file_size - (size_t)(data_start - raw);

    if (actual_data_len != data_size) { free(raw); return -1; }

    void *out = malloc(data_size + 1); // +1 for safe null termination
    if (!out) { free(raw); return -1; }
    memcpy(out, data_start, data_size);
    ((uint8_t *)out)[data_size] = '\0';

    free(raw);
    *data_out = out;
    *len_out = data_size;
    return 0;
}

