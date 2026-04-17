// object.c — Content-addressable object store

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

// ─── FIXED IMPLEMENTATION ───────────────────────────────────────────────────

// Write object
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {

    const char *type_str;
    if      (type == OBJ_BLOB)   type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // Step 1: Build full object
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);

    size_t full_len = (size_t)header_len + 1 + len;
    uint8_t *full_obj = malloc(full_len);
    if (!full_obj) return -1;

    memcpy(full_obj, header, header_len);
    full_obj[header_len] = '\0';
    memcpy(full_obj + header_len + 1, data, len);

    // Step 2: Hash
    compute_hash(full_obj, full_len, id_out);

    // Step 3: Dedup
    if (object_exists(id_out)) {
        free(full_obj);
        return 0;
    }

    // Step 4: Ensure directories exist
    mkdir(".pes", 0755);
    mkdir(".pes/objects", 0755);

    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755);

    // Step 5: Paths
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    char tmp_path[520];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path);

    // Step 6: Write temp file
    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full_obj);
        return -1;
    }

    ssize_t written = write(fd, full_obj, full_len);
    if (written != (ssize_t)full_len) {
        close(fd);
        free(full_obj);
        return -1;
    }

    // Step 7: fsync
    if (fsync(fd) < 0) {
        close(fd);
        free(full_obj);
        return -1;
    }

    close(fd);
    free(full_obj);

    // Step 8: Rename
    if (rename(tmp_path, final_path) != 0) {
        perror("rename failed");
        return -1;
    }

    // Step 9: fsync directory
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    return 0;
}

// Read object
int object_read(const ObjectID *id, ObjectType *type_out,
                void **data_out, size_t *len_out) {

    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    if (file_size <= 0) {
        fclose(f);
        return -1;
    }

    uint8_t *buf = malloc(file_size);
    if (!buf) {
        fclose(f);
        return -1;
    }

    if (fread(buf, 1, file_size, f) != (size_t)file_size) {
        fclose(f);
        free(buf);
        return -1;
    }

    fclose(f);

    // Step 1: Verify hash
    ObjectID computed;
    compute_hash(buf, file_size, &computed);

    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1;
    }

    // Step 2: Parse header
    uint8_t *null_ptr = memchr(buf, '\0', file_size);
    if (!null_ptr) {
        free(buf);
        return -1;
    }

    size_t header_len = null_ptr - buf;

    char header[64];
    memcpy(header, buf, header_len);
    header[header_len] = '\0';

    char type_str[16];
    size_t size;

    if (sscanf(header, "%15s %zu", type_str, &size) != 2) {
        free(buf);
        return -1;
    }

    if (strcmp(type_str, "blob") == 0)        *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0)   *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else {
        free(buf);
        return -1;
    }

    // Step 3: Extract data
    uint8_t *data_start = null_ptr + 1;
    size_t data_len = file_size - (header_len + 1);

    if (data_len != size) {
        free(buf);
        return -1;
    }

    void *out = malloc(data_len);
    if (!out) {
        free(buf);
        return -1;
    }

    memcpy(out, data_start, data_len);

    *data_out = out;
    *len_out = data_len;

    free(buf);
    return 0;
}
