// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"

#include "tree.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// Forward declaration
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1;

        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';

        ptr = null_byte + 1;

        if (ptr + HASH_SIZE > end) return -1;
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1;
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

// Recursive helper: build a tree from a subset of index entries that share
// a common prefix (the current directory level).
//
// entries: array of IndexEntry pointers for this level
// count:   number of entries
// prefix:  the path prefix to strip (e.g., "src/" for entries in src/)
// id_out:  output — hash of the written tree object
static int write_tree_level(IndexEntry **entries, int count,
                             const char *prefix, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        // Get path relative to current prefix
        const char *rel = entries[i]->path + strlen(prefix);

        // Check if this entry is in a subdirectory
        const char *slash = strchr(rel, '/');

        if (slash == NULL) {
            // It's a direct file entry at this level
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entries[i]->mode;
            te->hash = entries[i]->hash;
            strncpy(te->name, rel, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            i++;
        } else {
            // It's inside a subdirectory — collect all entries with same subdir
            size_t dir_name_len = (size_t)(slash - rel);
            char dir_name[256];
            strncpy(dir_name, rel, dir_name_len);
            dir_name[dir_name_len] = '\0';

            // Build new prefix for the subdirectory
            char new_prefix[512];
            snprintf(new_prefix, sizeof(new_prefix), "%s%s/", prefix, dir_name);

            // Find all entries belonging to this subdir
            int j = i;
            while (j < count) {
                const char *r = entries[j]->path + strlen(prefix);
                const char *s = strchr(r, '/');
                if (s == NULL) break;
                size_t dl = (size_t)(s - r);
                if (dl != dir_name_len || strncmp(r, dir_name, dl) != 0) break;
                j++;
            }

            // Recursively build subtree for this subdir
            ObjectID subtree_id;
            if (write_tree_level(entries + i, j - i, new_prefix, &subtree_id) != 0)
                return -1;

            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = MODE_DIR;
            te->hash = subtree_id;
            strncpy(te->name, dir_name, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';

            i = j;
        }
    }

    // Serialize and write this tree level
    void *data;
    size_t len;
    if (tree_serialize(&tree, &data, &len) != 0) return -1;
    int rc = object_write(OBJ_TREE, data, len, id_out);
    free(data);
    return rc;
}

// Comparator for sorting IndexEntry pointers by path
static int compare_entry_ptrs(const void *a, const void *b) {
    const IndexEntry *ea = *(const IndexEntry **)a;
    const IndexEntry *eb = *(const IndexEntry **)b;
    return strcmp(ea->path, eb->path);
}

int tree_from_index(ObjectID *id_out) {
    Index index;
    index.count = 0;

    if (index_load(&index) != 0) return -1;

    if (index.count == 0) {
        // Empty tree
        Tree empty;
        empty.count = 0;
        void *data;
        size_t len;
        if (tree_serialize(&empty, &data, &len) != 0) return -1;
        int rc = object_write(OBJ_TREE, data, len, id_out);
        free(data);
        return rc;
    }

    // Build array of pointers for sorting
    IndexEntry **ptrs = malloc((size_t)index.count * sizeof(IndexEntry *));
    if (!ptrs) return -1;
    for (int i = 0; i < index.count; i++)
        ptrs[i] = &index.entries[i];

    qsort(ptrs, (size_t)index.count, sizeof(IndexEntry *), compare_entry_ptrs);

    int rc = write_tree_level(ptrs, index.count, "", id_out);
    free(ptrs);
    return rc;
}


