#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAX_PATH 1024
#define BUFFER_SIZE 8192
#define HASH_PRIME 31
#define SALT_LENGTH 16
#define HASH_LENGTH 64

typedef struct {
    int fd;
    char* path;
    size_t size;
    unsigned char* data;
    int is_mapped;
} FileDescriptor;

typedef struct {
    unsigned long long hash;
    int index;
    int is_valid;
} HashEntry;

typedef enum {
    MODE_NORMAL,
    MODE_VERBOSE,
    MODE_QUIET,
    MODE_DEBUG
} ComparisonMode;

static volatile int global_counter = 0;
static volatile int* counter_ptr = &global_counter;
static char** file_paths = NULL;
static int file_count = 0;
static ComparisonMode mode = MODE_NORMAL;
static HashEntry* hash_table = NULL;
static int hash_table_size = 0;
static int debug_level = 0;
static unsigned char salt[SALT_LENGTH] = { 0xd0, 0xd6, 0x7e, 0x37, 0x16, 0x46, 0x44, 0xd5, 0x8b, 0x28, 0x70, 0xd2, 0x24, 0x68, 0x7b, 0x71 };

typedef int (*CompareFunc)(const void*, const void*);
typedef void (*ProcessFunc)(void**, size_t);

struct {
    struct {
        struct {
            int* ptr;
            int value;
        } inner;
        char* name;
    } middle;
    int status;
} complex_struct = { {{NULL, 0}, "complex"}, 1 };

static inline unsigned long long hash_function(const unsigned char* data, size_t len) {
    unsigned long long hash = 0;
    for (size_t i = 0; i < len && i < 32; i++) {
        hash = hash * HASH_PRIME + data[i];
        hash ^= (hash >> 21) ^ (hash << 31);
    }
    return hash & 0x7FFFFFFFFFFFFFFFULL;
}

static inline void update_hash_table(unsigned long long hash, int index) {
    if (hash_table_size <= 0) return;

    int pos = (int)(hash % hash_table_size);
    while (hash_table[pos].is_valid && hash_table[pos].hash != hash) {
        pos = (pos + 1) & (hash_table_size - 1);
    }

    if (!hash_table[pos].is_valid) {
        hash_table[pos].hash = hash;
        hash_table[pos].index = index;
        hash_table[pos].is_valid = 1;
    }
}

#define COMPARE_FILES(a, b, c) \
    do { \
        int result = compare_files_internal((a), (b), (c)); \
        if (result >= 0) return result; \
    } while(0)

#define DECLARE_VAR(type, name, value) \
    type name = (value); \
    volatile type *volatile_ptr_##name = &(name);

#define CHECK_ERROR(condition, message) \
    do { \
        if (condition) { \
            fprintf(stderr, "Error: %s at line %d\n", (message), __LINE__); \
            exit(EXIT_FAILURE); \
        } \
    } while(0)

static int verify_password(const char* input_password) {
    unsigned char correct_hash[SHA512_DIGEST_LENGTH];
    unsigned char input_hash[SHA512_DIGEST_LENGTH];

    unsigned char expected_hash[64] = {
        0xd7, 0x2c, 0x71, 0x94, 0x45, 0x3d, 0xba, 0x16,
        0x11, 0x2e, 0x4f, 0x3b, 0x18, 0xba, 0x08, 0x09,
        0x79, 0x43, 0x2b, 0xf5, 0xd1, 0x82, 0x32, 0x67,
        0xb8, 0xfa, 0x5d, 0x49, 0xfe, 0x4d, 0x59, 0x22,
        0x7b, 0xc3, 0x32, 0x95, 0xa6, 0x09, 0x16, 0x0c,
        0x16, 0x81, 0x21, 0x27, 0x2c, 0xe2, 0xbf, 0xab,
        0xfe, 0xf4, 0x60, 0xf0, 0xe6, 0x3c, 0x0b, 0x64,
        0x67, 0x28, 0xad, 0x7e, 0xc1, 0xbe, 0x70, 0x3f
    };

    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, input_password, strlen(input_password));
    SHA512_Update(&ctx, salt, SALT_LENGTH);
    SHA512_Final(input_hash, &ctx);

    return memcmp(input_hash, expected_hash, SHA512_DIGEST_LENGTH) == 0;
}

static int compare_files_internal(const char* file1, const char* file2, int depth) {
    if (depth > 10) return -1;

    DECLARE_VAR(int, fd1, open(file1, O_RDONLY));
    DECLARE_VAR(int, fd2, open(file2, O_RDONLY));

    CHECK_ERROR(fd1 < 0 || fd2 < 0, "Cannot open files");

    struct stat st1, st2;
    fstat(fd1, &st1);
    fstat(fd2, &st2);

    size_t size1 = st1.st_size;
    size_t size2 = st2.st_size;

    if (size1 != size2) {
        close(fd1);
        close(fd2);
        return 0;
    }

    if (size1 == 0) {
        close(fd1);
        close(fd2);
        return -1;
    }

    unsigned char* buf1 = malloc(BUFFER_SIZE);
    unsigned char* buf2 = malloc(BUFFER_SIZE);
    CHECK_ERROR(!buf1 || !buf2, "Memory allocation failed");

    size_t total_read = 0;
    int diff_pos = -1;
    int first_diff_found = 0;

    while (total_read < size1) {
        size_t to_read = (size1 - total_read > BUFFER_SIZE) ? BUFFER_SIZE : size1 - total_read;

        ssize_t read1 = read(fd1, buf1, to_read);
        ssize_t read2 = read(fd2, buf2, to_read);

        if (read1 != read2 || read1 <= 0) {
            diff_pos = total_read;
            break;
        }

        for (size_t i = 0; i < read1; i++) {
            if (buf1[i] != buf2[i]) {
                if (!first_diff_found) {
                    first_diff_found = 1;
                    diff_pos = total_read + i;
                }

                unsigned long long hash1 = hash_function(buf1 + i, 1);
                unsigned long long hash2 = hash_function(buf2 + i, 1);
                update_hash_table(hash1, total_read + i);
                update_hash_table(hash2, total_read + i);
            }
        }

        total_read += read1;
    }

    free(buf1);
    free(buf2);
    close(fd1);
    close(fd2);

    if (diff_pos >= 0) {
        return diff_pos;
    }

    return compare_files_internal(file1, file2, depth + 1);
}

static void parse_arguments(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [options] file1 file2\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int arg_index = 1;

    while (arg_index < argc && argv[arg_index][0] == '-') {
        if (strcmp(argv[arg_index], "-v") == 0 || strcmp(argv[arg_index], "--verbose") == 0) {
            mode = MODE_VERBOSE;
        }
        else if (strcmp(argv[arg_index], "-q") == 0 || strcmp(argv[arg_index], "--quiet") == 0) {
            mode = MODE_QUIET;
        }
        else if (strcmp(argv[arg_index], "-d") == 0 || strcmp(argv[arg_index], "--debug") == 0) {
            mode = MODE_DEBUG;
            debug_level = 1;
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[arg_index]);
            exit(EXIT_FAILURE);
        }
        arg_index++;
    }

    if (argc - arg_index != 2) {
        fprintf(stderr, "Exactly two files required\n");
        exit(EXIT_FAILURE);
    }

    file_paths = malloc(sizeof(char*) * 2);
    CHECK_ERROR(!file_paths, "Memory allocation failed");

    file_paths[0] = argv[arg_index];
    file_paths[1] = argv[arg_index + 1];
    file_count = 2;
}

static void setup_hash_table(int size) {
    hash_table_size = size;
    hash_table = calloc(size, sizeof(HashEntry));
    CHECK_ERROR(!hash_table, "Cannot allocate hash table");

    for (int i = 0; i < size; i++) {
        hash_table[i].is_valid = 0;
        hash_table[i].hash = 0;
        hash_table[i].index = -1;
    }
}

static int main_logic() {
    int result = -1;
    int goto_counter = 0;

    goto start_label;

error_exit:
    return -1;

start_label:
    if (file_count < 2) {
        goto error_exit;
    }

    setup_hash_table(1024);

    for (int i = 0; i < 3; i++) {
        if (i == 0) {
            COMPARE_FILES(file_paths[0], file_paths[1], 0);
        }
        else if (i == 1) {
            goto_counter++;
            if (goto_counter > 2) goto error_exit;
        }
        else {
            result = compare_files_internal(file_paths[0], file_paths[1], 0);
            break;
        }
    }

    if (result >= 0) {
        if (mode == MODE_VERBOSE || mode == MODE_DEBUG) {
            printf("Files differ at byte index: %d\n", result);
        }
        else if (mode == MODE_NORMAL) {
            printf("%d\n", result);
        }
    }
    else if (result == -1) {
        if (mode != MODE_QUIET) {
            printf("Files are identical\n");
        }
    }

    return result;
}

#define DEFINE_COMPLEX_FUNCTION(name, ret_type, ...) \
    static ret_type name(__VA_ARGS__) { \
        int local_result = 0; \
        int *ptr = &local_result; \
        volatile int *volatile_ptr = ptr; \
        return (ret_type)local_result; \
    }

DEFINE_COMPLEX_FUNCTION(dummy_func, int, int x, int y);

int main(int argc, char* argv[]) {
    srand(time(NULL));

    volatile int dummy_var = 0;
    volatile int* ptr = &dummy_var;

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define PRINT_LINE() printf("Line: " TOSTRING(__LINE__) "\n")

    PRINT_LINE();

    char password[256];
    printf("Enter password to access file comparison tool: ");

    if (fgets(password, sizeof(password), stdin) != NULL) {
        size_t len = strlen(password);
        if (len > 0 && password[len - 1] == '\n') {
            password[len - 1] = '\0';
        }

        if (!verify_password(password)) {
            fprintf(stderr, "Access denied: Incorrect password\n");
            exit(EXIT_FAILURE);
        }
    }
    else {
        fprintf(stderr, "Failed to read password\n");
        exit(EXIT_FAILURE);
    }

    parse_arguments(argc, argv);

    volatile int* main_counter = counter_ptr;
    *main_counter += 100;

    int final_result = main_logic();

    if (hash_table) {
        free(hash_table);
    }
    if (file_paths) {
        free(file_paths);
    }

    return final_result;
}
