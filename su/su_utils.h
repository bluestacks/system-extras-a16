#ifndef SU_UTILS_H
#define SU_UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
// File operation utility functions
bool read_file_all(const char* path, unsigned char** out, size_t* outlen);

// String processing utility functions
void trim(char* s);
bool starts_with(const char* s, const char* prefix);
void to_lower_inplace(char* s);

// Hexadecimal and Base64 encoding/decoding
int hexval(int c);
size_t hex2bin(const char* hex, uint8_t* out, size_t outcap);
void normalize_hex(char* s);
size_t base64_decode(const char* encoded, unsigned char* decoded, size_t max_decoded_len);

// XML attribute extraction
int extract_attr(const char* s, const char* key, char* out, size_t outlen);

// Process path retrieval
bool get_caller_path(char* buffer, size_t buf_size);

// Logging utilities
void init_debug_log(void);
void log_debug(const char* fmt, ...);
void log_error(const char* fmt, ...);
void warnx(const char* fmt, ...);
void die(const char* fmt, ...) __attribute__((noreturn));
#ifdef __cplusplus
}
#endif

#endif // SU_UTILS_H