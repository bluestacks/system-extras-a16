#define LOG_TAG "su"

#include "su_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <android/log.h>
#include <sys/stat.h>
#include <limits.h>
#include <cutils/properties.h>

// Debug log control
static bool g_debug_log_enabled = false;

void init_debug_log(void) {
    char prop_value[PROPERTY_VALUE_MAX];
    property_get("bst.debug.su", prop_value, "0");
    g_debug_log_enabled = (strcmp(prop_value, "1") == 0);
}

// File operation utility function
bool read_file_all(const char* path, unsigned char** out, size_t* outlen) {
    *out = NULL; *outlen = 0;
    FILE* fp = fopen(path, "rb");
    if (!fp) return false;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return false; }
    long n = ftell(fp);
    if (n < 0) { fclose(fp); return false; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return false; }
    size_t sz = (size_t)n;
    unsigned char* p = (unsigned char*)malloc(sz + 1); // +1 for NUL
    if (!p) { fclose(fp); return false; }
    size_t r = fread(p, 1, sz, fp);
    fclose(fp);
    if (r != sz) { free(p); return false; }
    p[sz] = 0;
    *out = p; *outlen = sz;
    return true;
}

// String processing utility function
void trim(char* s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len && (s[len-1]=='\n' || s[len-1]=='\r' || isspace((unsigned char)s[len-1]))) {
        s[--len] = 0;
    }
    char* p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p)+1);
}

bool starts_with(const char* s, const char* prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

void to_lower_inplace(char* s) {
    for (; *s; ++s) *s = (char)tolower((unsigned char)*s);
}

// Hexadecimal and Base64 encoding/decoding
int hexval(int c) {
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}

size_t hex2bin(const char* hex, uint8_t* out, size_t outcap) {
    size_t n=0; int hi,lo;
    while(*hex){
        while(*hex==':'||isspace((unsigned char)*hex)) hex++;
        if(!*hex) break;
        hi=hexval(*hex++); if(hi<0) break;
        while(*hex==':'||isspace((unsigned char)*hex)) hex++;
        if(!*hex) break;
        lo=hexval(*hex++); if(lo<0) break;
        if(n>=outcap) return n;
        out[n++]=(uint8_t)((hi<<4)|lo);
    }
    return n;
}

void normalize_hex(char* s) { // Remove colons and convert to uppercase
    char* w=s; for(char* p=s; *p; ++p){ if(*p!=':'){ *w++=(char)toupper((unsigned char)*p);} } *w='\0';
}

size_t base64_decode(const char* encoded, unsigned char* decoded, size_t max_decoded_len) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char* d = decoded;
    size_t len = strlen(encoded);
    size_t i = 0;
    
    while (i < len && *encoded && max_decoded_len > 0) {
        // Skip padding character '='
        if (*encoded == '=') break;
        
        // Find the index of the first character
        const char* p = strchr(b64, *encoded++);
        if (!p) continue; // Skip invalid characters
        unsigned char a = (unsigned char)(p - b64);
        
        // Find the index of the second character
        if (i+1 >= len || *encoded == '=') break;
        p = strchr(b64, *encoded++);
        if (!p) continue;
        unsigned char b = (unsigned char)(p - b64);
        
        // Decode the first byte
        if (max_decoded_len > 0) {
            *d++ = (a << 2) | (b >> 4);
            max_decoded_len--;
        }
        
        // Find the index of the third character
        if (i+2 >= len || *encoded == '=') break;
        p = strchr(b64, *encoded++);
        if (!p) continue;
        unsigned char c = (unsigned char)(p - b64);
        
        // Decode the second byte
        if (max_decoded_len > 0) {
            *d++ = (b << 4) | (c >> 2);
            max_decoded_len--;
        }
        
        // Find the index of the fourth character
        if (i+3 >= len || *encoded == '=') break;
        p = strchr(b64, *encoded++);
        if (!p) continue;
        unsigned char e = (unsigned char)(p - b64);
        
        // Decode the third byte
        if (max_decoded_len > 0) {
            *d++ = (c << 6) | e;
            max_decoded_len--;
        }
        
        i += 4;
    }
    
    return d - decoded;
}

// XML attribute extraction
int extract_attr(const char* s, const char* key, char* out, size_t outlen) {
    const char* p=strstr(s,key); if(!p) return -1;
    p=strchr(p,'"'); if(!p) return -1; p++;
    const char* q=strchr(p,'"'); if(!q) return -1;
    size_t n=(size_t)(q-p); if(n>=outlen) n=outlen-1;
    memcpy(out,p,n); out[n]='\0'; return 0;
}

// Get caller process path
bool get_caller_path(char* buffer, size_t buf_size) {
    char proc_path[64];
    pid_t pid = getppid();  // Get the parent process ID, which is the process that called su
    
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    ssize_t len = readlink(proc_path, buffer, buf_size - 1);
    
    if (len < 0) {
        log_error("readlink failed for %s: %s", proc_path, strerror(errno));
        return false;
    }
    
    buffer[len] = '\0';
    return true;
}

// Log utility
void log_debug(const char* fmt, ...) {
    if (!g_debug_log_enabled) {
        return;
    }
    
    va_list ap;
    va_start(ap, fmt);
    __android_log_vprint(ANDROID_LOG_DEBUG, "su", fmt, ap);
    va_end(ap);
}

void log_error(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    __android_log_vprint(ANDROID_LOG_ERROR, "su", fmt, ap);
    va_end(ap);
}

void warnx(const char* fmt, ...) {
    // Check if debug logging is enabled
    if (!g_debug_log_enabled) {
        return;
    }
    
    va_list ap, ap_copy;
    va_start(ap, fmt);
    va_copy(ap_copy, ap);
    
    // Original standard error output
    fprintf(stderr, "su: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    
    // Android log output
    __android_log_vprint(ANDROID_LOG_WARN, "su", fmt, ap_copy);
    
    va_end(ap_copy);
    va_end(ap);
}

void die(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "su: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}