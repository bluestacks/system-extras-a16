#include "su_packages.h"
#include "su_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>

#define PACKAGES_LIST_PATH   "/data/system/packages.list"
#define PACKAGES_XML_PATH    "/data/system/packages.xml"
// Certificate mapping table structure
typedef struct {
    int index;            // cert index
    char digest[129];     // HEX that can be directly used for comparison (uppercase, no colons), length 64
    char key[4097];       // Original key (HEX or BASE64), can be empty
    int key_is_hex;       // 1=HEX, 0=BASE64(or unknown)
} CertEntry;

typedef struct {
    CertEntry *a; size_t n, cap;
} CertMap;

static void cmap_init(CertMap *m) { m->a=NULL; m->n=0; m->cap=0; }
static void cmap_free(CertMap *m) { free(m->a); m->a=NULL; m->n=m->cap=0; }

static CertEntry* cmap_get(CertMap *m, int index) {
    for(size_t i=0;i<m->n;i++) if(m->a[i].index==index) return &m->a[i];
    if(m->n==m->cap){ m->cap=m->cap?m->cap*2:16; m->a=(CertEntry*)realloc(m->a, m->cap*sizeof(CertEntry)); }
    CertEntry *e=&m->a[m->n++]; memset(e,0,sizeof(*e)); e->index=index; return e;
}

/* Try to convert key -> digest (SHA-256), prefer HEX, otherwise try BASE64 */
static int digest_from_key(const char *key, int key_is_hex, char out_hex[65]){
    uint8_t buf[8192]; size_t blen=0;
    if(key_is_hex){
        blen=hex2bin(key, buf, sizeof(buf));
        if(blen==0) return -1;
    }else{
        blen=base64_decode(key, buf, sizeof(buf));
        if(blen==0) return -1;
    }
    uint8_t d[32];
    SHA256(buf, blen, d);
    static const char *hexmap="0123456789ABCDEF";
    for(int i=0;i<32;i++){ out_hex[i*2]=hexmap[(d[i]>>4)&0xF]; out_hex[i*2+1]=hexmap[d[i]&0xF]; }
    out_hex[64]='\0';
    return 0;
}

/* First pass: Collect globally/arbitrarily appearing cert index -> digest/key */
static int build_cert_map_from_file(const char* xml_path, CertMap* map) {
    FILE *f=fopen(xml_path,"re"); if(!f) return -1;
    char line[16384];
    while(fgets(line,sizeof(line),f)){
        if(!strstr(line,"<cert")) continue;
        int idx=-1; char idxs[32];
        if(extract_attr(line,"index=", idxs, sizeof(idxs))==0) idx=atoi(idxs);
        if(idx<0) continue;
        CertEntry *e=cmap_get(map, idx);

        // First, check if digest is directly provided
        char tmp[4096];
        if(e->digest[0]==0 &&
           (extract_attr(line,"certDigest=",tmp,sizeof(tmp))==0 ||
            extract_attr(line,"digest=",tmp,sizeof(tmp))==0 ||
            extract_attr(line,"sha256=",tmp,sizeof(tmp))==0)){
            strncpy(e->digest,tmp,sizeof(e->digest)-1);
            e->digest[sizeof(e->digest)-1]='\0';
            normalize_hex(e->digest);
        }

        // Then, check if there is a key
        if(e->key[0]==0 && extract_attr(line,"key=",tmp,sizeof(tmp))==0){
            strncpy(e->key,tmp,sizeof(e->key)-1); e->key[sizeof(e->key)-1]='\0';
            // Determine if it's HEX: Consider it HEX if all characters are [0-9a-fA-F:]
            int hexlike=1;
            for(char *p=e->key; *p; ++p){
                if(!isxdigit((unsigned char)*p) && *p!=':' && !isspace((unsigned char)*p)){ hexlike=0; break; }
            }
            e->key_is_hex=hexlike?1:0;

            // If there is no digest yet, try to calculate it from the key
            if(e->digest[0]==0){
                char dhex[65];
                if(digest_from_key(e->key, e->key_is_hex, dhex)==0){
                    strncpy(e->digest,dhex,sizeof(e->digest)); e->digest[64]='\0';
                }
            }
        }
    }
    fclose(f);
    return 0;
}

// Get the list of packages for the specified UID
size_t get_packages_for_uid(int uid, char pkgs[][256], size_t max_pkgs) {
    // Method 1: Try to open the packages.list file (old method)
    FILE* fp = fopen(PACKAGES_LIST_PATH, "r");
    if (fp) {
        warnx("DEBUG: get_packages_for_uid - successfully opened packages list file");
        char line[1024];
        size_t count = 0;
        while (fgets(line, sizeof(line), fp)) {
            char pkg[256] = {0};
            int file_uid = -1;
            // Format: Package name UID GID Data directory Flags Version
            if (sscanf(line, "%255s %d", pkg, &file_uid) >= 1) {
                // warnx("DEBUG: get_packages_for_uid - parsed pkg: %s, uid: %d", pkg, file_uid);
                if (file_uid == uid) {
                    strncpy(pkgs[count], pkg, 255);
                    pkgs[count][255] = 0;
                    warnx("DEBUG: get_packages_for_uid - found match: %s for uid: %d", pkg, uid);
                    if (++count >= max_pkgs) break;
                }
            }
        }
        fclose(fp);
        warnx("DEBUG: get_packages_for_uid - total matches found via file: %zu for uid: %d", count, uid);
        return count;
    }

    warnx("DEBUG: get_packages_for_uid - failed to open packages list file: %s. Error: %s",
          PACKAGES_LIST_PATH, strerror(errno));

    // Method 2: If direct file access is not possible, try using the pm command to get package information
    char command[256];
    snprintf(command, sizeof(command), "pm list packages --uid %d", uid);
    warnx("DEBUG: get_packages_for_uid - trying to run command: %s", command);

    FILE* pipe = popen(command, "r");
    if (pipe) {
        warnx("DEBUG: get_packages_for_uid - successfully executed pm command");
        char line[1024];
        size_t count = 0;
        while (fgets(line, sizeof(line), pipe)) {
            char pkg[256] = {0};
            // pm command output format: "package:com.example.package"
            if (sscanf(line, "package:%255s", pkg) == 1) {
                warnx("DEBUG: get_packages_for_uid - parsed pkg from pm: %s", pkg);
                strncpy(pkgs[count], pkg, 255);
                pkgs[count][255] = 0;
                warnx("DEBUG: get_packages_for_uid - found match via pm: %s for uid: %d", pkg, uid);
                if (++count >= max_pkgs) break;
            }
        }
        pclose(pipe);
        warnx("DEBUG: get_packages_for_uid - total matches found via pm: %zu for uid: %d", count, uid);
        return count;
    }

    warnx("DEBUG: get_packages_for_uid - failed to execute pm command. Error: %s", strerror(errno));

    // Method 3: Try to read the /data/system/packages.xml file (as an alternative)
    FILE* xml_fp = fopen(PACKAGES_XML_PATH, "r");
    if (xml_fp) {
        warnx("DEBUG: get_packages_for_uid - successfully opened packages.xml file");
        char line[2048];
        size_t count = 0;
        char pkg[256] = {0};
        int file_uid = -1;
        bool in_package = false;

        while (fgets(line, sizeof(line), xml_fp)) {
            if (strstr(line, "<package name=") && strstr(line, "name=\"")) {
                char name[512];
                if (extract_attr(line, "name=", name, sizeof(name)) == 0 && strcmp(name, pkg) == 0) {
                    in_package = true;
                }
            } else if (in_package && strstr(line, "userId=\"")) {
                char* uid_start = strstr(line, "userId=\"");
                if (uid_start) {
                    uid_start += 8; // Skip "userId="
                    file_uid = atoi(uid_start);
                    warnx("DEBUG: get_packages_for_uid - parsed from xml pkg: %s, uid: %d", pkg, file_uid);

                    if (file_uid == uid) {
                        strncpy(pkgs[count], pkg, 255);
                        pkgs[count][255] = 0;
                        warnx("DEBUG: get_packages_for_uid - found match via xml: %s for uid: %d", pkg, uid);
                        if (++count >= max_pkgs) break;
                    }
                    in_package = false;
                }
            }
        }
        fclose(xml_fp);
        warnx("DEBUG: get_packages_for_uid - total matches found via xml: %zu for uid: %d", count, uid);
        return count;
    }

    warnx("DEBUG: get_packages_for_uid - failed to open packages.xml file: %s. Error: %s",
          PACKAGES_XML_PATH, strerror(errno));

    // If all methods fail, return 0
    warnx("DEBUG: get_packages_for_uid - all methods failed to find packages for uid: %d", uid);
    return 0;
}

// Get the SHA256 signature of a package from packages.xml
int get_pkg_sha256_from_packages_xml_indexed(const char* pkg, char out_hex[65]) {
    const char* path="/data/system/packages.xml";
    CertMap cmap; cmap_init(&cmap);
    if(build_cert_map_from_file(path, &cmap)!=0){ cmap_free(&cmap); return -1; }

    FILE *f=fopen(path,"re"); if(!f){ cmap_free(&cmap); return -1; }
    char line[16384]; int in_pkg=0;

    while(fgets(line,sizeof(line),f)){
        if(!in_pkg){
            if(strstr(line,"<package ") && strstr(line,"name=\"")){
                char name[512];
                if(extract_attr(line,"name=",name,sizeof(name))==0 && strcmp(name,pkg)==0){
                    in_pkg=1;
                    // Some ROMs put certDigest directly on the same line
                    char d[256];
                    if(extract_attr(line,"certDigest=",d,sizeof(d))==0 ||
                       extract_attr(line,"digest=",d,sizeof(d))==0 ||
                       extract_attr(line,"sha256=",d,sizeof(d))==0){
                        strncpy(out_hex,d,65); out_hex[64]='\0'; normalize_hex(out_hex);
                        fclose(f); cmap_free(&cmap);
                        return (strlen(out_hex)==64)?0:-1;
                    }
                }
            }
            continue;
        }

        // Look for cert within the target package section
        if(strstr(line,"<cert")){
            char d[256];
            if(extract_attr(line,"certDigest=",d,sizeof(d))==0 ||
               extract_attr(line,"digest=",d,sizeof(d))==0 ||
               extract_attr(line,"sha256=",d,sizeof(d))==0){
                strncpy(out_hex,d,65); out_hex[64]='\0'; normalize_hex(out_hex);
                fclose(f); cmap_free(&cmap);
                to_lower_inplace(out_hex);
                return (strlen(out_hex)==64)?0:-1;
            }

            char idxs[32];
            if(extract_attr(line,"index=",idxs,sizeof(idxs))==0){
                int idx=atoi(idxs);
                CertEntry *e=cmap_get(&cmap, idx);
                if(e && e->digest[0]){
                    strncpy(out_hex, e->digest, 65); out_hex[64]='\0';
                    fclose(f); cmap_free(&cmap);
                    to_lower_inplace(out_hex);
                    return (strlen(out_hex)==64)?0:-1;
                }
                // As a fallback: If there is only a key, calculate it now
                if(e && e->key[0]){
                    char dhex[65];
                    if(digest_from_key(e->key, e->key_is_hex, dhex)==0){
                        strncpy(out_hex,dhex,65); out_hex[64]='\0';
                        fclose(f); cmap_free(&cmap);
                        to_lower_inplace(out_hex);
                        return 0;
                    }
                }
            }
        }

        if(strstr(line,"</package>")) break; // End of the target package block
    }

    fclose(f); cmap_free(&cmap);
    return -1;
}
