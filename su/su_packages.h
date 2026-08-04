#ifndef SU_PACKAGES_H
#define SU_PACKAGES_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Package management related functions
size_t get_packages_for_uid(int uid, char pkgs[][256], size_t max_pkgs);

int get_pkg_sha256_from_packages_xml_indexed(const char* pkg, char out_hex[65]);

#ifdef __cplusplus
}
#endif

#endif // SU_PACKAGES_H