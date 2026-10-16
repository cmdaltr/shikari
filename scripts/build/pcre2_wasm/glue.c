/*
 * The Regex page's PCRE2 interface (static/js/regex_worker.js): one compiled pattern at a
 * time, matched with Splunk's default [rex] limits from limits.conf.
 */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <emscripten.h>
#include <stdio.h>
#include <string.h>
#include "pcre2.h"

#define SPLUNK_MATCH_LIMIT 100000
#define SPLUNK_DEPTH_LIMIT 1000

static pcre2_code *code = NULL;
static pcre2_match_data *match_data = NULL;
static pcre2_match_context *match_context = NULL;
static char error_text[256];
static PCRE2_SIZE error_offset = 0;
static char names[4096];
static char version[32];

/* Compiles pattern; returns its capture count, or -1 (rx_error, rx_error_offset say why) */
EMSCRIPTEN_KEEPALIVE int rx_compile(const char *pattern, uint32_t options) {
    int error_code;
    uint32_t count = 0, name_count = 0, entry_size = 0;
    PCRE2_SPTR table;

    if (match_data) { pcre2_match_data_free(match_data); match_data = NULL; }
    if (code) { pcre2_code_free(code); code = NULL; }
    if (!match_context) {
        match_context = pcre2_match_context_create(NULL);
        pcre2_set_match_limit(match_context, SPLUNK_MATCH_LIMIT);
        pcre2_set_depth_limit(match_context, SPLUNK_DEPTH_LIMIT);
    }
    code = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, options, &error_code, &error_offset, NULL);
    if (!code) {
        pcre2_get_error_message(error_code, (PCRE2_UCHAR *)error_text, sizeof error_text);
        return -1;
    }
    match_data = pcre2_match_data_create_from_pattern(code, NULL);
    pcre2_pattern_info(code, PCRE2_INFO_CAPTURECOUNT, &count);

    /* "name=number" lines for the named groups */
    names[0] = '\0';
    pcre2_pattern_info(code, PCRE2_INFO_NAMECOUNT, &name_count);
    pcre2_pattern_info(code, PCRE2_INFO_NAMEENTRYSIZE, &entry_size);
    pcre2_pattern_info(code, PCRE2_INFO_NAMETABLE, &table);
    for (uint32_t i = 0; i < name_count; i++) {
        PCRE2_SPTR entry = table + i * entry_size;
        size_t used = strlen(names);
        snprintf(names + used, sizeof names - used, "%s=%d\n", (const char *)(entry + 2), (entry[0] << 8) | entry[1]);
    }
    return (int)count;
}

EMSCRIPTEN_KEEPALIVE const char *rx_error(void) { return error_text; }
EMSCRIPTEN_KEEPALIVE int rx_error_offset(void) { return (int)error_offset; }
EMSCRIPTEN_KEEPALIVE const char *rx_names(void) { return names; }

/* pcre2_match's result: the pair count, PCRE2_ERROR_NOMATCH, or a limit or other error */
EMSCRIPTEN_KEEPALIVE int rx_match(const char *subject, int length, int start, uint32_t options) {
    if (!code) return PCRE2_ERROR_NULL;
    return pcre2_match(code, (PCRE2_SPTR)subject, (PCRE2_SIZE)length, (PCRE2_SIZE)start, options, match_data, match_context);
}

/* Offsets as 32-bit pairs: wasm32's size_t; PCRE2_UNSET reads as 0xffffffff */
EMSCRIPTEN_KEEPALIVE PCRE2_SIZE *rx_ovector(void) { return pcre2_get_ovector_pointer(match_data); }

EMSCRIPTEN_KEEPALIVE const char *rx_version(void) {
    pcre2_config(PCRE2_CONFIG_VERSION, version);
    return version;
}
