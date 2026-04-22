/*
 * Curated C declarations read by cffi at build time.
 *
 * Mirrors the public API exported by upstream libcoraza's cgo-generated
 * `coraza/coraza.h`. Only the subset pycoraza binds is declared here.
 *
 * When bumping LIBCORAZA_TAG in native/version.txt, diff the installed
 * coraza.h against this file. cffi's verifier catches signature
 * mismatches at build time.
 *
 * Note on handle types: upstream declares them as `uintptr_t`. cffi's
 * stdint support provides uintptr_t, so we use it verbatim.
 */

typedef unsigned long uintptr_t;
typedef unsigned long size_t;

typedef uintptr_t coraza_waf_config_t;
typedef uintptr_t coraza_waf_t;
typedef uintptr_t coraza_transaction_t;
typedef uintptr_t coraza_matched_rule_t;

typedef struct coraza_intervention_t {
    char *action;
    int status;
    int pause;
    int disruptive;
    char *data;
} coraza_intervention_t;

typedef enum coraza_debug_log_level_t {
    CORAZA_DEBUG_LOG_LEVEL_UNKNOWN,
    CORAZA_DEBUG_LOG_LEVEL_TRACE,
    CORAZA_DEBUG_LOG_LEVEL_DEBUG,
    CORAZA_DEBUG_LOG_LEVEL_INFO,
    CORAZA_DEBUG_LOG_LEVEL_WARN,
    CORAZA_DEBUG_LOG_LEVEL_ERROR
} coraza_debug_log_level_t;

typedef enum coraza_severity_t {
    CORAZA_SEVERITY_UNKNOWN,
    CORAZA_SEVERITY_DEBUG,
    CORAZA_SEVERITY_INFO,
    CORAZA_SEVERITY_NOTICE,
    CORAZA_SEVERITY_WARNING,
    CORAZA_SEVERITY_ERROR,
    CORAZA_SEVERITY_CRITICAL,
    CORAZA_SEVERITY_ALERT,
    CORAZA_SEVERITY_EMERGENCY
} coraza_severity_t;

typedef void (*coraza_debug_log_cb)(void *ctx, coraza_debug_log_level_t level,
                                    const char *msg, const char *fields);
typedef void (*coraza_error_cb)(void *ctx, coraza_matched_rule_t rule);

coraza_waf_config_t coraza_new_waf_config(void);
int coraza_rules_add(coraza_waf_config_t c, char *directives);
int coraza_rules_add_file(coraza_waf_config_t c, char *file);
int coraza_add_debug_log_callback(coraza_waf_config_t c, coraza_debug_log_cb cb, void *userContext);
int coraza_add_error_callback(coraza_waf_config_t c, coraza_error_cb cb, void *userContext);
int coraza_free_waf_config(coraza_waf_config_t config);

coraza_waf_t coraza_new_waf(coraza_waf_config_t config, char **er);
int coraza_rules_count(coraza_waf_t w);
int coraza_rules_merge(coraza_waf_t w1, coraza_waf_t w2, char **er);
int coraza_free_waf(coraza_waf_t t);

coraza_transaction_t coraza_new_transaction(coraza_waf_t w);
coraza_transaction_t coraza_new_transaction_with_id(coraza_waf_t w, char *id);
int coraza_free_transaction(coraza_transaction_t t);

int coraza_process_connection(coraza_transaction_t t, char *sourceAddress,
                              int clientPort, char *serverHost, int serverPort);
int coraza_process_uri(coraza_transaction_t t, char *uri, char *method, char *proto);
int coraza_add_request_header(coraza_transaction_t t, char *name, int name_len,
                              char *value, int value_len);
int coraza_process_request_headers(coraza_transaction_t t);
int coraza_append_request_body(coraza_transaction_t t, unsigned char *data, int length);
int coraza_request_body_from_file(coraza_transaction_t t, char *file);
int coraza_process_request_body(coraza_transaction_t t);
int coraza_add_get_args(coraza_transaction_t t, char *name, char *value);

int coraza_update_status_code(coraza_transaction_t t, int code);
int coraza_add_response_header(coraza_transaction_t t, char *name, int name_len,
                               char *value, int value_len);
int coraza_process_response_headers(coraza_transaction_t t, int status, char *proto);
int coraza_append_response_body(coraza_transaction_t t, unsigned char *data, int length);
int coraza_process_response_body(coraza_transaction_t t);
int coraza_is_response_body_processable(coraza_transaction_t t);

coraza_intervention_t *coraza_intervention(coraza_transaction_t t);
int coraza_free_intervention(coraza_intervention_t *it);
int coraza_process_logging(coraza_transaction_t t);

coraza_severity_t coraza_matched_rule_get_severity(coraza_matched_rule_t r);
char *coraza_matched_rule_get_error_log(coraza_matched_rule_t r);
