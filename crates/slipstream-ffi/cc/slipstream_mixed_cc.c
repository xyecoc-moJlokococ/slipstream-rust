#include <stdint.h>

#include <picoquic_internal.h>

typedef enum {
    slipstream_path_mode_unknown = 0,
    slipstream_path_mode_recursive = 1,
    slipstream_path_mode_authoritative = 2,
} slipstream_path_mode_t;

static slipstream_path_mode_t slipstream_default_path_mode = slipstream_path_mode_recursive;
static picoquic_congestion_algorithm_t const* slipstream_cc_override = NULL;
extern picoquic_congestion_algorithm_t* slipstream_server_cc_algorithm;

static slipstream_path_mode_t slipstream_normalize_mode(int mode)
{
    if (mode == slipstream_path_mode_authoritative || mode == slipstream_path_mode_recursive) {
        return (slipstream_path_mode_t)mode;
    }
    return slipstream_path_mode_recursive;
}

static slipstream_path_mode_t slipstream_resolve_mode(uint8_t mode)
{
    slipstream_path_mode_t resolved = (slipstream_path_mode_t)mode;
    if (resolved == slipstream_path_mode_unknown) {
        resolved = slipstream_default_path_mode;
    }
    return resolved;
}

static picoquic_congestion_algorithm_t const* slipstream_select_cc(picoquic_path_t* path_x)
{
    if (slipstream_cc_override != NULL) {
        return slipstream_cc_override;
    }
    slipstream_path_mode_t mode = slipstream_resolve_mode(path_x->slipstream_path_mode);
    if (mode == slipstream_path_mode_authoritative) {
        if (slipstream_server_cc_algorithm != NULL) {
            return slipstream_server_cc_algorithm;
        }
        return picoquic_bbr_algorithm;
    }
    return picoquic_dcubic_algorithm;
}

/* Resolve the algorithm for a path that already owns congestion_alg_state: ALWAYS the one pinned
   when that state was allocated. Re-running slipstream_select_cc here is a heap-corruption bug --
   the selection reads mutable state (per-path mode + global override) which really does change
   while a connection is live (apply_path_mode runs again on resolver refresh), so a later callback
   could interpret the state as a different algorithm's struct: dcubic's notify memsets a ~120-byte
   picoquic_cubic_state_t over slipstream_server_cc's 4-byte allocation. Falls back to a fresh
   selection only for paths never initialised through us (pin still NULL). */
static picoquic_congestion_algorithm_t const* slipstream_pinned_cc(picoquic_path_t* path_x)
{
    if (path_x->slipstream_cc_alg != NULL) {
        return path_x->slipstream_cc_alg;
    }
    return slipstream_select_cc(path_x);
}

static void slipstream_mixed_cc_init(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time)
{
    /* The one place a fresh selection is correct: this is the pinning point. */
    picoquic_congestion_algorithm_t const* alg = slipstream_select_cc(path_x);
    /* Pin before delegating: alg_init allocates congestion_alg_state, and every later callback must
       dispatch to this same algorithm. picoquic may re-init a live path (see
       picoquic_set_congestion_algorithm), which re-pins in step with the newly allocated state. */
    path_x->slipstream_cc_alg = alg;
    if (alg != NULL && alg->alg_init != NULL) {
        alg->alg_init(cnx, path_x, current_time);
    }
}

static void slipstream_mixed_cc_notify(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t* ack_state,
    uint64_t current_time)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_pinned_cc(path_x);
    if (alg != NULL && alg->alg_notify != NULL) {
        alg->alg_notify(cnx, path_x, notification, ack_state, current_time);
    }
}

static void slipstream_mixed_cc_delete(picoquic_path_t* path_x)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_pinned_cc(path_x);
    if (alg != NULL && alg->alg_delete != NULL) {
        alg->alg_delete(path_x);
    }
    /* State is gone; unpin so a later init cannot be mistaken for the old allocation. */
    path_x->slipstream_cc_alg = NULL;
}

static void slipstream_mixed_cc_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_pinned_cc(path_x);
    if (alg != NULL && alg->alg_observe != NULL) {
        alg->alg_observe(path_x, cc_state, cc_param);
        return;
    }
    *cc_state = 0;
    *cc_param = 0;
}

#define picoquic_slipstream_mixed_cc_ID "slipstream_mixed"
#define PICOQUIC_CC_ALGO_NUMBER_SLIPSTREAM_MIXED 11

picoquic_congestion_algorithm_t slipstream_mixed_cc_algorithm_struct = {
    picoquic_slipstream_mixed_cc_ID, PICOQUIC_CC_ALGO_NUMBER_SLIPSTREAM_MIXED,
    slipstream_mixed_cc_init,
    slipstream_mixed_cc_notify,
    slipstream_mixed_cc_delete,
    slipstream_mixed_cc_observe
};

picoquic_congestion_algorithm_t* slipstream_mixed_cc_algorithm = &slipstream_mixed_cc_algorithm_struct;

void slipstream_set_cc_override(const char* alg_name)
{
    if (alg_name == NULL) {
        slipstream_cc_override = NULL;
        return;
    }
    picoquic_congestion_algorithm_t const* alg = picoquic_get_congestion_algorithm(alg_name);
    slipstream_cc_override = alg;
}

void slipstream_set_default_path_mode(int mode)
{
    slipstream_default_path_mode = slipstream_normalize_mode(mode);
}

void slipstream_set_path_mode(picoquic_cnx_t* cnx, int path_id, int mode)
{
    if (cnx == NULL || path_id < 0 || path_id >= cnx->nb_paths) {
        return;
    }
    picoquic_path_t* path_x = cnx->path[path_id];
    path_x->slipstream_path_mode = (uint8_t)slipstream_normalize_mode(mode);
}

void slipstream_set_path_ack_delay(picoquic_cnx_t* cnx, int path_id, int disable)
{
    if (cnx == NULL || path_id < 0 || path_id >= cnx->nb_paths) {
        return;
    }
    cnx->path[path_id]->slipstream_no_ack_delay = (disable != 0) ? 1 : 0;
}
