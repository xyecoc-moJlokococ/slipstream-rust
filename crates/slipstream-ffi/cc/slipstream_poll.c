#include "picoquic_internal.h"

void slipstream_request_poll(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return;
    }
    cnx->is_poll_requested = 1;
}

int slipstream_is_flow_blocked(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return 0;
    }
    return (cnx->flow_blocked || cnx->stream_blocked) ? 1 : 0;
}

int slipstream_has_ready_stream(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return 0;
    }
    return picoquic_find_ready_stream(cnx) != NULL ? 1 : 0;
}

void slipstream_get_flow_debug(
    picoquic_cnx_t *cnx,
    uint64_t *maxdata_remote,
    uint64_t *data_sent,
    uint64_t *maxdata_local,
    uint64_t *data_consumed
) {
    if (maxdata_remote != NULL) {
        *maxdata_remote = cnx == NULL ? 0 : cnx->maxdata_remote;
    }
    if (data_sent != NULL) {
        *data_sent = cnx == NULL ? 0 : cnx->data_sent;
    }
    if (maxdata_local != NULL) {
        *maxdata_local = cnx == NULL ? 0 : cnx->maxdata_local;
    }
    if (data_consumed != NULL) {
        *data_consumed = cnx == NULL ? 0 : cnx->data_consumed;
    }
}

void slipstream_disable_ack_delay(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return;
    }
    cnx->no_ack_delay = 1;
}

int slipstream_find_path_id_by_addr(picoquic_cnx_t *cnx, const struct sockaddr* addr_peer) {
    if (cnx == NULL || addr_peer == NULL || addr_peer->sa_family == 0) {
        return -1;
    }

    for (int path_id = 0; path_id < cnx->nb_paths; path_id++) {
        picoquic_path_t* path_x = cnx->path[path_id];
        if (path_x == NULL) {
            continue;
        }
        if (path_x->path_is_demoted || path_x->path_abandon_received || path_x->path_abandon_sent) {
            continue;
        }
        if (picoquic_compare_addr((struct sockaddr*) &path_x->peer_addr, addr_peer) != 0) {
            continue;
        }
        return path_id;
    }

    return -1;
}

int slipstream_get_path_id_from_unique(picoquic_cnx_t *cnx, uint64_t unique_path_id) {
    if (cnx == NULL) {
        return -1;
    }
    int path_id = picoquic_get_path_id_from_unique(cnx, unique_path_id);
    if (path_id < 0 || path_id >= cnx->nb_paths) {
        return -1;
    }
    picoquic_path_t* path_x = cnx->path[path_id];
    if (path_x == NULL) {
        return -1;
    }
    if (path_x->path_is_demoted || path_x->path_abandon_received || path_x->path_abandon_sent) {
        return -1;
    }
    return path_id;
}

uint64_t slipstream_get_max_streams_bidir_remote(picoquic_cnx_t *cnx) {
    if (cnx == NULL || cnx->remote_parameters_received == 0) {
        return 0;
    }
    /* STREAM_RANK_FROM_ID is 1-based and returns stream count, not a zero-based index. */
    return STREAM_RANK_FROM_ID(cnx->max_stream_id_bidir_remote);
}

/* picoquic's stock per-stream default (initial_max_stream_data_bidi_remote = 65635, ~64KB)
 * governs how much a PEER-opened stream may send before it needs a MAX_STREAM_DATA update
 * from us -- independent of the much larger connection-level window set via
 * picoquic_set_max_data_control. On this DNS-poll carrier, a MAX_STREAM_DATA update can only
 * go out in response to a client poll, so once several streams are opened at once (e.g. an
 * app uploading a file over many parallel connections), each one stalls at ~64KB waiting for
 * its own poll-driven window update, even though the connection has plenty of budget left.
 * This raises the *default* for all three per-stream directions so newly created streams
 * start with real headroom, without touching already-negotiated streams. Mirrors
 * picoquic_set_max_data_control's pattern of writing default_tp directly rather than going
 * through picoquic_set_default_tp (which memcpy's the whole picoquic_tp_t and would need this
 * shim to replicate the entire struct's layout just to touch three fields). */
void slipstream_set_default_stream_data_control(picoquic_quic_t *quic, uint64_t max_stream_data) {
    if (quic == NULL) {
        return;
    }
    quic->default_tp.initial_max_stream_data_bidi_local = max_stream_data;
    quic->default_tp.initial_max_stream_data_bidi_remote = max_stream_data;
    quic->default_tp.initial_max_stream_data_uni = max_stream_data;
}
