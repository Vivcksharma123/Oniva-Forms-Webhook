<?php
/**
 * Plugin Name:       Oniva – Forms Webhook
 * Plugin URI:        https://oniva.app
 * Description:       Sends a webhook notification to the Oniva API after every Gravity Forms or Contact Form 7 submission. Provides a REST API to list CF7 forms and their entries.
 * Version:           1.0.0
 * Author:            Oniva
 * Author URI:        https://oniva.app
 * Text Domain:       oniva-gf-webhook
 */

defined( 'ABSPATH' ) || exit;

// ──────────────────────────────────────────────
// Plugin Update Checker (GitHub)
// ──────────────────────────────────────────────
require_once __DIR__ . '/plugin-update-checker/plugin-update-checker.php';

use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

$onivaUpdateChecker = PucFactory::buildUpdateChecker(
    'https://github.com/Vivcksharma123/Oniva-Forms-Webhook.git/',
    __FILE__,
    'oniva-forms-webhook'
);

// Set branch (important)
$onivaUpdateChecker->setBranch('main');

// Enable GitHub releases (recommended)
$onivaUpdateChecker->getVcsApi()->enableReleaseAssets();

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────
define( 'ONIVA_GF_WEBHOOK_VERSION',    '1.0.0' );
define( 'ONIVA_GF_WEBHOOK_DB_VERSION', '1.1' );
define( 'ONIVA_GF_WEBHOOK_URL',        'https://api.oniva.app/api/v1/webhook-gravity/webhook-gravity-forms' );
define( 'ONIVA_CF7_WEBHOOK_URL',       'https://api.oniva.app/api/v1/webhook-gravity/webhook-cf7' );
define( 'ONIVA_GF_WEBHOOK_LOG_KEY',    'oniva_gf_webhook_last_error' );
define( 'ONIVA_CF7_SECRET_KEY_OPTION', 'oniva_cf7_api_secret_key' );
define( 'ONIVA_CF7_TABLE',             'oniva_cf7_entries' );

// ──────────────────────────────────────────────
// 1. Activation – check for supported form plugins + generate secret key
// ──────────────────────────────────────────────
register_activation_hook( __FILE__, 'oniva_plugin_activate' );
function oniva_plugin_activate() {
    if ( ! get_option( ONIVA_CF7_SECRET_KEY_OPTION ) ) {
        update_option( ONIVA_CF7_SECRET_KEY_OPTION, oniva_generate_secret_key() );
    }
    oniva_cf7_create_table();
    if ( ! class_exists( 'GFForms' ) && ! defined( 'WPCF7_VERSION' ) ) {
        set_transient( 'oniva_no_forms_plugin_notice', true, 60 );
    }
}

// ──────────────────────────────────────────────
// 1b. Create / upgrade the CF7 entries table
// ──────────────────────────────────────────────
function oniva_cf7_create_table() {
    global $wpdb;
    $table_name      = $wpdb->prefix . ONIVA_CF7_TABLE;
    $charset_collate = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE {$table_name} (
        id           BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        form_id      VARCHAR(100)        NOT NULL DEFAULT '',
        form_title   VARCHAR(255)        NOT NULL DEFAULT '',
        site_url     VARCHAR(255)        NOT NULL DEFAULT '',
        fields       LONGTEXT                     DEFAULT NULL,
        submitted_at DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY form_id (form_id)
    ) {$charset_collate};";
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta( $sql );
    update_option( 'oniva_cf7_db_version', ONIVA_GF_WEBHOOK_DB_VERSION );
}

add_action( 'plugins_loaded', 'oniva_cf7_maybe_upgrade_table' );
function oniva_cf7_maybe_upgrade_table() {
    if ( get_option( 'oniva_cf7_db_version' ) !== ONIVA_GF_WEBHOOK_DB_VERSION ) {
        oniva_cf7_create_table();
    }
}

// ──────────────────────────────────────────────
// 2. Secret key helpers
// ──────────────────────────────────────────────
function oniva_generate_secret_key() {
    return bin2hex( random_bytes( 20 ) );
}

function oniva_get_secret_key() {
    $key = get_option( ONIVA_CF7_SECRET_KEY_OPTION );
    if ( ! $key ) {
        $key = oniva_generate_secret_key();
        update_option( ONIVA_CF7_SECRET_KEY_OPTION, $key );
    }
    return $key;
}

// ──────────────────────────────────────────────
// 3. Admin notices
// ──────────────────────────────────────────────
add_action( 'admin_notices', 'oniva_admin_notices' );
function oniva_admin_notices() {
    if ( get_transient( 'oniva_no_forms_plugin_notice' ) ) {
        echo '<div class="notice notice-warning is-dismissible"><p>'
            . '<strong>Oniva Forms Webhook:</strong> '
            . esc_html__( 'Neither Gravity Forms nor Contact Form 7 is active. Please activate one for this plugin to work.', 'oniva-gf-webhook' )
            . '</p></div>';
        delete_transient( 'oniva_no_forms_plugin_notice' );
    }

    if ( current_user_can( 'manage_options' ) ) {
        $last_error = get_option( ONIVA_GF_WEBHOOK_LOG_KEY );
        if ( ! empty( $last_error ) ) {
            echo '<div class="notice notice-error is-dismissible"><p>'
                . '<strong>Oniva Webhook Error:</strong> '
                . esc_html( $last_error )
                . ' &mdash; <a href="' . esc_url( admin_url( 'admin.php?page=oniva-gf-webhook&clear_error=1' ) ) . '">'
                . esc_html__( 'Dismiss', 'oniva-gf-webhook' )
                . '</a></p></div>';
        }
    }
}

// ──────────────────────────────────────────────
// 3b. Handle CF7 entry deletions early (admin_init) so headers aren't sent yet
// ──────────────────────────────────────────────
add_action( 'admin_init', 'oniva_cf7_handle_entry_deletions' );
function oniva_cf7_handle_entry_deletions() {
    if (
        ! isset( $_GET['page'] ) ||
        $_GET['page'] !== 'oniva-cf7-entries' ||
        ! current_user_can( 'manage_options' )
    ) {
        return;
    }

    global $wpdb;
    $table = $wpdb->prefix . ONIVA_CF7_TABLE;

    // ── Single delete ──
    if (
        isset( $_GET['action'], $_GET['entry_id'], $_GET['_wpnonce'] ) &&
        $_GET['action'] === 'delete_entry' &&
        wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'oniva_delete_entry_' . (int) $_GET['entry_id'] )
    ) {
        $wpdb->delete( $table, [ 'id' => (int) $_GET['entry_id'] ], [ '%d' ] );
        wp_safe_redirect( add_query_arg(
            array_filter( [
                'page'        => 'oniva-cf7-entries',
                'paged'       => isset( $_GET['paged'] ) && (int) $_GET['paged'] > 1 ? (int) $_GET['paged'] : false,
                'filter_form' => isset( $_GET['filter_form'] ) && $_GET['filter_form'] !== '' ? sanitize_text_field( wp_unslash( $_GET['filter_form'] ) ) : false,
                's'           => isset( $_GET['s'] ) && $_GET['s'] !== '' ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : false,
                'deleted'     => 1,
            ] ),
            admin_url( 'admin.php' )
        ) );
        exit;
    }

    // ── Bulk delete ──
    if (
        isset( $_POST['action'], $_POST['entry_ids'], $_POST['_wpnonce'] ) &&
        $_POST['action'] === 'bulk_delete' &&
        wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'oniva_bulk_delete' )
    ) {
        $ids = array_filter( array_map( 'intval', (array) $_POST['entry_ids'] ) );
        if ( ! empty( $ids ) ) {
            $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
            $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id IN ({$placeholders})", $ids ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        }
        wp_safe_redirect( add_query_arg(
            array_filter( [
                'page'        => 'oniva-cf7-entries',
                'filter_form' => isset( $_GET['filter_form'] ) && $_GET['filter_form'] !== '' ? sanitize_text_field( wp_unslash( $_GET['filter_form'] ) ) : false,
                's'           => isset( $_GET['s'] ) && $_GET['s'] !== '' ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : false,
                'deleted'     => 1,
            ] ),
            admin_url( 'admin.php' )
        ) );
        exit;
    }

    // ── Delete all ──
    if (
        isset( $_POST['action'], $_POST['_wpnonce'] ) &&
        $_POST['action'] === 'delete_all' &&
        wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'oniva_delete_all' )
    ) {
        $wpdb->query( "TRUNCATE TABLE {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        wp_safe_redirect( add_query_arg( [ 'page' => 'oniva-cf7-entries', 'deleted' => 1 ], admin_url( 'admin.php' ) ) );
        exit;
    }
}

// ──────────────────────────────────────────────
// 4. Admin menu
// ──────────────────────────────────────────────
add_action( 'admin_menu', 'oniva_admin_menu' );
function oniva_admin_menu() {
    add_menu_page(
        __( 'Oniva App', 'oniva-gf-webhook' ),
        __( 'Oniva App', 'oniva-gf-webhook' ),
        'manage_options',
        'oniva-gf-webhook',
        'oniva_settings_page',
        'dashicons-rest-api',
        80
    );

    add_submenu_page(
        'oniva-gf-webhook',
        __( 'Settings', 'oniva-gf-webhook' ),
        __( 'Settings', 'oniva-gf-webhook' ),
        'manage_options',
        'oniva-gf-webhook',
        'oniva_settings_page'
    );

    // CF7 Entries submenu – only visible when CF7 is active
    if ( defined( 'WPCF7_VERSION' ) ) {
        add_submenu_page(
            'oniva-gf-webhook',
            __( 'CF7 Entries', 'oniva-gf-webhook' ),
            __( 'CF7 Entries', 'oniva-gf-webhook' ),
            'manage_options',
            'oniva-cf7-entries',
            'oniva_cf7_entries_page'
        );
    }
}

// ──────────────────────────────────────────────
// 4a. Enqueue admin styles – inline to guarantee loading
// ──────────────────────────────────────────────
add_action( 'admin_head', 'oniva_admin_enqueue_scripts' );
function oniva_admin_enqueue_scripts() {
    $screen = get_current_screen();
    if ( ! $screen || strpos( $screen->id, 'oniva' ) === false ) {
        return;
    }
    ?>
    <style id="oniva-cf7-entries-css">
        #oniva-entries-wrap { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        #oniva-entries-wrap .oniva-toolbar { display:flex; align-items:center; gap:12px; margin-bottom:16px; flex-wrap:wrap; }
        #oniva-entries-wrap .oniva-search { padding:6px 10px; border:1px solid #c3c4c7; border-radius:4px; font-size:13px; min-width:220px; }
        #oniva-entries-wrap .oniva-form-select { padding:6px 10px; border:1px solid #c3c4c7; border-radius:4px; font-size:13px; width: 18%;}
        #oniva-entries-wrap .oniva-count-badge { margin-left:auto; font-size:12px; color:#646970; }
        .oniva-table-wrap { overflow-x:auto; }
        .oniva-entries-table { width:100%; border-collapse:collapse; font-size:13px; background:#fff; border:1px solid #e0e0e0; border-radius:6px; overflow:hidden; }
        .oniva-entries-table thead th { background:#f6f7f7; color:#2c3338; font-weight:600; padding:10px 14px; text-align:left; border-bottom:1px solid #e0e0e0; white-space:nowrap; }
        .oniva-entries-table tbody tr { border-bottom:1px solid #f0f0f1; }
        .oniva-entries-table tbody tr:last-child { border-bottom:none; }
        .oniva-entries-table tbody tr:hover { background:#f9f9f9; }
        .oniva-entries-table td { padding:10px 14px; vertical-align:top; color:#3c434a; }
        .oniva-entries-table td.oniva-date { white-space:nowrap; color:#646970; font-size:12px; }
        .oniva-entries-table td.oniva-form-title { font-weight:500; }
        .oniva-fields-preview { display:flex; flex-wrap:wrap; align-items:center; gap:6px; }
        .oniva-field-pill-wrap { display:inline-flex; align-items:baseline; gap:4px; background:#f0f6fc; border:1px solid #c5d9ed; border-radius:4px; padding:3px 9px; font-size:12px; white-space:nowrap; max-width:240px; overflow:hidden; text-overflow:ellipsis; }
        .oniva-field-pill-wrap .oniva-field-label { color:#646970; font-size:11px; flex-shrink:0; }
        .oniva-field-pill-wrap .oniva-field-value { color:#0a4480; font-weight:500; overflow:hidden; text-overflow:ellipsis; }
        .oniva-entry-toggle { cursor:pointer; color:#2271b1; font-size:11px; white-space:nowrap; text-decoration:underline; }

        /* Modal overlay */
        .oniva-modal-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.55); z-index:100000; align-items:center; justify-content:center; }
        .oniva-modal-overlay.open { display:flex; }

        /* Modal box */
        .oniva-modal { background:#fff; border-radius:8px; width:90%; max-width:680px; max-height:85vh; display:flex; flex-direction:column; box-shadow:0 8px 32px rgba(0,0,0,0.18); overflow:hidden; }

        /* Modal header */
        .oniva-modal-header { display:flex; align-items:center; justify-content:space-between; padding:16px 20px; border-bottom:1px solid #e0e0e0; flex-shrink:0; }
        .oniva-modal-title { font-size:15px; font-weight:600; color:#2c3338; margin:0; }
        .oniva-modal-close { background:none; border:none; cursor:pointer; font-size:20px; line-height:1; color:#646970; padding:0 4px; }
        .oniva-modal-close:hover { color:#2c3338; }

        /* Modal body */
        .oniva-modal-body { overflow-y:auto; padding:20px; flex:1; }

        /* Field rows inside modal */
        .oniva-modal-field { display:flex; align-items:baseline; gap:10px; padding:10px 0; border-bottom:1px solid #f0f0f1; }
        .oniva-modal-field:last-child { border-bottom:none; }
        .oniva-modal-field-label { min-width:140px; max-width:160px; font-size:12px; color:#646970; font-weight:500; flex-shrink:0; }
        .oniva-modal-field-value { font-size:13px; color:#2c3338; word-break:break-word; flex:1; }
        .oniva-empty { text-align:center; padding:40px 20px; color:#646970; }
        .oniva-pagination { display:flex; align-items:center; gap:6px; margin-top:16px; flex-wrap:wrap; }
        .oniva-pagination .page-numbers { display:inline-flex; padding:5px 10px; border:1px solid #c3c4c7; border-radius:3px; font-size:13px; color:#2271b1; text-decoration:none; background:#fff; }
        .oniva-pagination .page-numbers li{margin-right: 10px}
        .oniva-pagination .page-numbers.current { background:#2271b1; color:#fff; border-color:#2271b1; }
        .oniva-pagination .page-numbers:hover:not(.current) { background:#f0f0f1; }
        .oniva-no-cf7 { background:#fff8e1; border-left:4px solid #ffb900; padding:16px 20px; border-radius:0 4px 4px 0; margin-top:20px; }
    </style>
    <?php
}

// ──────────────────────────────────────────────
// 4b. Helper – fetch all CF7 forms as { "1": {id, title, entries}, ... }
// ──────────────────────────────────────────────
function oniva_get_cf7_forms_list() {
    global $wpdb;
    $table  = $wpdb->prefix . 'oniva_cf7_entries';
    $forms  = [];
    $index  = 1;
    $query  = new WP_Query( [
        'post_type'      => 'wpcf7_contact_form',
        'posts_per_page' => -1,
        'post_status'    => 'publish',
        'orderby'        => 'title',
        'order'          => 'ASC',
        'no_found_rows'  => true,
    ] );
    foreach ( $query->posts as $post ) {
        $entry_count = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table} WHERE form_id = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                (string) $post->ID
            )
        );
        $forms[ (string) $index ] = [
            'id'      => (string) $post->ID,
            'title'   => $post->post_title,
            'entries' => (string) $entry_count,
        ];
        $index++;
    }
    return $forms;
}

// ──────────────────────────────────────────────
// 4c. REST API routes
// ──────────────────────────────────────────────
add_action( 'rest_api_init', 'oniva_register_rest_routes' );
function oniva_register_rest_routes() {
    register_rest_route( 'oniva/v1', '/cf7-forms', [
        'methods'             => 'GET',
        'callback'            => 'oniva_rest_get_cf7_forms',
        'permission_callback' => 'oniva_rest_verify_secret_key',
    ] );

    register_rest_route( 'oniva/v1', '/cf7-debug/(?P<form_id>\d+)', [
        'methods'             => 'GET',
        'callback'            => 'oniva_rest_debug_cf7_labels',
        'permission_callback' => 'oniva_rest_verify_secret_key',
        'args'                => [
            'form_id' => [
                'required'          => true,
                'validate_callback' => function( $v ) { return is_numeric( $v ) && (int) $v > 0; },
                'sanitize_callback' => 'absint',
            ],
        ],
    ] );

    register_rest_route( 'oniva/v1', '/cf7-entries/(?P<form_id>\d+)', [
        'methods'             => 'GET',
        'callback'            => 'oniva_rest_get_cf7_entries',
        'permission_callback' => 'oniva_rest_verify_secret_key',
        'args'                => [
            'form_id' => [
                'required'          => true,
                'validate_callback' => function ( $value ) { return is_numeric( $value ) && (int) $value > 0; },
                'sanitize_callback' => 'absint',
            ],
            'per_page' => [
                'required'          => false,
                'default'           => 20,
                'validate_callback' => function ( $value ) { return is_numeric( $value ) && (int) $value > 0 && (int) $value <= 100; },
                'sanitize_callback' => 'absint',
            ],
            'page' => [
                'required'          => false,
                'default'           => 1,
                'validate_callback' => function ( $value ) { return is_numeric( $value ) && (int) $value > 0; },
                'sanitize_callback' => 'absint',
            ],
        ],
    ] );
}

function oniva_rest_verify_secret_key( WP_REST_Request $request ) {
    $stored_key = oniva_get_secret_key();
    $param_key  = $request->get_param( 'secret_key' );
    if ( $param_key && hash_equals( $stored_key, $param_key ) ) {
        return true;
    }
    $auth_header = $request->get_header( 'authorization' );
    if ( $auth_header && preg_match( '/^Bearer\s+(.+)$/i', $auth_header, $matches ) ) {
        if ( hash_equals( $stored_key, trim( $matches[1] ) ) ) {
            return true;
        }
    }
    return new WP_Error( 'rest_forbidden', __( 'Invalid or missing secret key.', 'oniva-gf-webhook' ), [ 'status' => 401 ] );
}

function oniva_rest_debug_cf7_labels( WP_REST_Request $request ) {
    $form_id = $request->get_param( 'form_id' );
    $form    = WPCF7_ContactForm::get_instance( $form_id );
    if ( ! $form ) {
        return new WP_Error( 'not_found', 'Form not found', [ 'status' => 404 ] );
    }
    $form_body = $form->prop( 'form' );
    $label_map = [];
    if ( preg_match_all( '/<label[^>]*>(.*?)<\/label>/is', $form_body, $label_blocks ) ) {
        foreach ( $label_blocks[1] as $block ) {
            if ( preg_match( '/\[\w[\w-]*\*?\s+([\w-]+)[^\]]*\]/', $block, $m ) ) {
                $field_name = $m[1];
                $label_text = trim( wp_strip_all_tags( preg_replace( '/\[[^\]]+\]/', '', $block ) ) );
                $label_map[ $field_name ] = $label_text !== '' ? $label_text : '(empty label)';
            }
        }
    }
    $tags = [];
    foreach ( $form->scan_form_tags() as $tag ) {
        if ( empty( $tag->name ) || 'submit' === $tag->basetype ) continue;
        $tags[] = [ 'name' => $tag->name, 'basetype' => $tag->basetype ];
    }
    return rest_ensure_response( [
        'form_id'    => $form_id,
        'form_title' => $form->title(),
        'label_map'  => $label_map,
        'tags'       => $tags,
        'raw_template_snippet' => mb_substr( $form_body, 0, 500 ),
    ] );
}

function oniva_rest_get_cf7_forms() {
    if ( ! defined( 'WPCF7_VERSION' ) ) {
        return new WP_Error( 'cf7_not_active', __( 'Contact Form 7 is not active.', 'oniva-gf-webhook' ), [ 'status' => 503 ] );
    }
    return rest_ensure_response( oniva_get_cf7_forms_list() );
}

function oniva_rest_get_cf7_entries( WP_REST_Request $request ) {
    if ( ! defined( 'WPCF7_VERSION' ) ) {
        return new WP_Error( 'cf7_not_active', __( 'Contact Form 7 is not active.', 'oniva-gf-webhook' ), [ 'status' => 503 ] );
    }
    $form_id  = $request->get_param( 'form_id' );
    $per_page = $request->get_param( 'per_page' );
    $page     = $request->get_param( 'page' );
    $form_post = get_post( $form_id );
    if ( ! $form_post || 'wpcf7_contact_form' !== $form_post->post_type ) {
        return new WP_Error( 'form_not_found', __( 'No CF7 form found with that ID.', 'oniva-gf-webhook' ), [ 'status' => 404 ] );
    }
    global $wpdb;
    $table  = $wpdb->prefix . ONIVA_CF7_TABLE;
    $offset = ( $page - 1 ) * $per_page;
    $total  = (int) $wpdb->get_var(
        $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE form_id = %s", (string) $form_id ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
    );
    $rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT id, form_id, form_title, site_url, fields, submitted_at FROM {$table} WHERE form_id = %s ORDER BY submitted_at DESC LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            (string) $form_id,
            $per_page,
            $offset
        ),
        ARRAY_A
    );
    $entries = [];
    foreach ( $rows as $row ) {
        $fields = ! empty( $row['fields'] ) ? json_decode( $row['fields'], true ) : [];
        if ( ! is_array( $fields ) ) $fields = [];
        $entries[] = array_merge( [ 'submitted_at' => $row['submitted_at'] ], $fields );
    }
    $response = rest_ensure_response( [ 'total_count' => $total, 'entries' => $entries ] );
    $response->header( 'X-WP-Total',      $total );
    $response->header( 'X-WP-TotalPages', (int) ceil( $total / $per_page ) );
    return $response;
}

// ──────────────────────────────────────────────
// 5. Register settings
// ──────────────────────────────────────────────
add_action( 'admin_init', 'oniva_register_settings' );
function oniva_register_settings() {
    register_setting( 'oniva_webhook_group', 'oniva_gf_webhook_enabled',
        [ 'type' => 'boolean', 'default' => true, 'sanitize_callback' => 'rest_sanitize_boolean' ] );
    register_setting( 'oniva_webhook_group', 'oniva_cf7_webhook_enabled',
        [ 'type' => 'boolean', 'default' => true, 'sanitize_callback' => 'rest_sanitize_boolean' ] );
    register_setting( 'oniva_webhook_group', 'oniva_gf_webhook_custom_url',
        [ 'type' => 'string', 'default' => '', 'sanitize_callback' => 'esc_url_raw' ] );
    register_setting( 'oniva_webhook_group', 'oniva_cf7_webhook_custom_url',
        [ 'type' => 'string', 'default' => '', 'sanitize_callback' => 'esc_url_raw' ] );
}

// ──────────────────────────────────────────────
// 6. Settings page
// ──────────────────────────────────────────────
function oniva_settings_page() {
    if (
        isset( $_GET['clear_error'], $_GET['page'] ) &&
        $_GET['page'] === 'oniva-gf-webhook' &&
        current_user_can( 'manage_options' )
    ) {
        delete_option( ONIVA_GF_WEBHOOK_LOG_KEY );
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Error log cleared.', 'oniva-gf-webhook' ) . '</p></div>';
    }

    if (
        isset( $_POST['oniva_regenerate_key'], $_POST['_wpnonce'] ) &&
        wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'oniva_regenerate_key' ) &&
        current_user_can( 'manage_options' )
    ) {
        update_option( ONIVA_CF7_SECRET_KEY_OPTION, oniva_generate_secret_key() );
        echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Secret key regenerated. Update your Oniva integration with the new key.', 'oniva-gf-webhook' ) . '</p></div>';
    }

    $gf_active  = class_exists( 'GFForms' );
    $cf7_active = defined( 'WPCF7_VERSION' );
    $secret_key = oniva_get_secret_key();
    ?>
    <div class="wrap">
        <h1><?php esc_html_e( 'Oniva – Forms Webhook', 'oniva-gf-webhook' ); ?></h1>

        <h2><?php esc_html_e( 'Active Plugins', 'oniva-gf-webhook' ); ?></h2>
        <table class="widefat" style="max-width:480px;">
            <tbody>
                <tr>
                    <td><strong>Gravity Forms</strong></td>
                    <td><?php echo $gf_active
                        ? '<span style="color:green;">&#10003; Active</span>'
                        : '<span style="color:#aaa;">&#10007; Not active</span>'; ?></td>
                </tr>
                <tr>
                    <td><strong>Contact Form 7</strong></td>
                    <td><?php echo $cf7_active
                        ? '<span style="color:green;">&#10003; Active</span>'
                        : '<span style="color:#aaa;">&#10007; Not active</span>'; ?></td>
                </tr>
            </tbody>
        </table>

        <?php if ( $cf7_active ) : ?>
        <p style="margin-top:12px;">
            <a href="<?php echo esc_url( admin_url( 'admin.php?page=oniva-cf7-entries' ) ); ?>" class="button button-primary">
                <?php esc_html_e( 'View CF7 Entries →', 'oniva-gf-webhook' ); ?>
            </a>
        </p>
        <?php endif; ?>

        <h2 style="margin-top:2em;"><?php esc_html_e( 'API Secret Key', 'oniva-gf-webhook' ); ?></h2>
        <p><?php esc_html_e( 'Use this key to authenticate requests to the CF7 Forms REST API endpoint.', 'oniva-gf-webhook' ); ?></p>

        <table class="form-table" role="presentation" style="max-width:700px;">
            <tr>
                <th scope="row"><?php esc_html_e( 'Secret Key', 'oniva-gf-webhook' ); ?></th>
                <td>
                    <div style="display:flex;align-items:center;gap:8px;">
                        <input
                            type="text"
                            id="oniva-secret-key"
                            value="<?php echo esc_attr( $secret_key ); ?>"
                            class="regular-text"
                            readonly
                            style="font-family:monospace;background:#f6f7f7;"
                        />
                        <button
                            type="button"
                            class="button"
                            onclick="
                                var el = document.getElementById('oniva-secret-key');
                                el.select();
                                document.execCommand('copy');
                                this.textContent = '<?php echo esc_js( __( 'Copied!', 'oniva-gf-webhook' ) ); ?>';
                                var btn = this;
                                setTimeout(function(){ btn.textContent = '<?php echo esc_js( __( 'Copy', 'oniva-gf-webhook' ) ); ?>'; }, 2000);
                            ">
                            <?php esc_html_e( 'Copy', 'oniva-gf-webhook' ); ?>
                        </button>
                    </div>
                    <p class="description" style="margin-top:6px;">
                        <?php esc_html_e( 'Generated automatically on plugin activation. Regenerate only if the key is compromised.', 'oniva-gf-webhook' ); ?>
                    </p>
                </td>
            </tr>
            <tr>
                <td>
                    <form method="post"
                        onsubmit="return confirm('<?php esc_attr_e( 'This will invalidate the current key. Any integration using the old key will stop working until updated. Continue?', 'oniva-gf-webhook' ); ?>')">
                        <?php wp_nonce_field( 'oniva_regenerate_key' ); ?>
                        <button type="submit" name="oniva_regenerate_key" class="button button-secondary" style="color:#fff;background:#2271b1">
                            <?php esc_html_e( 'Regenerate Secret Key', 'oniva-gf-webhook' ); ?>
                        </button>
                    </form>
                </td>
            </tr>
        </table>
    </div>
    <?php
}

// ──────────────────────────────────────────────
// 6b. CF7 Entries admin page
// ──────────────────────────────────────────────
function oniva_cf7_entries_page() {
    // Guard: CF7 must be active
    if ( ! defined( 'WPCF7_VERSION' ) ) {
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'CF7 Entries', 'oniva-gf-webhook' ); ?></h1>
            <div class="oniva-no-cf7">
                <strong><?php esc_html_e( 'Contact Form 7 is not active.', 'oniva-gf-webhook' ); ?></strong>
                <?php esc_html_e( 'Please install and activate Contact Form 7 to view entries here.', 'oniva-gf-webhook' ); ?>
            </div>
        </div>
        <?php
        return;
    }

    global $wpdb;

    $table = $wpdb->prefix . ONIVA_CF7_TABLE;

    // ── Notice: entry deleted ──
    if ( ! empty( $_GET['deleted'] ) ) {
        echo '<div class="notice notice-success is-dismissible"><p>'
            . esc_html__( 'Entry deleted successfully.', 'oniva-gf-webhook' )
            . '</p></div>';
    }

    $per_page   = 10;
    $current_pg = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
    $offset     = ( $current_pg - 1 ) * $per_page;

    // ── Filter: form_id ──
    $filter_form = isset( $_GET['filter_form'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_form'] ) ) : '';

    // ── Filter: search keyword ──
    $search_raw  = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';

    // Build WHERE clause
    $where      = '1=1';
    $where_args = [];

    if ( $filter_form !== '' ) {
        $where       .= ' AND form_id = %s';
        $where_args[] = $filter_form;
    }

    if ( $search_raw !== '' ) {
        $where       .= ' AND ( form_title LIKE %s OR fields LIKE %s )';
        $like         = '%' . $wpdb->esc_like( $search_raw ) . '%';
        $where_args[] = $like;
        $where_args[] = $like;
    }

    $total_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where}"; // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
    $rows_sql  = "SELECT * FROM {$table} WHERE {$where} ORDER BY submitted_at DESC LIMIT %d OFFSET %d"; // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

    if ( ! empty( $where_args ) ) {
        $total = (int) $wpdb->get_var( $wpdb->prepare( $total_sql, $where_args ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $rows  = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $where_args, [ $per_page, $offset ] ) ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
    } else {
        $total = (int) $wpdb->get_var( $total_sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $rows  = $wpdb->get_results( $wpdb->prepare( $rows_sql, $per_page, $offset ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
    }

    $total_pages = (int) ceil( $total / $per_page );

    // ── Fetch all forms for the filter dropdown ──
    $all_forms = $wpdb->get_results(
        "SELECT DISTINCT form_id, form_title FROM {$table} ORDER BY form_title ASC", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        ARRAY_A
    );

    // ── Build page URL helper ──
    $base_url = admin_url( 'admin.php' );
    $url_args = [
        'page'        => 'oniva-cf7-entries',
        'filter_form' => $filter_form,
        's'           => $search_raw,
    ];
    ?>
    <div class="wrap" id="oniva-entries-wrap">
        <h1 style="display:flex;align-items:center;gap:10px;">
            <?php esc_html_e( 'CF7 Entries', 'oniva-gf-webhook' ); ?>
            <span style="font-size:13px;font-weight:400;color:#646970;background:#f0f0f1;padding:3px 10px;border-radius:10px;">
                <?php echo esc_html( number_format_i18n( $total ) ); ?> <?php esc_html_e( 'total', 'oniva-gf-webhook' ); ?>
            </span>
            <?php if ( $total > 0 ) : ?>
            <form method="post" style="margin-left:auto;"
                  onsubmit="return confirm('<?php esc_attr_e( 'Delete ALL entries? This cannot be undone.', 'oniva-gf-webhook' ); ?>')">
                <?php wp_nonce_field( 'oniva_delete_all' ); ?>
                <input type="hidden" name="action" value="delete_all" />
                <button type="submit" class="button" style="color:#b32d2e;border-color:#b32d2e;">
                    <?php esc_html_e( 'Delete All Entries', 'oniva-gf-webhook' ); ?>
                </button>
            </form>
            <?php endif; ?>
        </h1>

        <?php // ── Toolbar: search + form filter ── ?>
        <form method="get" action="<?php echo esc_url( $base_url ); ?>">
            <input type="hidden" name="page" value="oniva-cf7-entries" />
            <div class="oniva-toolbar">
                <input
                    type="search"
                    name="s"
                    class="oniva-search"
                    placeholder="<?php esc_attr_e( 'Search entries…', 'oniva-gf-webhook' ); ?>"
                    value="<?php echo esc_attr( $search_raw ); ?>"
                />
                <select name="filter_form" class="oniva-form-select">
                    <option value=""><?php esc_html_e( 'All forms', 'oniva-gf-webhook' ); ?></option>
                    <?php foreach ( $all_forms as $form_row ) : ?>
                        <option value="<?php echo esc_attr( $form_row['form_id'] ); ?>"
                            <?php selected( $filter_form, $form_row['form_id'] ); ?>>
                            <?php echo esc_html( $form_row['form_title'] ); ?>
                            (ID: <?php echo esc_html( $form_row['form_id'] ); ?>)
                        </option>
                    <?php endforeach; ?>
                </select>
                <button type="submit" class="button"><?php esc_html_e( 'Filter', 'oniva-gf-webhook' ); ?></button>
                <?php if ( $search_raw || $filter_form ) : ?>
                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=oniva-cf7-entries' ) ); ?>" class="button">
                        <?php esc_html_e( 'Reset', 'oniva-gf-webhook' ); ?>
                    </a>
                <?php endif; ?>

                <span class="oniva-count-badge">
                    <?php
                    /* translators: 1: current page, 2: total pages */
                    printf(
                        esc_html__( 'Page %1$d of %2$d', 'oniva-gf-webhook' ),
                        $current_pg,
                        max( 1, $total_pages )
                    );
                    ?>
                </span>
            </div>
        </form>

        <?php if ( empty( $rows ) ) : ?>
            <div class="oniva-table-wrap">
                <table class="oniva-entries-table">
                    <thead>
                        <tr>
                            <th style="width:30px;"></th>
                            <th><?php esc_html_e( '#', 'oniva-gf-webhook' ); ?></th>
                            <th><?php esc_html_e( 'Form', 'oniva-gf-webhook' ); ?></th>
                            <th><?php esc_html_e( 'Fields', 'oniva-gf-webhook' ); ?></th>
                            <th><?php esc_html_e( 'Submitted', 'oniva-gf-webhook' ); ?></th>
                            <th><?php esc_html_e( 'Actions', 'oniva-gf-webhook' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td colspan="6" class="oniva-empty">
                                <?php esc_html_e( 'No entries found. Entries will appear here after a Contact Form 7 form is submitted.', 'oniva-gf-webhook' ); ?>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

        <?php else : ?>
            <form method="post" id="oniva-bulk-form">
                <?php wp_nonce_field( 'oniva_bulk_delete' ); ?>
                <input type="hidden" name="action" value="bulk_delete" />

                <div style="margin-bottom:8px;display:flex;align-items:center;gap:8px;">
                    <button type="submit" class="button"
                            style="color:#b32d2e;border-color:#b32d2e;"
                            onclick="return confirm('<?php esc_attr_e( 'Delete selected entries?', 'oniva-gf-webhook' ); ?>')">
                        <?php esc_html_e( 'Delete Selected', 'oniva-gf-webhook' ); ?>
                    </button>
                </div>

            <div class="oniva-table-wrap">
                <table class="oniva-entries-table">
                    <thead>
                        <tr>
                            <th style="width:30px;">
                                <input type="checkbox" id="oniva-select-all" title="<?php esc_attr_e( 'Select all', 'oniva-gf-webhook' ); ?>" />
                            </th>
                            <th style="width:50px;"><?php esc_html_e( '#', 'oniva-gf-webhook' ); ?></th>
                            <th style="width:160px;"><?php esc_html_e( 'Form', 'oniva-gf-webhook' ); ?></th>
                            <th><?php esc_html_e( 'Fields', 'oniva-gf-webhook' ); ?></th>
                            <th style="width:140px;"><?php esc_html_e( 'Submitted', 'oniva-gf-webhook' ); ?></th>
                            <th style="width:120px;"><?php esc_html_e( 'Actions', 'oniva-gf-webhook' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $rows as $i => $row ) :
                            $fields = ! empty( $row['fields'] ) ? json_decode( $row['fields'], true ) : [];
                            if ( ! is_array( $fields ) ) $fields = [];
                            $row_num    = $offset + $i + 1;
                        ?>
                        <tr>
                            <td>
                                <input type="checkbox" name="entry_ids[]" value="<?php echo esc_attr( $row['id'] ); ?>" class="oniva-entry-cb" />
                            </td>
                            <td style="color:#646970;font-size:12px;"><?php echo esc_html( $row_num ); ?></td>

                            <td class="oniva-form-title">
                                <?php echo esc_html( $row['form_title'] ); ?>
                                <br>
                                <span style="font-size:11px;color:#646970;">ID: <?php echo esc_html( $row['form_id'] ); ?></span>
                            </td>

                            <td>
                                <?php
                                $preview_fields = array_slice( $fields, 0, 3, true );
                                $field_count    = count( $fields );
                                if ( ! empty( $preview_fields ) ) : ?>
                                <div class="oniva-fields-preview">
                                    <?php foreach ( $preview_fields as $f_label => $f_value ) : ?>
                                    <span class="oniva-field-pill-wrap" title="<?php echo esc_attr( $f_label . ': ' . $f_value ); ?>">
                                        <span class="oniva-field-label"><?php echo esc_html( $f_label ); ?>:</span>
                                        <span class="oniva-field-value"><?php echo esc_html( $f_value !== '' ? $f_value : '—' ); ?></span>
                                    </span>
                                    <?php endforeach; ?>
                                    <?php if ( $field_count > 3 ) : ?>
                                        <span style="font-size:11px;color:#646970;">+<?php echo esc_html( $field_count - 3 ); ?> more</span>
                                    <?php endif; ?>
                                </div>
                                <?php else : ?>
                                    <span style="color:#aaa;font-size:12px;"><?php esc_html_e( '—', 'oniva-gf-webhook' ); ?></span>
                                <?php endif; ?>
                            </td>

                            <td class="oniva-date">
                                <?php
                                echo esc_html(
                                    wp_date( get_option( 'date_format' ), strtotime( $row['submitted_at'] ) )
                                );
                                echo '<br>';
                                echo esc_html(
                                    wp_date( get_option( 'time_format' ), strtotime( $row['submitted_at'] ) )
                                );
                                ?>
                            </td>

                            <td style="white-space:nowrap;">
                                <a class="button button-small oniva-entry-toggle"
                                   href="#"
                                   data-form="<?php echo esc_attr( $row['form_title'] ); ?>"
                                   data-fields="<?php echo esc_attr( wp_json_encode( $fields ) ); ?>"
                                   style="margin-right:6px;">
                                    <?php esc_html_e( 'View', 'oniva-gf-webhook' ); ?>
                                </a>
                                <a href="<?php echo esc_url( wp_nonce_url(
                                    add_query_arg( [ 'action' => 'delete_entry', 'entry_id' => $row['id'] ] ),
                                    'oniva_delete_entry_' . (int) $row['id']
                                ) ); ?>"
                                   class="button button-small"
                                   style="color:#b32d2e;border-color:#b32d2e;"
                                   onclick="return confirm('<?php esc_attr_e( 'Delete this entry?', 'oniva-gf-webhook' ); ?>')">
                                    <?php esc_html_e( 'Delete', 'oniva-gf-webhook' ); ?>
                                </a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            </form>

            <?php // ── Pagination ── ?>
            <?php if ( $total_pages > 1 ) : ?>
                <div class="oniva-pagination">
                    <?php
                    $paginate_links = paginate_links( [
                        'base'      => add_query_arg( array_merge( $url_args, [ 'paged' => '%#%' ] ), $base_url ),
                        'format'    => '',
                        'current'   => $current_pg,
                        'total'     => $total_pages,
                        'prev_text' => __( '&laquo; Prev', 'oniva-gf-webhook' ),
                        'next_text' => __( 'Next &raquo;', 'oniva-gf-webhook' ),
                        'type'      => 'list',
                    ] );
                    echo wp_kses_post( $paginate_links );
                    ?>
                </div>
            <?php endif; ?>

        <?php endif; ?>
    </div>

    <?php // ── Modal markup (single instance, reused for all rows) ── ?>
    <div class="oniva-modal-overlay" id="oniva-modal-overlay" role="dialog" aria-modal="true" aria-labelledby="oniva-modal-title">
        <div class="oniva-modal">
            <div class="oniva-modal-header">
                <p class="oniva-modal-title" id="oniva-modal-title"><?php esc_html_e( 'Entry Fields', 'oniva-gf-webhook' ); ?></p>
                <button class="oniva-modal-close" id="oniva-modal-close" aria-label="<?php esc_attr_e( 'Close', 'oniva-gf-webhook' ); ?>">&times;</button>
            </div>
            <div class="oniva-modal-body" id="oniva-modal-body"></div>
        </div>
    </div>

    <script>
    document.addEventListener( 'DOMContentLoaded', function () {
        // ── Select-all checkbox ──
        var selectAll = document.getElementById( 'oniva-select-all' );
        if ( selectAll ) {
            selectAll.addEventListener( 'change', function () {
                document.querySelectorAll( '.oniva-entry-cb' ).forEach( function ( cb ) {
                    cb.checked = selectAll.checked;
                } );
            } );
        }
        var overlay = document.getElementById( 'oniva-modal-overlay' );
        var title   = document.getElementById( 'oniva-modal-title' );
        var body    = document.getElementById( 'oniva-modal-body' );
        var closeBtn = document.getElementById( 'oniva-modal-close' );

        function openModal( formName, fields ) {
            title.textContent = formName;
            body.innerHTML = '';

            Object.keys( fields ).forEach( function( label ) {
                var row = document.createElement( 'div' );
                row.className = 'oniva-modal-field';

                var lbl = document.createElement( 'span' );
                lbl.className = 'oniva-modal-field-label';
                lbl.textContent = label;

                var val = document.createElement( 'span' );
                val.className = 'oniva-modal-field-value';
                val.textContent = fields[ label ] || '—';

                row.appendChild( lbl );
                row.appendChild( val );
                body.appendChild( row );
            } );

            overlay.classList.add( 'open' );
            document.body.style.overflow = 'hidden';
        }

        function closeModal() {
            overlay.classList.remove( 'open' );
            document.body.style.overflow = '';
        }

        document.querySelectorAll( '.oniva-entry-toggle' ).forEach( function ( link ) {
            link.addEventListener( 'click', function ( e ) {
                e.preventDefault();
                var formName = this.getAttribute( 'data-form' ) || 'Entry Fields';
                var raw      = this.getAttribute( 'data-fields' );
                var fields   = {};
                try { fields = JSON.parse( raw ); } catch(err) {}
                openModal( formName, fields );
            } );
        } );

        closeBtn.addEventListener( 'click', closeModal );

        overlay.addEventListener( 'click', function ( e ) {
            if ( e.target === overlay ) { closeModal(); }
        } );

        document.addEventListener( 'keydown', function ( e ) {
            if ( e.key === 'Escape' ) { closeModal(); }
        } );
    } );
    </script>
    <?php
}

// ──────────────────────────────────────────────
// 7. Helpers – resolve active webhook URLs
// ──────────────────────────────────────────────
function oniva_get_gf_webhook_url() {
    $custom = get_option( 'oniva_gf_webhook_custom_url', '' );
    return ! empty( $custom ) ? $custom : ONIVA_GF_WEBHOOK_URL;
}

function oniva_get_cf7_webhook_url() {
    $custom = get_option( 'oniva_cf7_webhook_custom_url', '' );
    return ! empty( $custom ) ? $custom : ONIVA_CF7_WEBHOOK_URL;
}

// ──────────────────────────────────────────────
// 8. Helper – fire the webhook
// ──────────────────────────────────────────────
function oniva_send_webhook( array $payload, $source_label = '', $url = '' ) {
    $response = wp_remote_post( $url, [
        'method'    => 'POST',
        'body'      => wp_json_encode( $payload ),
        'headers'   => [ 'Content-Type' => 'application/json' ],
        'timeout'   => 15,
        'sslverify' => true,
    ] );

    if ( is_wp_error( $response ) ) {
        update_option(
            ONIVA_GF_WEBHOOK_LOG_KEY,
            sprintf( '[%s] %s WP Error: %s', current_time( 'mysql' ), $source_label, $response->get_error_message() )
        );
        return false;
    }

    $code = wp_remote_retrieve_response_code( $response );
    if ( $code < 200 || $code >= 300 ) {
        update_option(
            ONIVA_GF_WEBHOOK_LOG_KEY,
            sprintf( '[%s] %s HTTP %d – %s', current_time( 'mysql' ), $source_label, $code, wp_remote_retrieve_body( $response ) )
        );
        return false;
    }

    delete_option( ONIVA_GF_WEBHOOK_LOG_KEY );
    return true;
}

// ──────────────────────────────────────────────
// 9. Gravity Forms – send webhook
// ──────────────────────────────────────────────
add_action( 'gform_after_submission', 'oniva_gf_handle_submission', 10, 2 );
function oniva_gf_handle_submission( $entry, $form ) {
    if ( ! get_option( 'oniva_gf_webhook_enabled', true ) ) {
        return;
    }
    oniva_send_webhook( [
        'source'       => 'gravity_forms',
        'form_id'      => $form['id'],
        'form_title'   => $form['title'],
        'site_url'     => get_site_url(),
        'entry_id'     => $entry['id'],
        'date_created' => $entry['date_created'],
    ], 'GravityForms #' . $form['id'], oniva_get_gf_webhook_url() );
}

// ──────────────────────────────────────────────
// 10. Contact Form 7 – save entry + send webhook
// ──────────────────────────────────────────────
add_action( 'wpcf7_mail_sent', 'oniva_cf7_handle_submission', 10, 1 );
function oniva_cf7_handle_submission( $contact_form ) {
    if ( ! get_option( 'oniva_cf7_webhook_enabled', true ) ) {
        return;
    }

    $submission = WPCF7_Submission::get_instance();
    if ( ! $submission ) {
        return;
    }

    $posted    = $submission->get_posted_data();
    $form_body = $contact_form->prop( 'form' );

    $label_map = [];
    if ( preg_match_all( '/<label[^>]*>(.*?)<\/label>/is', $form_body, $label_blocks ) ) {
        foreach ( $label_blocks[1] as $block ) {
            if ( preg_match( '/\[\w[\w-]*\*?\s+([\w-]+)[^\]]*\]/', $block, $m ) ) {
                $field_name = $m[1];
                $label_text = trim( wp_strip_all_tags( preg_replace( '/\[[^\]]+\]/', '', $block ) ) );
                if ( $label_text !== '' ) {
                    $label_map[ $field_name ] = $label_text;
                }
            }
        }
    }

    $fields = [];
    foreach ( $contact_form->scan_form_tags() as $tag ) {
        if ( empty( $tag->name ) || 'submit' === $tag->basetype ) {
            continue;
        }
        $label = isset( $label_map[ $tag->name ] ) ? $label_map[ $tag->name ] : $tag->name;
        $value = isset( $posted[ $tag->name ] ) ? $posted[ $tag->name ] : '';
        if ( is_array( $value ) ) {
            $value = implode( ', ', array_filter( $value ) );
        }
        $fields[ sanitize_text_field( $label ) ] = sanitize_textarea_field( (string) $value );
    }

    global $wpdb;
    $wpdb->insert(
        $wpdb->prefix . ONIVA_CF7_TABLE,
        [
            'form_id'      => sanitize_text_field( (string) $contact_form->id() ),
            'form_title'   => sanitize_text_field( $contact_form->title() ),
            'site_url'     => esc_url_raw( get_site_url() ),
            'fields'       => wp_json_encode( $fields ),
            'submitted_at' => current_time( 'mysql' ),
        ],
        [ '%s', '%s', '%s', '%s', '%s' ]
    );

    oniva_send_webhook( [
        'source'     => 'contact_form_7',
        'form_id'    => (string) $contact_form->id(),
        'form_title' => $contact_form->title(),
        'site_url'   => get_site_url(),
        'fields'     => $fields,
    ], 'CF7 #' . $contact_form->id(), oniva_get_cf7_webhook_url() );
}

// ──────────────────────────────────────────────
// 11. Uninstall – clean up options
// ──────────────────────────────────────────────
register_uninstall_hook( __FILE__, 'oniva_plugin_uninstall' );
function oniva_plugin_uninstall() {
    delete_option( 'oniva_gf_webhook_enabled' );
    delete_option( 'oniva_cf7_webhook_enabled' );
    delete_option( 'oniva_gf_webhook_custom_url' );
    delete_option( 'oniva_cf7_webhook_custom_url' );
    delete_option( ONIVA_GF_WEBHOOK_LOG_KEY );
    delete_option( ONIVA_CF7_SECRET_KEY_OPTION );
    delete_option( 'oniva_cf7_db_version' );
    // Note: wp_oniva_cf7_entries table preserved on uninstall to avoid data loss.
}