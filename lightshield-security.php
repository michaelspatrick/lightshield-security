<?php
/*
Plugin Name: LightShield Security
Description: Lightweight protection against brute force login attempts, bad bots, xmlrpc access, and simple request spikes. Includes IP whitelist/blocklist with a clean admin UI. Optional Cloudflare IP blocking at the edge.
Version: 1.1.4
Author: Michael Patrick
License: GPLv2 or later
*/

if (!defined('ABSPATH')) { exit; }

define('LS_VERSION', '1.1.4');
define('LS_OPTION_SETTINGS', 'ls_settings');
define('LS_OPTION_BLOCKLIST', 'ls_blocklist');
define('LS_OPTION_WHITELIST', 'ls_whitelist');
define('LS_OPTION_CF', 'ls_cf_settings');
define('LS_OPTION_CF_MAP', 'ls_cf_map'); // ip => rule_id

/**
 * Default settings on activation
 */
register_activation_hook(__FILE__, function () {
    if (!get_option(LS_OPTION_SETTINGS)) {
        add_option(LS_OPTION_SETTINGS, array(
            'trust_cloudflare'       => 1,
            'disable_xmlrpc'         => 1,
            'block_bad_ua'           => 1,
            'login_fail_limit'       => 5,
            'login_block_minutes'    => 15,
            'throttle_all'           => 0,
            'throttle_per_minute'    => 120,
        ));
    }
    if (!get_option(LS_OPTION_BLOCKLIST)) { add_option(LS_OPTION_BLOCKLIST, array()); }
    if (!get_option(LS_OPTION_WHITELIST)) { add_option(LS_OPTION_WHITELIST, array()); }
    if (!get_option(LS_OPTION_CF)) { add_option(LS_OPTION_CF, array('enabled'=>0,'zone_id'=>'','token'=>'')); }
    if (!get_option(LS_OPTION_CF_MAP)) { add_option(LS_OPTION_CF_MAP, array()); }

    if (!wp_next_scheduled('ls_prune_event')) {
        wp_schedule_event(time() + 300, 'hourly', 'ls_prune_event');
    }
});
register_deactivation_hook(__FILE__, function () {
    $timestamp = wp_next_scheduled('ls_prune_event');
    if ($timestamp) { wp_unschedule_event($timestamp, 'ls_prune_event'); }
});

/** Cloudflare helpers */
function ls_cf_enabled() {
    $cf = get_option(LS_OPTION_CF, array());
    return !empty($cf['enabled']) && !empty($cf['zone_id']) && !empty($cf['token']);
}
function ls_cf_http($method, $path, $args = array()) {
    $cf = get_option(LS_OPTION_CF, array());
    $url = 'https://api.cloudflare.com/client/v4' . $path;
    $defaults = array(
        'headers' => array('Authorization'=>'Bearer ' . ($cf['token'] ?? ''), 'Content-Type'=>'application/json'),
        'timeout' => 12,
    );
    $req = wp_parse_args($args, $defaults);
    if ($method === 'GET')  { $response = wp_remote_get($url, $req); }
    elseif ($method === 'POST') { $response = wp_remote_post($url, $req); }
    else { $req['method'] = $method; $response = wp_remote_request($url, $req); }

    if (is_wp_error($response)) { set_transient('ls_cf_last_error', 'Cloudflare API error: ' . $response->get_error_message(), 300); return false; }
    $code = wp_remote_retrieve_response_code($response);
    $data = json_decode(wp_remote_retrieve_body($response), true);
    if ($code >= 200 && $code < 300 && !empty($data['success'])) { return $data; }
    $msg = !empty($data['errors'][0]['message']) ? $data['errors'][0]['message'] : ('HTTP ' . $code);
    set_transient('ls_cf_last_error', 'Cloudflare API error (' . $code . '): ' . $msg, 300);
    return false;
}
function ls_cf_block_ip($ip, $reason = '') {
    if (!ls_cf_enabled()) { return false; }
    if (!filter_var($ip, FILTER_VALIDATE_IP)) { return false; }
    $cf = get_option(LS_OPTION_CF, array());
    $body = array('mode'=>'block','configuration'=>array('target'=>'ip','value'=>$ip),'notes'=>'LightShield: ' . ($reason ?: 'blocked'));
    $data = ls_cf_http('POST', '/zones/' . rawurlencode($cf['zone_id']) . '/firewall/access_rules/rules', array('body'=>wp_json_encode($body)));
    if ($data && !empty($data['result']['id'])) {
        $map = get_option(LS_OPTION_CF_MAP, array());
        $map[$ip] = $data['result']['id'];
        update_option(LS_OPTION_CF_MAP, $map, false);
        return $data['result']['id'];
    }
    return false;
}
function ls_cf_find_rule_id_by_ip($ip) {
    if (!ls_cf_enabled()) { return false; }
    $cf = get_option(LS_OPTION_CF, array());
    $qs = '?configuration_target=ip&configuration_value=' . rawurlencode($ip) . '&per_page=50';
    $data = ls_cf_http('GET', '/zones/' . rawurlencode($cf['zone_id']) . '/firewall/access_rules/rules' . $qs);
    if ($data && !empty($data['result'])) {
        foreach ($data['result'] as $r) {
            if (!empty($r['configuration']['target']) && $r['configuration']['target']==='ip'
                && !empty($r['configuration']['value']) && $r['configuration']['value']===$ip) {
                return $r['id'];
            }
        }
    }
    return false;
}
function ls_cf_unblock_ip($ip) {
    if (!ls_cf_enabled()) { return false; }
    $map = get_option(LS_OPTION_CF_MAP, array());
    $rid = !empty($map[$ip]) ? $map[$ip] : ls_cf_find_rule_id_by_ip($ip);
    if (!$rid) { return false; }
    $cf = get_option(LS_OPTION_CF, array());
    $ok = ls_cf_http('DELETE', '/zones/' . rawurlencode($cf['zone_id']) . '/firewall/access_rules/rules/' . rawurlencode($rid));
    if ($ok) {
        if (isset($map[$ip])) { unset($map[$ip]); update_option(LS_OPTION_CF_MAP, $map, false); }
        return true;
    }
    return false;
}
function ls_cf_sync_cleanup() {
    if (!ls_cf_enabled()) { return 0; }
    $cf = get_option(LS_OPTION_CF, array());
    $keep_ips = array_keys(get_option(LS_OPTION_BLOCKLIST, array()));
    $deleted = 0;
    // Pull first 200 rules and delete those with "LightShield" note not in keep list
    $data = ls_cf_http('GET', '/zones/' . rawurlencode($cf['zone_id']) . '/firewall/access_rules/rules?per_page=200');
    if ($data && !empty($data['result'])) {
        foreach ($data['result'] as $r) {
            $is_ls = !empty($r['notes']) && stripos($r['notes'], 'lightshield') !== false;
            $is_ip = !empty($r['configuration']['target']) && $r['configuration']['target']==='ip';
            $ipval = $is_ip ? ($r['configuration']['value'] ?? '') : '';
            if ($is_ls && $is_ip && $ipval && !in_array($ipval, $keep_ips, true)) {
                $ok = ls_cf_http('DELETE', '/zones/' . rawurlencode($cf['zone_id']) . '/firewall/access_rules/rules/' . rawurlencode($r['id']));
                if ($ok) { $deleted++; }
            }
        }
    }
    return $deleted;
}

/** Prune helper */
function ls_prune_blocklist() {
    $blocklist = get_option(LS_OPTION_BLOCKLIST, array());
    $changed = false;
    $now = time();
    foreach ($blocklist as $ip => $entry) {
        if (empty($entry['until']) || $now >= intval($entry['until'])) {
            // remove at Cloudflare too
            if (ls_cf_enabled()) { ls_cf_unblock_ip($ip); }
            unset($blocklist[$ip]);
            $changed = true;
        }
    }
    if ($changed) { update_option(LS_OPTION_BLOCKLIST, $blocklist, false); }
}
add_action('ls_prune_event', 'ls_prune_blocklist');

/**
 * Helper: get client IP (Cloudflare-aware if enabled)
 */
function ls_get_client_ip() {
    $settings = get_option(LS_OPTION_SETTINGS, array());
    $candidates = array();

    if (!empty($settings['trust_cloudflare'])) {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) { $candidates[] = $_SERVER['HTTP_CF_CONNECTING_IP']; }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            if (!empty($parts)) { $candidates[] = trim($parts[0]); }
        }
    }
    if (!empty($_SERVER['REMOTE_ADDR'])) { $candidates[] = $_SERVER['REMOTE_ADDR']; }

    foreach ($candidates as $ip) {
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP)) { return $ip; }
    }
    return '0.0.0.0';
}

/** Blocklist helpers */
function ls_is_whitelisted($ip = null) {
    if ($ip === null) { $ip = ls_get_client_ip(); }
    $wl = get_option(LS_OPTION_WHITELIST, array());
    return in_array($ip, (array)$wl, true);
}
function ls_is_blocked($ip = null) {
    if ($ip === null) { $ip = ls_get_client_ip(); }
    $blocklist = get_option(LS_OPTION_BLOCKLIST, array());
    if (isset($blocklist[$ip])) {
        $entry = $blocklist[$ip];
        if (!empty($entry['until']) && time() < intval($entry['until'])) {
            return $entry;
        } else {
            unset($blocklist[$ip]); update_option(LS_OPTION_BLOCKLIST, $blocklist, false);
            if (ls_cf_enabled()) { ls_cf_unblock_ip($ip); }
        }
    }
    return false;
}
function ls_block_ip($ip, $minutes, $reason) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) { return; }
    if (ls_is_whitelisted($ip)) { return; }
    $blocklist = get_option(LS_OPTION_BLOCKLIST, array());
    $until = time() + max(1, intval($minutes)) * 60;
    $blocklist[$ip] = array('reason'=>sanitize_text_field($reason),'blocked_at'=>time(),'until'=>$until);
    update_option(LS_OPTION_BLOCKLIST, $blocklist, false);
    if (ls_cf_enabled()) { ls_cf_block_ip($ip, $reason); }
    do_action('lightshield_ip_blocked', $ip, $reason, $until);
}

/** Deny helper */
function ls_forbid_now($message = '') {
    status_header(403); nocache_headers(); header('Content-Type: text/plain; charset=utf-8');
    echo ($message ?: 'Access denied by LightShield Security.'); exit;
}

/** Occasional prune on load (cheap) */
add_action('plugins_loaded', function () {
    $k = 'ls_prune_tick';
    if (!get_transient($k)) { ls_prune_blocklist(); set_transient($k, 1, 300); }
    $ip = ls_get_client_ip();
    if (ls_is_whitelisted($ip)) { return; }

    if ($entry = ls_is_blocked($ip)) {
        $mins_left = max(1, floor(($entry['until'] - time())/60));
        ls_forbid_now('Access denied (' . $entry['reason'] . '). Try again in ~' . $mins_left . ' minute(s).');
    }

    $settings = get_option(LS_OPTION_SETTINGS, array());

    if (!empty($settings['disable_xmlrpc'])) {
        $is_xmlrpc = false;
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) { $is_xmlrpc = true; }
        if (isset($_SERVER['REQUEST_URI']) && stripos($_SERVER['REQUEST_URI'], 'xmlrpc.php') !== false) { $is_xmlrpc = true; }
        if ($is_xmlrpc) { ls_forbid_now('XML-RPC disabled.'); }
        add_filter('xmlrpc_enabled', '__return_false');
    }

    if (!empty($settings['block_bad_ua'])) {
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '';
        $bad = false;
        if ($ua === '' || $ua === '-') { $bad = true; }
        $patterns = array('sqlmap','acunetix','nikto','nessus','wpscanner','wpscan','curl','python-requests','libwww-perl','masscan','apachebench','scrapy','httpclient','winhttp','botnet','spammer');
        foreach ($patterns as $p) { if ($ua && strpos($ua, $p) !== false) { $bad = true; break; } }
        $allow_if_contains = array('googlebot','bingbot','yandex','duckduckgo','baiduspider');
        foreach ($allow_if_contains as $good) { if ($ua && strpos($ua, $good) !== false) { $bad = false; break; } }
        if ($bad) { ls_block_ip($ip, 60, 'Bad user-agent'); ls_forbid_now('Bad user-agent.'); }
    }

    if (!empty($settings['throttle_all'])) {
        if (!is_user_logged_in() || !current_user_can('manage_options')) {
            $limit = intval($settings['throttle_per_minute']);
            if ($limit > 0) {
                $key = 'ls_rl_' . md5($ip);
                $count = get_transient($key);
                if ($count === false) { $count = 0; }
                $count++;
                set_transient($key, $count, 60);
                if ($count > $limit) {
                    $bmin = max(5, intval($settings['login_block_minutes']));
                    ls_block_ip($ip, $bmin, 'Rate limit exceeded');
                    ls_forbid_now('Rate limit exceeded.');
                }
            }
        }
    }

    add_action('template_redirect', function () { if (is_author()) { wp_redirect(home_url('/'), 301); exit; } });
    add_filter('rest_endpoints', function ($endpoints) {
        if (isset($endpoints['/wp/v2/users'])) { $endpoints['/wp/v2/users'] = array(); }
        if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) { $endpoints['/wp/v2/users/(?P<id>[\d]+)'] = array(); }
        return $endpoints;
    });
});

/** Brute-force protection */
add_action('wp_login_failed', function ($username) {
    $ip = ls_get_client_ip();
    if (ls_is_whitelisted($ip)) { return; }
    $settings = get_option(LS_OPTION_SETTINGS, array());
    $limit = max(1, intval($settings['login_fail_limit'] ?? 5));
    $block_minutes = max(1, intval($settings['login_block_minutes'] ?? 15));
    $key = 'ls_lf_' . md5($ip);
    $fails = get_transient($key);
    if ($fails === false) { $fails = 0; }
    $fails++; set_transient($key, $fails, 15 * 60);
    if ($fails >= $limit) { ls_block_ip($ip, $block_minutes, 'Too many failed logins'); ls_forbid_now('Too many failed logins.'); }
});

/** Admin UI */
add_action('admin_menu', function () { add_menu_page('LightShield Security','LightShield','manage_options','lightshield-security','ls_render_admin_page','dashicons-shield-alt',59); });

function ls_admin_post_actions() {
    if (!current_user_can('manage_options')) { return; }
    if (empty($_POST['ls_action']) || !check_admin_referer('ls_save', 'ls_nonce')) { return; }
    $action = sanitize_text_field($_POST['ls_action']);

    if ($action === 'save_settings') {
        $settings = get_option(LS_OPTION_SETTINGS, array());
        $settings['trust_cloudflare']    = !empty($_POST['trust_cloudflare']) ? 1 : 0;
        $settings['disable_xmlrpc']      = !empty($_POST['disable_xmlrpc']) ? 1 : 0;
        $settings['block_bad_ua']        = !empty($_POST['block_bad_ua']) ? 1 : 0;
        $settings['throttle_all']        = !empty($_POST['throttle_all']) ? 1 : 0;
        $settings['login_fail_limit']    = max(1, intval($_POST['login_fail_limit'] ?? 5));
        $settings['login_block_minutes'] = max(1, intval($_POST['login_block_minutes'] ?? 15));
        $settings['throttle_per_minute'] = max(1, intval($_POST['throttle_per_minute'] ?? 120));
        update_option(LS_OPTION_SETTINGS, $settings, false);

        // Whitelist
        $raw = trim($_POST['whitelist'] ?? '');
        $wl = array();
        foreach (preg_split('/\r\n|\r|\n/', $raw) as $line) { $ip = trim($line); if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) { $wl[] = $ip; } }
        update_option(LS_OPTION_WHITELIST, array_values(array_unique($wl)), false);

        // Cloudflare settings
        $cf = get_option(LS_OPTION_CF, array());
        $cf['enabled'] = !empty($_POST['cf_enabled']) ? 1 : 0;
        $cf['zone_id'] = sanitize_text_field($_POST['cf_zone_id'] ?? '');
        $token = trim($_POST['cf_token'] ?? '');
        $clear = !empty($_POST['cf_clear_token']);
        if ($clear) { $cf['token'] = ''; }
        elseif ($token !== '') { $cf['token'] = $token; }
        update_option(LS_OPTION_CF, $cf, false);

        // prune now so UI is current
        ls_prune_blocklist();

        if ($err = get_transient('ls_cf_last_error')) { add_settings_error('ls_messages', 'ls_cf_error', esc_html($err), 'error'); delete_transient('ls_cf_last_error'); }
        add_settings_error('ls_messages', 'ls_settings_saved', 'Settings saved.', 'updated');
    }

    if ($action === 'unblock_ip') {
        $ip = sanitize_text_field($_POST['ip'] ?? '');
        $blocklist = get_option(LS_OPTION_BLOCKLIST, array());
        if (!empty($blocklist[$ip])) {
            unset($blocklist[$ip]); update_option(LS_OPTION_BLOCKLIST, $blocklist, false);
            if (ls_cf_enabled()) { ls_cf_unblock_ip($ip); }
            if ($err = get_transient('ls_cf_last_error')) { add_settings_error('ls_messages', 'ls_cf_error', esc_html($err), 'error'); delete_transient('ls_cf_last_error'); }
            add_settings_error('ls_messages', 'ls_ip_unblocked', 'IP unblocked: ' . esc_html($ip), 'updated');
        }
    }

    if ($action === 'block_ip') {
        $ip = sanitize_text_field($_POST['ip'] ?? '');
        $minutes = max(1, intval($_POST['minutes'] ?? 60));
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            ls_block_ip($ip, $minutes, 'Manual block');
            if ($err = get_transient('ls_cf_last_error')) { add_settings_error('ls_messages', 'ls_cf_error', esc_html($err), 'error'); delete_transient('ls_cf_last_error'); }
            add_settings_error('ls_messages', 'ls_ip_blocked', 'IP blocked: ' . esc_html($ip), 'updated');
        } else {
            add_settings_error('ls_messages', 'ls_ip_invalid', 'Invalid IP.', 'error');
        }
    }

    if ($action === 'cf_test') {
        if (!ls_cf_enabled()) {
            add_settings_error('ls_messages', 'ls_cf_error', 'Cloudflare not enabled or missing Zone ID/token.', 'error');
        } else {
            $test_ip = '203.0.113.1';
            $rid = ls_cf_block_ip($test_ip, 'LightShield test');
            if ($rid) {
                ls_cf_unblock_ip($test_ip);
                add_settings_error('ls_messages', 'ls_cf_ok', 'Cloudflare API test succeeded.', 'updated');
            } else {
                if ($err = get_transient('ls_cf_last_error')) { add_settings_error('ls_messages', 'ls_cf_error', esc_html($err), 'error'); delete_transient('ls_cf_last_error'); }
                else { add_settings_error('ls_messages', 'ls_cf_error', 'Cloudflare API test failed.', 'error'); }
            }
        }
    }

    if ($action === 'cf_sync_cleanup') {
        if (!ls_cf_enabled()) {
            add_settings_error('ls_messages', 'ls_cf_error', 'Cloudflare not enabled or missing Zone ID/token.', 'error');
        } else {
            $deleted = ls_cf_sync_cleanup();
            add_settings_error('ls_messages', 'ls_cf_ok', sprintf('Cloudflare sync complete. Removed %d stale LightShield rule(s).', intval($deleted)), 'updated');
        }
    }
}
add_action('admin_init', 'ls_admin_post_actions');

function ls_render_admin_page() {
    if (!current_user_can('manage_options')) { wp_die('Insufficient permissions'); }
    ls_prune_blocklist(); // ensure UI shows only active blocks

    $settings = get_option(LS_OPTION_SETTINGS, array());
    $blocklist = get_option(LS_OPTION_BLOCKLIST, array());
    $whitelist = get_option(LS_OPTION_WHITELIST, array());
    $cf = get_option(LS_OPTION_CF, array());
    $cf_map = get_option(LS_OPTION_CF_MAP, array());

    settings_errors('ls_messages'); ?>
    <div class="wrap">
        <h1>LightShield Security</h1>
        <p>A lightweight alternative to heavyweight security suites. Best used alongside Cloudflare/WAF.</p>

        <h2 class="title">Blocked IPs</h2>
        <table class="widefat striped">
            <thead><tr>
                <th>IP</th><th>Reason</th><th>Blocked</th><th>Expires</th><th>Edge (CF)</th><th>Action</th>
            </tr></thead>
            <tbody>
            <?php if (!empty($blocklist)): foreach ($blocklist as $ip => $entry): ?>
                <tr>
                    <td><?php echo esc_html($ip); ?></td>
                    <td><?php echo esc_html($entry['reason'] ?? ''); ?></td>
                    <td><?php echo !empty($entry['blocked_at']) ? esc_html(wp_date(get_option('date_format').' '.get_option('time_format'), intval($entry['blocked_at']))) : ''; ?></td>
                    <td><?php echo !empty($entry['until']) ? esc_html(wp_date(get_option('date_format').' '.get_option('time_format'), intval($entry['until']))) : ''; ?></td>
                    <td><?php echo !empty($cf_map[$ip]) ? '<span class="dashicons dashicons-cloud"></span>' : '&mdash;'; ?></td>
                    <td>
                        <form method="post" style="display:inline;">
                            <?php wp_nonce_field('ls_save', 'ls_nonce'); ?>
                            <input type="hidden" name="ls_action" value="unblock_ip">
                            <input type="hidden" name="ip" value="<?php echo esc_attr($ip); ?>">
                            <button class="button button-secondary">Unblock</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; else: ?>
                <tr><td colspan="6">No blocked IPs.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>

        <h3 style="margin-top:20px;">Manually Block an IP</h3>
        <form method="post">
            <?php wp_nonce_field('ls_save', 'ls_nonce'); ?>
            <input type="hidden" name="ls_action" value="block_ip">
            <input type="text" name="ip" placeholder="IP address" class="regular-text">
            <input type="number" name="minutes" min="1" step="1" value="60"> minutes
            <button class="button button-primary">Block</button>
        </form>

        <hr/>

        <h2 class="title">Settings</h2>
        <form method="post">
            <?php wp_nonce_field('ls_save', 'ls_nonce'); ?>
            <input type="hidden" name="ls_action" value="save_settings">

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row">Trust Cloudflare Headers</th>
                    <td><label><input type="checkbox" name="trust_cloudflare" value="1" <?php checked(1, intval($settings['trust_cloudflare'] ?? 0)); ?>> Use <code>CF-Connecting-IP</code> / <code>X-Forwarded-For</code> for client IP</label></td>
                </tr>
                <tr>
                    <th scope="row">Disable XML-RPC</th>
                    <td><label><input type="checkbox" name="disable_xmlrpc" value="1" <?php checked(1, intval($settings['disable_xmlrpc'] ?? 0)); ?>> Block all <code>xmlrpc.php</code> requests (except whitelisted IPs)</label></td>
                </tr>
                <tr>
                    <th scope="row">Block Bad/Empty User-Agents</th>
                    <td><label><input type="checkbox" name="block_bad_ua" value="1" <?php checked(1, intval($settings['block_bad_ua'] ?? 0)); ?>> Immediately block known bad or empty user-agents</label></td>
                </tr>
                <tr>
                    <th scope="row">Global Throttle (optional)</th>
                    <td>
                        <label><input type="checkbox" name="throttle_all" value="1" <?php checked(1, intval($settings['throttle_all'] ?? 0)); ?>> Throttle all requests per IP (unauthenticated)</label><br>
                        <label>Requests per minute: <input type="number" name="throttle_per_minute" min="10" step="1" value="<?php echo esc_attr(intval($settings['throttle_per_minute'] ?? 120)); ?>"></label>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Login Brute-Force Limit</th>
                    <td>
                        <label>Failed attempts: <input type="number" name="login_fail_limit" min="1" step="1" value="<?php echo esc_attr(intval($settings['login_fail_limit'] ?? 5)); ?>"></label><br>
                        <label>Block duration (minutes): <input type="number" name="login_block_minutes" min="1" step="1" value="<?php echo esc_attr(intval($settings['login_block_minutes'] ?? 15)); ?>"></label>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Whitelist IPs</th>
                    <td>
                        <textarea name="whitelist" rows="5" cols="55" placeholder="One IP per line"><?php echo esc_textarea(implode("\n", (array)$whitelist)); ?></textarea>
                        <p class="description">Whitelisted IPs are never blocked and bypass throttles/XML-RPC blocks.</p>
                    </td>
                </tr>

                <tr><th colspan="2"><hr></th></tr>

                <tr>
                    <th scope="row">Cloudflare Edge Blocking (optional)</th>
                    <td>
                        <?php $cf = get_option(LS_OPTION_CF, array()); ?>
                        <label><input type="checkbox" name="cf_enabled" value="1" <?php checked(1, intval($cf['enabled'] ?? 0)); ?>> Push blocks to Cloudflare (IP Access Rules)</label>
                        <p class="description">Requires Zone ID and an API token with permission to edit IP Access Rules for this zone.</p>
                        <p><strong>Token status:</strong> <?php echo !empty($cf['token']) ? '<span style="color:#2271b1;">Saved (hidden)</span>' : '<span style="color:#d63638;">Not set</span>'; ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Cloudflare Zone ID</th>
                    <td><input type="text" name="cf_zone_id" class="regular-text" value="<?php echo esc_attr($cf['zone_id'] ?? ''); ?>" placeholder="e.g. 23ab45cdef6789..."></td>
                </tr>
                <tr>
                    <th scope="row">Cloudflare API Token</th>
                    <td>
                        <input type="password" name="cf_token" class="regular-text" value="" autocomplete="new-password" placeholder="<?php echo (!empty($cf['token']) ? '****************' : 'Enter token'); ?>">
                        <label style="margin-left:10px;"><input type="checkbox" name="cf_clear_token" value="1"> Clear stored token</label>
                        <p class="description">Token should have permission: <code>Zone Firewall Access Rules: Edit</code>. Stored in your WordPress DB. We never display the saved token.</p>
                    </td>
                </tr>
            </table>

            <p>
                <button class="button button-primary">Save Changes</button>
                <button class="button" name="ls_action" value="cf_test" formmethod="post" formaction="<?php echo admin_url('admin.php?page=lightshield-security'); ?>">Test Cloudflare API</button>
                <button class="button" name="ls_action" value="cf_sync_cleanup" formmethod="post" formaction="<?php echo admin_url('admin.php?page=lightshield-security'); ?>" onclick="return confirm('Clean up stale LightShield rules at Cloudflare?');">Sync & Clean Cloudflare</button>
                <?php wp_nonce_field('ls_save', 'ls_nonce'); ?>
            </p>
        </form>
    </div>
<?php }
