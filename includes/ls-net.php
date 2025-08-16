<?php
if (!defined('ABSPATH')) exit;

/** ========== Hard-coded whitelist defaults ========== */
if (!defined('LS_HARDCODED_WHITELIST_CIDRS')) {
    define('LS_HARDCODED_WHITELIST_CIDRS', json_encode([
        // Local
        '127.0.0.1',
        '::1',
        // WordPress Jetpack
        '122.248.245.244/32',
        '54.217.201.243/32',
        '54.232.116.4/32',
        '192.0.80.0/20',
        '192.0.96.0/20',
        '192.0.112.0/20',
        '195.234.108.0/22',
        '192.0.64.0/18',
    ]));
}

/** ========== CIDR helpers (guarded) ========== */
if (!function_exists('ls_is_ip')) {
    function ls_is_ip($ip){ return (bool) filter_var($ip, FILTER_VALIDATE_IP); }
}
if (!function_exists('ls_is_ipv6')) {
    function ls_is_ipv6($ip){ return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6); }
}
if (!function_exists('ls_normalize_cidr')) {
    function ls_normalize_cidr($raw){
        $raw = trim((string)$raw);
        if ($raw === '') return '';
        if (preg_match('/^\d{1,3}(?:\.\d{1,3}){3}\.\d{1,2}$/', $raw)) {
            $raw = preg_replace('/\.(\d{1,2})$/', '/$1', $raw);
        }
        return $raw;
    }
}
if (!function_exists('ls_single_ip_to_cidr')) {
    function ls_single_ip_to_cidr($ip){
        if (!ls_is_ip($ip)) return '';
        return $ip . (ls_is_ipv6($ip) ? '/128' : '/32');
    }
}
if (!function_exists('ls_cidr_to_explicit')) {
    function ls_cidr_to_explicit($item){
        $item = ls_normalize_cidr($item);
        if ($item === '') return '';
        return (strpos($item, '/') === false) ? ls_single_ip_to_cidr($item) : $item;
    }
}
if (!function_exists('ls_cidr_is_valid')) {
    function ls_cidr_is_valid($item){
        $item = ls_normalize_cidr($item);
        if ($item === '') return false;
        if (strpos($item, '/') === false) return ls_is_ip($item);
        list($ip,$prefix) = explode('/', $item, 2);
        $bin = @inet_pton($ip);
        if ($bin === false || $prefix === '') return false;
        $prefix = (int)$prefix;
        $max = (strlen($bin) === 4) ? 32 : 128;
        return ($prefix >= 0 && $prefix <= $max);
    }
}
if (!function_exists('ls_ip_in_cidr')) {
    function ls_ip_in_cidr($ip, $cidr){
        if (!ls_is_ip($ip)) return false;
        $cidr = ls_cidr_to_explicit($cidr);
        list($net,$prefix) = explode('/', $cidr, 2);
        $netBin = @inet_pton($net);
        $ipBin  = @inet_pton($ip);
        if ($netBin === false || $ipBin === false) return false;
        if (strlen($netBin) !== strlen($ipBin)) return false;
        $prefix = (int)$prefix;
        $bytes = intdiv($prefix, 8);
        $bits  = $prefix % 8;
        if ($bytes > 0 && substr($netBin, 0, $bytes) !== substr($ipBin, 0, $bytes)) return false;
        if ($bits === 0) return true;
        $mask = chr((~(0xff >> $bits)) & 0xff);
        return (ord($ipBin[$bytes]) & ord($mask)) === (ord($netBin[$bytes]) & ord($mask));
    }
}

/** ========== Merged whitelist (hard-coded + UI) ========== */
if (!function_exists('ls_whitelist_cidrs')) {
    function ls_whitelist_cidrs(){
        $hard = json_decode(LS_HARDCODED_WHITELIST_CIDRS, true) ?: array();
        $ui   = get_option(LS_OPTION_WHITELIST, array());
        if (!is_array($ui)) $ui = preg_split('/[\r\n,]+/', (string)$ui);
        $merged = array_merge($hard, $ui);
        $out = array();
        foreach ($merged as $item) {
            $explicit = ls_cidr_to_explicit($item);
            if ($explicit && ls_cidr_is_valid($explicit)) $out[$explicit] = true;
        }
        return array_keys($out);
    }
}

/** ========== Save sanitizer (accept IPs or CIDR) ========== */
add_filter('pre_update_option_' . LS_OPTION_WHITELIST, function ($new, $old) {
    if (is_string($new)) $new = preg_split('/\r\n|\r|\n|,/', $new);
    $out = array();
    foreach ((array)$new as $item) {
        $explicit = ls_cidr_to_explicit($item);
        if ($explicit && ls_cidr_is_valid($explicit)) $out[$explicit] = true;
    }
    return array_keys($out);
}, 10, 2);

// Show IPs on LightShield pages; enhance IPv4 via client-side lookup
add_action('admin_notices', function () {
    if (!is_user_logged_in() || !function_exists('get_current_screen')) return;
    $screen = get_current_screen();
    $allowed = [
        'toplevel_page_lightshield-security',
        'lightshield_page_lightshield-security-dashboard',
        'lightshield_page_lightshield-security-log',
        'lightshield-security_page_lightshield-security-settings',
    ];
    if (!$screen || !in_array($screen->id, $allowed, true)) return;
    if (!current_user_can('manage_options')) return;

    // Server-side values (what PHP can actually see on THIS request)
    $primary = function_exists('ls_get_client_ip') ? ls_get_client_ip() : ($_SERVER['REMOTE_ADDR'] ?? '');
    $ipv6 = filter_var($primary, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? $primary : '';
    $ipv4 = filter_var($primary, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? $primary : '';

    echo '<div class="notice notice-info"><p><strong>Your IPs</strong> — Primary: <code>'
        . esc_html($primary ?: '—') . '</code> &nbsp; IPv4: <code id="ls-ipv4">'
        . esc_html($ipv4 ?: '…') . '</code> &nbsp; IPv6: <code>'
        . esc_html($ipv6 ?: '—') . '</code>'
        . ' <span id="ls-ipv4-src" style="opacity:.7;"></span>'
        . '</p></div>';

    // Inline JS: fetch public IPv4 via IPv4-only endpoints (browser -> provider)
    ?>
    <script>
    (function(){
      // Only replace if PHP didn't already supply a real v4
      var v4El = document.getElementById('ls-ipv4');
      var srcEl = document.getElementById('ls-ipv4-src');
      if (!v4El) return;
      var current = (v4El.textContent || '').trim();
      var ipv4Pattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
      if (ipv4Pattern.test(current)) { // PHP already showed v4
        if (srcEl) srcEl.textContent = ' (from server)';
        return;
      }

      // Providers that respond over IPv4-only hostnames
      // We’ll race a few; first success wins.
      var providers = [
        { url: 'https://ipv4.icanhazip.com', parse: t => t.trim() },
        { url: 'https://v4.ident.me',        parse: t => t.trim() },
        { url: 'https://api.ipify.org?format=json&v=4', parse: t => (JSON.parse(t).ip || '').trim() },
        // As a last resort, CF trace (may return v6 depending on path)
        { url: 'https://www.cloudflare.com/cdn-cgi/trace', parse: t => {
            var m = t.match(/^ip=([^\n\r]+)/m); return m ? m[1].trim() : '';
          }
        }
      ];

      function fetchText(p){
        return fetch(p.url, { cache: 'no-store', credentials: 'omit' })
          .then(r => r.ok ? r.text() : Promise.reject(new Error('HTTP '+r.status)))
          .then(txt => ({ ok:true, ip: p.parse(txt) }))
          .catch(() => ({ ok:false, ip:'' }));
      }

      var done = false;
      (async function run(){
        for (var i=0; i<providers.length && !done; i++){
          try {
            var res = await fetchText(providers[i]);
            if (res.ok && ipv4Pattern.test(res.ip)) {
              v4El.textContent = res.ip;
              if (srcEl) srcEl.textContent = ' (from browser lookup)';
              done = true;
              return;
            }
          } catch(e){}
        }
        if (!done && srcEl) srcEl.textContent = ' (IPv4 not present on this request)';
      })();
    })();
    </script>
    <?php
});

