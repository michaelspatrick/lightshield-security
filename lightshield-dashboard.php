<?php
/**
 * LightShield Dashboard (stats/graphs)
 * Place this next to lightshield-security.php
 */

if (!defined('ABSPATH')) { exit; }
if (!defined('LS_OPTION_LOG')) { define('LS_OPTION_LOG', 'ls_log'); }
define('LS_DASH_VER', '1.0.1');

/** Submenu: LightShield → Dashboard */
add_action('admin_menu', function () {
    add_submenu_page(
        'lightshield-security',
        'LightShield Dashboard',
        'Dashboard',
        'manage_options',
        'lightshield-security-dashboard',
        'ls_render_stats_dashboard'
    );
});

/** Scripts/styles for our page only */
add_action('admin_enqueue_scripts', function ($hook) {
    if (!current_user_can('manage_options')) { return; }
    if (!isset($_GET['page']) || $_GET['page'] !== 'lightshield-security-dashboard') { return; }

    // 1) Satisfy misbehaving plugins that assume datepicker exists on every admin screen.
    //    This resolves "Uncaught TypeError: ...datepicker is not a function".
    wp_enqueue_script('jquery-ui-datepicker');               // provides $.fn.datepicker
    wp_enqueue_style('wp-jquery-ui-dialog');                 // ships with WP; basic jQuery UI styling

    // 2) Chart.js (footer)
    wp_enqueue_script(
        'chartjs',
        'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js',
        array(),
        '4.4.1',
        true
    );

    // 3) Our tiny init handle that depends on chartjs; we'll inject inline code onto this.
    wp_register_script('ls-dashboard-init', '', array('chartjs'), LS_DASH_VER, true);
    wp_enqueue_script('ls-dashboard-init');
});

/** Build stats from the ring-buffer log */
function ls_stats_build($days = 30) {
    $days = max(7, min(180, intval($days)));
    $tz = function_exists('wp_timezone') ? wp_timezone() : new DateTimeZone(get_option('timezone_string') ?: 'UTC');

    $today = new DateTimeImmutable('now', $tz);
    $start = $today->setTime(0,0,0)->modify('-' . ($days - 1) . ' days');

    $labels = $keys = [];
    $denyByDay = $blockByDay = [];
    for ($i=0; $i<$days; $i++) {
        $d = $start->modify('+' . $i . ' days');
        $key = $d->format('Y-m-d');
        $labels[] = $d->format('M j');
        $keys[]   = $key;
        $denyByDay[$key]  = 0;
        $blockByDay[$key] = 0;
    }

    $log = get_option(LS_OPTION_LOG, []);
    if (!is_array($log)) { $log = []; }

    $totalDenied = 0; $totalBlocks = 0; $unique = [];
    $reasonCounts = $uriCounts = $ipCounts = $uaCounts = [];
    $cfPushes = 0;

    $denyActions  = ['deny','rest_deny'];
    $blockActions = ['block','cf_block'];

    foreach ($log as $e) {
        $ts = isset($e['ts']) ? intval($e['ts']) : 0;
        if ($ts <= 0) { continue; }
        $key = function_exists('wp_date') ? wp_date('Y-m-d', $ts, $tz) : date_i18n('Y-m-d', $ts);
        if (!isset($denyByDay[$key])) { continue; }

        $action = strtolower($e['action'] ?? '');
        $ip     = $e['ip'] ?? '';
        $reason = $e['reason'] ?? '';
        $uri    = $e['uri'] ?? '';
        $ua     = $e['ua']  ?? '';

        if (in_array($action, $denyActions, true)) {
            $denyByDay[$key]++; $totalDenied++;
            if ($ip) { $unique[$ip] = true; $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1; }
            if ($reason) { $reasonCounts[$reason] = ($reasonCounts[$reason] ?? 0) + 1; }
            if ($uri)    { $uriCounts[$uri]       = ($uriCounts[$uri] ?? 0) + 1; }
            if ($ua)     { $uaCounts[$ua]         = ($uaCounts[$ua] ?? 0) + 1; }
        }

        if (in_array($action, $blockActions, true)) {
            $blockByDay[$key]++; $totalBlocks++;
            if ($ip) { $unique[$ip] = true; $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1; }
            if ($reason) { $reasonCounts[$reason] = ($reasonCounts[$reason] ?? 0) + 1; }
            if ($action === 'cf_block') { $cfPushes++; }
        }
    }

    arsort($reasonCounts); arsort($ipCounts); arsort($uriCounts); arsort($uaCounts);

    return [
        'labels'        => array_values($labels),
        'denySeries'    => array_values(array_intersect_key($denyByDay, array_flip($keys))),
        'blockSeries'   => array_values(array_intersect_key($blockByDay, array_flip($keys))),
        'totalDenied'   => $totalDenied,
        'totalBlocks'   => $totalBlocks,
        'uniqueIPs'     => count($unique),
        'cfPushes'      => $cfPushes,
        'topReasons'    => array_slice($reasonCounts, 0, 10, true),
        'topIPs'        => array_slice($ipCounts,     0, 10, true),
        'topURIs'       => array_slice($uriCounts,    0, 12, true),
        'topUAs'        => array_slice($uaCounts,     0, 12, true),
    ];
}

/** Render the Dashboard page */
function ls_render_stats_dashboard() {
    if (!current_user_can('manage_options')) { wp_die('Insufficient permissions'); }

    $range = isset($_GET['range']) ? intval($_GET['range']) : 30;
    $range = max(7, min(180, $range));
    $s = ls_stats_build($range);

    $reasonLabels = array_keys($s['topReasons']);
    $reasonValues = array_values($s['topReasons']);
    ?>
    <div class="wrap">
        <h1>LightShield Dashboard</h1>
        <p>See how much work LightShield is doing to protect your site.</p>

        <form method="get" style="margin: 10px 0 15px;">
            <input type="hidden" name="page" value="lightshield-security-dashboard">
            <label for="ls-range">Range: </label>
            <select id="ls-range" name="range">
                <?php foreach ([7,14,30,60,90,120,180] as $d): ?>
                    <option value="<?php echo esc_attr($d); ?>" <?php selected($range, $d); ?>>Last <?php echo esc_html($d); ?> days</option>
                <?php endforeach; ?>
            </select>
            <button class="button">Update</button>
        </form>

        <style>
            .ls-cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:12px; }
            .ls-card { background:#fff; border:1px solid #dcdcde; border-radius:8px; padding:14px 16px; min-width:180px; flex:1; }
            .ls-card h3 { margin:0 0 8px; font-size:13px; font-weight:600; color:#1d2327; }
            .ls-card .num { font-size:22px; font-weight:700; }
            .ls-grid { display:grid; grid-template-columns: 1fr 1fr; gap:16px; }
            @media (max-width:1100px){ .ls-grid { grid-template-columns: 1fr; } }
            .ls-table { margin-top: 10px; }
            .ls-canvas-wrap { background:#fff; border:1px solid #dcdcde; border-radius:8px; padding:10px; }
            /* NEW: fixed-height wrapper for charts so Chart.js doesn't auto-stretch the page */
            .ls-chart { position: relative; height: 320px; }
            @media (max-width:1100px){ .ls-chart { height: 280px; } }
        </style>

        <div class="ls-cards">
            <div class="ls-card"><h3>Requests Denied (<?php echo esc_html($range); ?>d)</h3><div class="num"><?php echo esc_html(number_format_i18n($s['totalDenied'])); ?></div></div>
            <div class="ls-card"><h3>Blocks Created (<?php echo esc_html($range); ?>d)</h3><div class="num"><?php echo esc_html(number_format_i18n($s['totalBlocks'])); ?></div></div>
            <div class="ls-card"><h3>Unique IPs Touched (<?php echo esc_html($range); ?>d)</h3><div class="num"><?php echo esc_html(number_format_i18n($s['uniqueIPs'])); ?></div></div>
            <div class="ls-card"><h3>Cloudflare Edge Blocks (<?php echo esc_html($range); ?>d)</h3><div class="num"><?php echo esc_html(number_format_i18n($s['cfPushes'])); ?></div></div>
        </div>

        <div class="ls-grid">
            <div class="ls-canvas-wrap">
                <h2 style="margin-top:0;">Denied Requests per Day</h2>
                <div class="ls-chart"><canvas id="lsChartDeny"></canvas></div>
            </div>
            <div class="ls-canvas-wrap">
                <h2 style="margin-top:0;">Blocks Created per Day</h2>
                <div class="ls-chart"><canvas id="lsChartBlock"></canvas></div>
            </div>
        </div>

        <div class="ls-grid" style="margin-top:16px;">
            <div class="ls-canvas-wrap">
                <h2 style="margin-top:0;">Top Reasons</h2>
                <div class="ls-chart"><canvas id="lsChartReasons"></canvas></div>
            </div>
            <div class="ls-canvas-wrap">
                <h2 style="margin-top:0;">Top IPs (denies/blocks)</h2>
                <table class="widefat striped ls-table">
                    <thead><tr><th style="width:45%;">IP</th><th>Count</th></tr></thead>
                    <tbody>
                        <?php if (!empty($s['topIPs'])): foreach ($s['topIPs'] as $ip => $c): ?>
                            <tr><td><?php echo esc_html($ip); ?></td><td><?php echo esc_html(number_format_i18n($c)); ?></td></tr>
                        <?php endforeach; else: ?>
                            <tr><td colspan="2">No data.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="ls-row" style="margin-top:16px;">
            <div class="ls-col-50">
                <h2 style="margin-top:0;">Top Paths (denied)</h2>
                <table class="widefat striped ls-table">
                    <thead><tr><th>URI</th><th style="width:90px;">Count</th></tr></thead>
                    <tbody>
                        <?php if (!empty($s['topURIs'])): foreach ($s['topURIs'] as $uri => $c): ?>
                            <tr><td><code><?php echo esc_html($uri); ?></code></td><td><?php echo esc_html(number_format_i18n($c)); ?></td></tr>
                        <?php endforeach; else: ?>
                            <tr><td colspan="2">No data.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="ls-row" style="margin-top:16px;">
            <div class="ls-col-50">
                <h2 style="margin-top:0;">Top User-Agents (denied)</h2>
                <table class="widefat striped ls-table">
                    <thead><tr><th>User-Agent</th><th style="width:90px;">Count</th></tr></thead>
                    <tbody>
                        <?php if (!empty($s['topUAs'])): foreach ($s['topUAs'] as $ua => $c): ?>
                            <tr><td><?php echo esc_html($ua); ?></td><td><?php echo esc_html(number_format_i18n($c)); ?></td></tr>
                        <?php endforeach; else: ?>
                            <tr><td colspan="2">No data.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <?php

    // Data FIRST (before), so the init can read it.
    $chart = [
        'labels'      => $s['labels'],
        'denySeries'  => $s['denySeries'],
        'blockSeries' => $s['blockSeries'],
        'reasonLabels'=> array_values($reasonLabels),
        'reasonData'  => array_values($reasonValues),
    ];
    wp_add_inline_script('ls-dashboard-init', 'window.LS_DASH = ' . wp_json_encode($chart) . ';', 'before');

    // Init AFTER (depends on chartjs via handle)
$init_js = <<<JS
(function(){
  // Run once per page view
  function ready(fn){ if(document.readyState!=='loading'){ fn(); } else { document.addEventListener('DOMContentLoaded', fn); } }
  function boot(){
    if (typeof Chart === 'undefined') return;

    // One-shot guard — prevents duplicate inits (e.g., other scripts triggering twice)
    if (window.LS_DASH_BOOTED) return;
    window.LS_DASH_BOOTED = true;

    var D = window.LS_DASH || {labels:[],denySeries:[],blockSeries:[],reasonLabels:[],reasonData:[]};

    function getCtx(id){
      var el = document.getElementById(id);
      return el ? el.getContext('2d') : null;
    }
    function destroyIfExists(id){
      var el = document.getElementById(id);
      if (!el) return;
      var inst = Chart.getChart(el); // v3/v4 API: instance or undefined
      if (inst) inst.destroy();
    }

    // Ensure we don't re-use a canvas with an existing chart instance
    destroyIfExists('lsChartDeny');
    destroyIfExists('lsChartBlock');
    destroyIfExists('lsChartReasons');

    var c1 = getCtx('lsChartDeny'),
        c2 = getCtx('lsChartBlock'),
        c3 = getCtx('lsChartReasons');
    if (!c1 || !c2 || !c3) return;

    new Chart(c1,{
      type:'line',
      data:{ labels:D.labels, datasets:[{ label:'Denied', data:D.denySeries, borderWidth:2, tension:0.25, fill:false }]},
      options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ display:false }}, scales:{ x:{ grid:{ display:false }}, y:{ beginAtZero:true, ticks:{ precision:0 }}}}
    });

    new Chart(c2,{
      type:'bar',
      data:{ labels:D.labels, datasets:[{ label:'Blocks', data:D.blockSeries }]},
      options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ display:false }}, scales:{ x:{ grid:{ display:false }}, y:{ beginAtZero:true, ticks:{ precision:0 }}}}
    });

    new Chart(c3,{
      type:'doughnut',
      data:{ labels:D.reasonLabels, datasets:[{ data:D.reasonData }]},
      options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'right' }}, cutout:'50%'}
    });
  }
  ready(boot);
})();
JS;
wp_add_inline_script('ls-dashboard-init', $init_js, 'after');
}


