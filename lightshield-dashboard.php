<?php
/**
 * LightShield Dashboard (stats/graphs)
 * File: lightshield-dashboard.php
 * Drop this next to lightshield-security.php and add a one-line require in the main plugin.
 */

if (!defined('ABSPATH')) { exit; }

if (!defined('LS_OPTION_LOG')) {
    // Fallback just in case; the main plugin defines this already.
    define('LS_OPTION_LOG', 'ls_log');
}

define('LS_DASH_VER', '1.0.0');

/**
 * Add submenu: LightShield → Dashboard
 */
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

/**
 * Only load Chart.js on our page
 */
add_action('admin_enqueue_scripts', function ($hook) {
    if (!current_user_can('manage_options')) { return; }
    $on_our_page = isset($_GET['page']) && $_GET['page'] === 'lightshield-security-dashboard';
    if (!$on_our_page) { return; }

    // Chart.js (UMD) via jsDelivr CDN
    wp_enqueue_script(
        'chartjs',
        'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js',
        array(),
        '4.4.1',
        true
    );
});

/**
 * Utility: group and summarize log entries
 */
function ls_stats_build($days = 30) {
    $days = max(7, min(180, intval($days))); // clamp
    $tz = function_exists('wp_timezone') ? wp_timezone() : new DateTimeZone( get_option('timezone_string') ?: 'UTC' );

    $today = new DateTimeImmutable('now', $tz);
    $start = $today->setTime(0,0,0)->modify('-' . ($days - 1) . ' days'); // inclusive

    // Prepare day buckets
    $labels = array();         // e.g., "Aug 12"
    $keys   = array();         // YYYY-MM-DD
    $denyByDay  = array();
    $blockByDay = array();
    for ($i = 0; $i < $days; $i++) {
        $d = $start->modify('+' . $i . ' days');
        $key = $d->format('Y-m-d');
        $labels[] = $d->format('M j');
        $keys[]   = $key;
        $denyByDay[$key]  = 0;
        $blockByDay[$key] = 0;
    }

    $log = get_option(LS_OPTION_LOG, array());
    if (!is_array($log)) { $log = array(); }

    $totalDenied = 0;
    $totalBlocks = 0;
    $uniqueIPsDeniedOrBlocked = array();
    $reasonCounts = array();
    $uriCounts    = array();
    $ipCounts     = array();
    $uaCounts     = array();
    $cfPushes     = 0;

    // Which actions count in which bucket
    $denyActions  = array('deny', 'rest_deny');
    $blockActions = array('block', 'cf_block');

    foreach ($log as $e) {
        $ts = isset($e['ts']) ? intval($e['ts']) : 0;
        if ($ts <= 0) { continue; }

        // Convert to site day key
        $key = function_exists('wp_date') ? wp_date('Y-m-d', $ts, $tz) : date_i18n('Y-m-d', $ts);
        if (!isset($denyByDay[$key])) { continue; } // out of range

        $action = isset($e['action']) ? strtolower($e['action']) : '';
        $ip     = isset($e['ip']) ? $e['ip'] : '';
        $reason = isset($e['reason']) ? $e['reason'] : '';
        $uri    = isset($e['uri']) ? $e['uri'] : '';
        $ua     = isset($e['ua']) ? $e['ua'] : '';

        if (in_array($action, $denyActions, true)) {
            $denyByDay[$key]++;
            $totalDenied++;
            if ($ip !== '') { $uniqueIPsDeniedOrBlocked[$ip] = true; $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1; }
            if ($reason !== '') { $reasonCounts[$reason] = ($reasonCounts[$reason] ?? 0) + 1; }
            if ($uri !== '')    { $uriCounts[$uri] = ($uriCounts[$uri] ?? 0) + 1; }
            if ($ua  !== '')    { $uaCounts[$ua]  = ($uaCounts[$ua]  ?? 0) + 1; }
        }

        if (in_array($action, $blockActions, true)) {
            $blockByDay[$key]++;
            $totalBlocks++;
            if ($ip !== '') { $uniqueIPsDeniedOrBlocked[$ip] = true; $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1; }
            if ($reason !== '') { $reasonCounts[$reason] = ($reasonCounts[$reason] ?? 0) + 1; }
            if ($action === 'cf_block') { $cfPushes++; }
        }
    }

    // Sort top lists
    arsort($reasonCounts);
    arsort($ipCounts);
    arsort($uriCounts);
    arsort($uaCounts);

    // Build arrays for output
    $denySeries  = array_values(array_intersect_key($denyByDay, array_flip($keys)));
    $blockSeries = array_values(array_intersect_key($blockByDay, array_flip($keys)));

    return array(
        'labels'        => $labels,
        'denySeries'    => $denySeries,
        'blockSeries'   => $blockSeries,
        'totalDenied'   => $totalDenied,
        'totalBlocks'   => $totalBlocks,
        'uniqueIPs'     => count($uniqueIPsDeniedOrBlocked),
        'cfPushes'      => $cfPushes,
        'topReasons'    => array_slice($reasonCounts, 0, 10, true),
        'topIPs'        => array_slice($ipCounts,     0, 10, true),
        'topURIs'       => array_slice($uriCounts,    0, 10, true),
        'topUAs'        => array_slice($uaCounts,     0, 10, true),
    );
}

/**
 * Render admin page
 */
function ls_render_stats_dashboard() {
    if (!current_user_can('manage_options')) { wp_die('Insufficient permissions'); }

    $range = isset($_GET['range']) ? intval($_GET['range']) : 30;
    $range = max(7, min(180, $range));

    $stats = ls_stats_build($range);

    // Prepare pie data from reasons
    $reasonLabels = array_keys($stats['topReasons']);
    $reasonValues = array_values($stats['topReasons']);

    ?>
    <div class="wrap">
        <h1>LightShield Dashboard</h1>
        <p>See how much work LightShield is doing to protect your site.</p>

        <form method="get" style="margin: 10px 0 15px;">
            <input type="hidden" name="page" value="lightshield-security-dashboard">
            <label for="ls-range">Range: </label>
            <select id="ls-range" name="range">
                <?php foreach (array(7, 14, 30, 60, 90, 120, 180) as $d): ?>
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
        </style>

        <div class="ls-cards">
            <div class="ls-card">
                <h3>Requests Denied (<?php echo esc_html($range); ?>d)</h3>
                <div class="num"><?php echo esc_html(number_format_i18n($stats['totalDenied'])); ?></div>
            </div>
            <div class="ls-card">
                <h3>Blocks Created (<?php echo esc_html($range); ?>d)</h3>
                <div class="num"><?php echo esc_html(number_format_i18n($stats['totalBlocks'])); ?></div>
            </div>
            <div class="ls-card">
                <h3>Unique IPs Touched (<?php echo esc_html($range); ?>d)</h3>
                <div class="num"><?php echo esc_html(number_format_i18n($stats['uniqueIPs'])); ?></div>
            </div>
            <div class="ls-card">
                <h3>Cloudflare Edge Blocks (<?php echo esc_html($range); ?>d)</h3>
                <div class="num"><?php echo esc_html(number_format_i18n($stats['cfPushes'])); ?></div>
            </div>
        </div>

        <div class="ls-grid">
            <div class="ls-canvas-wrap">
                <h2 style="margin-top:0;">Denied Requests per Day</h2>
                <canvas id="lsChartDeny" height="120"></canvas>
            </div>
            <div class="ls-canvas-wrap">
                <h2 style="margin-top:0;">Blocks Created per Day</h2>
                <canvas id="lsChartBlock" height="120"></canvas>
            </div>
        </div>

        <div class="ls-grid" style="margin-top:16px;">
            <div class="ls-canvas-wrap">
                <h2 style="margin-top:0;">Top Reasons</h2>
                <canvas id="lsChartReasons" height="140"></canvas>
            </div>
            <div class="ls-canvas-wrap">
                <h2 style="margin-top:0;">Top IPs (denies/blocks)</h2>
                <table class="widefat striped ls-table">
                    <thead><tr><th style="width:45%;">IP</th><th>Count</th></tr></thead>
                    <tbody>
                        <?php if (!empty($stats['topIPs'])): foreach ($stats['topIPs'] as $ip => $c): ?>
                            <tr><td><?php echo esc_html($ip); ?></td><td><?php echo esc_html(number_format_i18n($c)); ?></td></tr>
                        <?php endforeach; else: ?>
                            <tr><td colspan="2">No data.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="ls-grid" style="margin-top:16px;">
            <div class="ls-canvas-wrap">
                <h2 style="margin-top:0;">Top Paths (denied)</h2>
                <table class="widefat striped ls-table">
                    <thead><tr><th>URI</th><th style="width:90px;">Count</th></tr></thead>
                    <tbody>
                        <?php if (!empty($stats['topURIs'])): 
                            $i = 0; foreach ($stats['topURIs'] as $uri => $c): $i++; if ($i>12) break; ?>
                            <tr><td><code><?php echo esc_html($uri); ?></code></td><td><?php echo esc_html(number_format_i18n($c)); ?></td></tr>
                        <?php endforeach; else: ?>
                            <tr><td colspan="2">No data.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            <div class="ls-canvas-wrap">
                <h2 style="margin-top:0;">Top User-Agents (denied)</h2>
                <table class="widefat striped ls-table">
                    <thead><tr><th>User-Agent</th><th style="width:90px;">Count</th></tr></thead>
                    <tbody>
                        <?php if (!empty($stats['topUAs'])):
                            $i = 0; foreach ($stats['topUAs'] as $ua => $c): $i++; if ($i>12) break; ?>
                            <tr><td><?php echo esc_html($ua); ?></td><td><?php echo esc_html(number_format_i18n($c)); ?></td></tr>
                        <?php endforeach; else: ?>
                            <tr><td colspan="2">No data.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <?php
        // Data for charts
        $chart = array(
            'labels'      => $stats['labels'],
            'denySeries'  => $stats['denySeries'],
            'blockSeries' => $stats['blockSeries'],
            'reasonLabels'=> $reasonLabels,
            'reasonData'  => $reasonValues,
        );
        ?>
        <script>
        window.LS_DASH = <?php echo wp_json_encode($chart); ?>;
        (function(){
            function makeLine(ctx, labels, data, title) {
                return new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: title,
                            data: data,
                            borderWidth: 2,
                            tension: 0.25,
                            fill: false
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            x: { grid: { display: false } },
                            y: { beginAtZero: true, ticks: { precision: 0 } }
                        }
                    }
                });
            }

            function makeBar(ctx, labels, data, title) {
                return new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: title,
                            data: data
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { display: false } },
                            y: { beginAtZero: true, ticks: { precision: 0 } }
                        }
                    }
                });
            }

            function makePie(ctx, labels, data, title) {
                return new Chart(ctx, {
                    type: 'doughnut',
                    data: { labels: labels, datasets: [{ data: data }] },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { position: 'right' } },
                        cutout: '50%'
                    }
                });
            }

            const D = window.LS_DASH || {labels:[],denySeries:[],blockSeries:[],reasonLabels:[],reasonData:[]};
            const c1 = document.getElementById('lsChartDeny').getContext('2d');
            const c2 = document.getElementById('lsChartBlock').getContext('2d');
            const c3 = document.getElementById('lsChartReasons').getContext('2d');

            makeLine(c1, D.labels, D.denySeries, 'Denied');
            makeBar (c2, D.labels, D.blockSeries, 'Blocks');
            makePie (c3, D.reasonLabels, D.reasonData, 'Reasons');
        })();
        </script>

        <p style="margin-top:12px;color:#646970;">
            <em>Notes:</em> “Denied” includes 403s from core rules (bad UA, patterns, 404/probe, rate-limit, existing block) and REST denials.
            “Blocks” counts newly created LightShield blocks (and Cloudflare rules, if enabled). Timezone is your site’s setting (Settings → General).
        </p>
    </div>
    <?php
}

