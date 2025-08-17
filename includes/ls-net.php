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
              //if (srcEl) srcEl.textContent = ' (from browser lookup)';
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


/**
 * Decide if a User-Agent should be blocked.
 * Strategy: allowlist (early exit) -> literal blacklist -> small regex blacklist.
 */
function ls_ua_is_bad(string $ua): array {
    // Normalize once for cheap, case-insensitive substring checks.
    $ua_lc = strtolower($ua);
    $why   = '';
    $tok   = '';

    // 0) Empty or placeholder UA => bad
    if ($ua === '' || $ua === '-') {
        return [true, 'empty-ua', ''];
    }

    // 1) Allowlist (cheap early exit). Add/remove to taste.
    static $ALLOW = [
        'googlebot','applebot','bingbot','yandexbot','duckduckgo','baiduspider','slurp',
        'ahrefsbot','semrushbot','mj12bot','facebookexternalhit','twitterbot','linkedinbot',
        'slackbot','pinterestbot','pingdom.com_bot','uptimerobot','betterstackbot',
        'cron-job.org','gptbot','chatgpt-user','claudebot','anthropic-ai','perplexitybot',
        'censys.io','shodan','bitsightbot','jetpack'
    ];
    foreach ($ALLOW as $ok) {
        if ($ok !== '' && strpos($ua_lc, $ok) !== false) {
            return [false, 'allow', $ok];
        }
    }

    // 2) Literal blacklist (fast path). Include only plain substrings (no regex metachars needed).
    //    This list combines common scanners plus a large subset of Perishable Press tokens.
    static $BAD_LITERALS = [
        // Common security/scanner tools and HTTP libs
        'sqlmap','acunetix','nikto','nessus','wpscan','wpscanner','masscan','nmap',
        'python-requests','libwww-perl','libwww','curl','wget','scrapy','java/','okhttp',
        'apachebench','ab/','go-http-client','httpclient','winhttp','winhttprequest','lwp',
        'mechanize','urllib','aiohttp','restsharp','http-get',' httpget',
        // Generic/abusive
        'botnet','spammer','crawler0','download', 'sitecrawler','grabber','copier','reaper',
        'proxy','vacuum','spiderbot','webzip','webcopier','webstripper','website.quester',
        'webdownloader','websucker','websnake','webfetch','webhook','libwhisker',
        // Perishable Press (selected literals that are meaningful substrings)
        'alexibot','almaden','atomz','autoemailspider','autohttp','backdoorbot','backstreet',
        'backweb','badass','baid','bandit','basichttp','bdfetch','bigfoot','bilgi','bitacle',
        'black.hole','blackwidow','blogshares.spiders','bmclient','boitho','bookmark.search.tool',
        'botalot','botpaidtoclick','brandwatch','browsex','browsezilla','bsalsa','bumblebee',
        'cafek','cisco','clshttp','coldfusion','commentreader','core-project','cr4nk','crank',
        'craft','crawler0','cshttp','cyberalert','daobot','dark','digger','digimarc','discobot',
        'dnloadmage','dotbot','doubanbot','dreampassport','dsurf','dtaagent','dts','dynaweb',
        'earthcom','easydl','emailcollector','emailsearch','emailsiphon','emailwolf',
        'enterprise_search','envolk','exabot','exploit','extractorpro','fastlwspider',
        'favorites.sweeper','filehound','firebat','flickbot','fooy','forex','franklin.locator',
        'freshdownload','frontpage','fsurf','fyber','galaxybot','gamespy_arcade','ginxbot',
        'go.zilla','goldfire','got-it','goforit','gosearch','grabnet','grub','grub-client',
        'gsearch','guidebot','gvfs','hippo','homepagesearch','houxoucrawler','hpprint','htdig',
        'httpretriever','httrack','hybrid','ia_archiver','ibm_planetwide','ichiro','idbot',
        'ieauto','iemp','igetter','iltrov','image.stripper','image.sucker','imagefetch',
        'incywincy','industry.program','ineturl','infonav','insuran.','intelliseek','interget',
        'internet.ninja','internetlinkagent','internetseer.com','irlbot','isc_sys','isilo',
        'isrccrawler','isspi','iupui.research.bot','jeteye','joc','kapere','kenjin','kernel',
        'kfsw','krug','ksibot','kwebget','larbin','leech','leechftp','leechget','libcrawl',
        'libcurl','libfetch','libghttp','libweb','lightningdownload','link.sleuth','linkscan',
        'linktiger','linkwalker','lmq','lnspiderguy','localcombot','lwp-request','lwp-trivial',
        'magnet','mail.sweeper','majestic','mcspider','mediapartners', // caution: Google AdSense uses this, keep in ALLOW if needed
        'megaupload','metaspin','microsoft.url','mirror','missigua.locator','mj12','mlbot',
        'mmmo.crawl','mnog','moreoverbot','mothra/netscan','movabletype','mozdex','mp3bot',
        'msfrontpage','msiecrawler','msnptc','msrbot','multithreaddb','netants','netcarta',
        'netcraft','netcrawl','netmech','netprospector','netresearchserver','net.vampire',
        'newlisp','newt','nikto','npbot','nutch','nutex','offline.explorer','offline.navigator',
        'openbot','opentextsitecrawler','orangebot','orbit','pagegrabber','pansci','persona',
        'php.vers','phpot','pingalink','playstarmusic','poe-com','powerset','privoxy',
        'progressive.download','propowerbot','prowebwalker','prozilla','psbot','psurf',
        'psycheclone','puxarapido','pycurl','pyq','query','rambler','realdownload','relevantnoise',
        'retriever','rob o z','rover','rpt-http','rsync','sapo','sbider','scagent','scooter',
        'searchhippo','searchme','searchpreview','seekbot','seeker','sensis','sharp','shopwiki',
        'sicklebot','sitesnagger','sitesucker','sitevigil','slurp y.verifier','smartdownload',
        'snag','snake','snapbot','snoop','soc sci','sogou','solr','sootle','spacebison',
        'sphider','spiderengine','spiderview','spurl','spyder','sq.webscanner','sqworm',
        'ssm_ag','statbot','strip','studybot','subot','suck','sunrise','superbot','superhttp',
        'surfbot','surfwalker','suz u','sweep','syncrisis','szukacz','talkro','tarantula',
        'tarspider','teamsoft','teleport','telesoft','tencent','terrawiz','texnut','the.nomad',
        'tmcrawler','to crawl','tongco','torrent','true','tutor gig','tv33_mercator','twat',
        'twisted.pagegetter','ucmore','udmsearch','ultraseek','universalfeedparser','upg1',
        'utilmind','url_spider_pro','urldispatcher','urlgetfile','urlspiderpro','urly',
        'user-agent','useragent','vacuum','valet','veri~li','viewer','virtual','visibilitygap',
        'voilabot','voyager','vspider','w3c','walhello','wapt','wavefire','wbdbot','web.by.mail',
        'web.data.extractor','web.downloader','web.mole','web.sucker','web2mal','web2wap',
        'webaltbot','webauto','webbandit','webbot','webcapture','webcat','webcollage',
        'webcollector','webcopier','webcopy','webcor','webdav','webdevil','webdup','webemail',
        'webenhancer','webfountain','weblea','webmirror','webmole','webpin','webpix','webreaper',
        'webripper','webrobot','websauger','webtre','webvac','webwalk','webwasher','webweasel',
        'webwhacker','webzip','werelatebot','whack','whacker','widow','winht','winhttprequest',
        'winhttrack','wisebot','wisenutbot','wizz','wordp','works','world','wweb','www-collector',
        'www.mechanize','www.ranks.nl','wwwster','xaldon','xenu','xget','ytunnel','zade','zbot',
        'zeal','zebot','zeus','zipcode','zixy','zmao','zyborg',
    ];

    foreach ($BAD_LITERALS as $lit) {
        if ($lit !== '' && strpos($ua_lc, $lit) !== false) {
            return [true, 'literal', $lit];
        }
    }

    // 3) Regex blacklist (only for tokens that require anchors/special chars)
    //    Keep this *small*. All patterns are lower-case (we matched against $ua, not $ua_lc, to keep anchors precise).
    static $BAD_REGEX = '~
        (?:                                  # group of alternatives
            ^attach                           # starts with "attach"
          | ^da$                              # exactly "da"
          | ^java                             # starts with "java"
          | ^mozilla$                         # exactly "mozilla"
          | mozilla/1\.22
          | mozilla/22
          | ^mozilla/3\.0\.\(compatible
          | mozilla/4\.0\(compatible
          | mozilla/4\.08
          | mozilla/4\.61\.\(macintosh
          | firefox\.2\.0
          | iexplore\.exe
          | char\(32,35\)
          | google\.wireless\.transcoder
          | googlebot\-image
          | go\.zilla
          | \+select\+                        # SQLi probes
          | \+union\+                         # SQLi probes
          | 1,1,1,                            # suspicious UA marker
          | ^gotit$                           # exactly "gotit"
          | gsa\-cra
          | msnbot\-media
          | msnbot\-products
          | www\.ranks\.nl
        )
    ~i';

    if (preg_match($BAD_REGEX, $ua)) {
        return [true, 'regex', 'pattern'];
    }

    // Passed all checks
    return [false, '', ''];
}
