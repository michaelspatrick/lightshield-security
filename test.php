<?php
$bad = true;
$good = "";

$ua = "facebokexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)";

        $allow_if_contains = array('googlebot','applebot','bingbot','yandex','duckduckgo','baiduspider','slurp','yandexbot','ahrefsbot','semrushbot','mj12bot','facebookexternalhit',
                                   'twitterbot','linkedinbot','slackbot','pinterestbot','pingdom.com_bot','uptimerobot','betterstackbot','cron-job.org','gptbot','chatgpt-user',
                                   'claudebot','anthropic-ai','perplexitybot','censys.io','shodan','bitsightbot','jetpack'
                                  );

        foreach ($allow_if_contains as $good) { if ($ua && stripos($ua, $good) !== false) { $bad = false; break; } }
echo "BAD: ".$bad."\n";
?>
