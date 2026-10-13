<?php
declare(strict_types=1);

/** HTTPS-only, passkey-protected battery monitoring dashboard. */
trait BatteryMonitorWebhook
{
    private const WEBHOOK_CONTROL = '{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}';
    private const PORTAL_VAULT = '{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}';

    private function webPath(): string
    {
        return '/hook/battery_monitor_' . $this->InstanceID;
    }

    private function webOrigin(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https'
            || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])
            || !in_array($parts['path'] ?? '', ['', '/'], true)) return '';
        return 'https://' . strtolower($parts['host'])
            . ((int)($parts['port'] ?? 443) === 443 ? '' : ':' . $parts['port']);
    }

    private function webVault(): int
    {
        $selected = $this->ReadPropertyInteger('VaultInstanceID');
        $candidates = $selected > 0 ? [$selected] : IPS_GetInstanceListByModuleID(self::PORTAL_VAULT);
        $eligible = [];
        foreach ($candidates as $id) {
            $id = (int)$id;
            if (!IPS_InstanceExists($id)) continue;
            try {
                if (strtoupper((string)IPS_GetInstance($id)['ModuleInfo']['ModuleID']) !== self::PORTAL_VAULT
                    || IPS_GetProperty($id, 'PortalEnabled') !== true
                    || $this->webOrigin((string)IPS_GetProperty($id, 'PortalOrigin')) === '') continue;
                $eligible[] = $id;
            } catch (Throwable $e) { continue; }
        }
        return count($eligible) === 1 ? $eligible[0] : 0;
    }

    public function SetupHook(): void
    {
        $this->SetTimerInterval('HookSetup', 0);
        if (IPS_GetKernelRunlevel() !== 10103) return;
        if (!IPS_SemaphoreEnter('ALPORT.WebhookControl', 1000)) {
            $this->SetTimerInterval('HookSetup', 1500);
            $this->logDebug('WebhookControl busy, retry scheduled.');
            return;
        }
        try {
            $ids = IPS_GetInstanceListByModuleID(self::WEBHOOK_CONTROL);
            if (count($ids) !== 1 || IPS_HasChanges((int)$ids[0])) {
                throw new RuntimeException('WebhookControl unavailable or pending changes.');
            }
            $id = (int)$ids[0];
            $current = json_decode((string)IPS_GetProperty($id, 'Hooks'), true);
            if (!is_array($current) || array_values($current) !== $current) {
                throw new RuntimeException('Invalid webhook registry.');
            }
            $path = $this->webPath();
            $enabled = $this->ReadPropertyBoolean('WebEnabled');
            $next = [];
            $found = false;
            foreach ($current as $entry) {
                if (($entry['Hook'] ?? '') === $path) {
                    if ((int)($entry['TargetID'] ?? 0) !== $this->InstanceID) {
                        throw new RuntimeException('Webhook path already belongs to another object.');
                    }
                    if (!$enabled || $found) continue;
                    $found = true;
                }
                $next[] = $entry;
            }
            if ($enabled && !$found) $next[] = ['Hook' => $path, 'TargetID' => $this->InstanceID];
            if ($next !== $current) {
                IPS_SetProperty($id, 'Hooks', json_encode($next, JSON_THROW_ON_ERROR));
                IPS_ApplyChanges($id);
            }
            $this->SetValue('WebPath', $enabled ? $path : 'Web page disabled');
            $this->logDebug('Battery Monitor page webhook ' . ($enabled ? 'enabled' : 'disabled') . ': ' . $path);
        } catch (Throwable $e) {
            $this->SetValue('WebPath', 'Webhook setup failed: ' . $e->getMessage());
            $this->SetTimerInterval('HookSetup', 3000);
            $this->logDebug('Webhook setup failed: ' . $e->getMessage());
        } finally {
            IPS_SemaphoreLeave('ALPORT.WebhookControl');
        }
    }

    private function webCSRF(int $vault, int $slot): string
    {
        $cookie = (string)($_COOKIE['SEC_PORTAL_V2_' . $vault] ?? '');
        if ($cookie === '' || strlen($cookie) > 1024) throw new RuntimeException('Portal session cookie missing.');
        return $slot . ':' . hash_hmac('sha256',
            $this->webPath() . '|' . $vault . '|' . $cookie . '|' . $slot,
            $this->ReadAttributeString('WebCSRFKey'));
    }

    private function webValidPOST(array $server, int $vault): bool
    {
        $expected = $this->webOrigin('https://' . ($server['HTTP_HOST'] ?? ''));
        if ($expected === '' || $expected !== $this->webOrigin((string)IPS_GetProperty($vault, 'PortalOrigin'))
            || $this->webOrigin((string)($server['HTTP_ORIGIN'] ?? '')) !== $expected
            || ($server['HTTP_SEC_FETCH_SITE'] ?? 'same-origin') !== 'same-origin') return false;
        $token = (string)($server['HTTP_X_BATTERY_CSRF'] ?? '');
        $slot = (int)floor(time() / 3600);
        return $token !== '' && (
            hash_equals($this->webCSRF($vault, $slot), $token)
            || hash_equals($this->webCSRF($vault, $slot - 1), $token));
    }



    private function portalPath(): string
    {
        $id=$this->ReadPropertyInteger('PortalInstanceID');
        if ($id <= 0 || !IPS_InstanceExists($id)) return '';
        $module=IPS_GetInstance($id)['ModuleInfo']['ModuleName'] ?? '';
        return $module === 'AlarmPortal' ? '/hook/alarm_portal_'.$id : '';
    }
    public function ProcessHookData()
    {
        $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $body = $method === 'POST' ? (string)file_get_contents('php://input', false, null, 0, 16385) : '';
        $result = $this->webResponse($_SERVER, $_GET, $body);
        http_response_code($result['status']);
        foreach ($result['headers'] as $name=>$value) header($name . ': ' . $value);
        if ($method !== 'HEAD') echo $result['body'];
    }

    private function webResponse(array $server, array $query, string $body): array
    {
        $headers = [
            'Cache-Control'=>'private, no-store, max-age=0','Pragma'=>'no-cache',
            'X-Content-Type-Options'=>'nosniff','Referrer-Policy'=>'no-referrer',
            'X-Frame-Options'=>'DENY','Permissions-Policy'=>'camera=(), microphone=(), geolocation=()',
            'Content-Type'=>'application/json; charset=utf-8',
            'Content-Security-Policy'=>"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        ];
        $reply = static function(int $status, $data, array $extra=[]) use ($headers): array {
            return ['status'=>$status,'headers'=>array_replace($headers,$extra),
                'body'=>is_string($data) ? $data : json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)];
        };
        $method = strtoupper((string)($server['REQUEST_METHOD'] ?? 'GET'));
        if (!in_array($method, ['GET','HEAD','POST'], true)) return $reply(405, ['error'=>'Method not allowed'], ['Allow'=>'GET, HEAD, POST']);
        if (!$this->ReadPropertyBoolean('WebEnabled')) return $reply(503, ['error'=>'Battery Monitor page disabled.']);
        $vault = $this->webVault();
        if (!$vault || !function_exists('SEC_IsPortalAuthenticated')) return $reply(503, ['error'=>'A valid SecretsManager HTTPS portal is required.']);
        try {
            if (SEC_IsPortalAuthenticated($vault) !== true) {
                if ($method === 'GET' && !isset($query['view'])) {
                    return $reply(303, '', ['Location'=>'/hook/secrets_'.$vault.'?portal=1&return='.rawurlencode($this->webPath())]);
                }
                return $reply(401, ['error'=>'Passkey session required. Sign in again.']);
            }
            $expected = $this->webOrigin((string)IPS_GetProperty($vault, 'PortalOrigin'));
            if ($expected === '' || $this->webOrigin('https://' . ($server['HTTP_HOST'] ?? '')) !== $expected) {
                return $reply(403, ['error'=>'Open this page through the SecretsManager HTTPS portal origin.']);
            }
            if ($method === 'POST') {
                if (!$this->webValidPOST($server, $vault)) return $reply(403, ['error'=>'Invalid session-bound security token or origin.']);
                if (strlen($body) > 16384) return $reply(413, ['error'=>'Request too large.']);
                if (strtolower(trim(explode(';',(string)($server['CONTENT_TYPE'] ?? ''),2)[0])) !== 'application/json') {
                    return $reply(415, ['error'=>'JSON body required.']);
                }
                $data = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
                if (!is_array($data)) throw new InvalidArgumentException('Invalid JSON body.');

                if (array_diff(array_keys($data), ['action','threshold'])) throw new InvalidArgumentException('Unknown request fields.');
                if (($data['action'] ?? '') === 'scan') {
                    if (isset($data['threshold'])) {
                        if (!is_int($data['threshold']) && !is_float($data['threshold'])) throw new InvalidArgumentException('Threshold must be numeric.');
                        $this->SetThreshold((float)$data['threshold']);
                    }
                    return $reply(200, json_decode($this->Scan(),true));
                }
                if (($data['action'] ?? '') === 'threshold' && (is_int($data['threshold'] ?? null) || is_float($data['threshold'] ?? null))) {
                    $this->SetThreshold((float)$data['threshold']);
                    return $reply(200,json_decode($this->GetReport(),true));
                }
                throw new InvalidArgumentException('Unsupported action.');
            }
            if (($query['view'] ?? '') === 'state') {
                return $reply(200,json_decode($this->GetReport(),true));
            }
            if (isset($query['view'])) return $reply(404, ['error'=>'Unknown view.']);
            $nonce = base64_encode(random_bytes(24));
            $escape = static function($value): string { return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); };
            $template = file_get_contents(__DIR__ . '/page.html');
            if ($template === false) throw new RuntimeException('Page template not found.');
            $html = strtr($template, [
                '{{NONCE}}'=>$escape($nonce),
                '{{PATH}}'=>$escape($this->webPath()),
                '{{CSRF}}'=>$escape($this->webCSRF($vault, (int)floor(time()/3600))),
                '{{INSTANCE}}'=>(string)$this->InstanceID,
                '{{PORTAL}}'=>$escape($this->portalPath())
            ]);
            return $reply(200, $html, [
                'Content-Type'=>'text/html; charset=utf-8',
                'Content-Security-Policy'=>"default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; connect-src 'self'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            ]);
        } catch (JsonException | InvalidArgumentException $e) {
            return $reply(422, ['error'=>$e->getMessage()]);
        } catch (Throwable $e) {
            $this->logDebug('Battery Monitor web request failed: ' . $e->getMessage());
            return $reply(503, ['error'=>'Request failed. Check the module Last Error / Debug variables or refresh the page.']);
        }
    }
}

