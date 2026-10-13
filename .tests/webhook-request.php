<?php
declare(strict_types=1);
set_error_handler(static function($n,$s,$f,$l){throw new ErrorException($s,0,$n,$f,$l);});
require_once __DIR__.'/../BatteryMonitor/Webhook.php';
$GLOBALS['authenticated']=true;
function IPS_InstanceExists($id): bool { return $id===900001; }
function IPS_GetInstance($id): array { return ['ModuleInfo'=>['ModuleID'=>'{7C5A3841-3F7B-4D2A-9E1C-5B6D8F9A0E12}']]; }
function IPS_GetProperty($id,$name) { return $name==='PortalEnabled' ? true : 'https://house.example:3777'; }
function SEC_IsPortalAuthenticated($id): bool { return $GLOBALS['authenticated']; }
final class RequestFixture {
    use BatteryMonitorWebhook;
    public int $InstanceID=900002;
    public float $threshold=30;
    public int $scans=0;
    public bool $warn=false,$emit=false;
    public array $debug=[];
    private function ReadPropertyBoolean($name): bool { return true; }
    private function ReadPropertyInteger($name): int { return 900001; }
    private function ReadAttributeString($name): string { return 'test-only-key'; }
    private function logDebug($message): void { $this->debug[]=$message; }
    public function SetThreshold(float $value): void {
        if (!is_finite($value)||$value<0||$value>100)throw new InvalidArgumentException('Invalid threshold.');
        $this->threshold=$value;
    }
    public function GetReport(): string { return json_encode(['threshold'=>$this->threshold,'rows'=>[],'below'=>[]]); }
    public function Scan(): string { $this->scans++;if($this->emit)echo 'diagnostic text';if($this->warn)trigger_error('Cannot auto-convert test warning',E_USER_WARNING);return $this->GetReport(); }
    public function response(array $server,string $body): array { return $this->webDispatch($server,[],$body); }
    public function csrf(): string { return $this->webCSRF(900001,(int)floor(time()/3600)); }
}
$count=0;
function check(bool $ok,string $reason): void { global $count;if(!$ok)throw new RuntimeException($reason);$count++; }
$m=new RequestFixture();$_COOKIE['SEC_PORTAL_V2_900001']='fixture-session';
$base=['REQUEST_METHOD'=>'POST','HTTP_HOST'=>'house.example:3777','HTTP_ORIGIN'=>'https://house.example:3777','HTTP_SEC_FETCH_SITE'=>'same-origin','HTTP_X_BATTERY_CSRF'=>$m->csrf()];
$body='{"action":"threshold","threshold":80}';
check($m->response($base+['CONTENT_TYPE'=>'application/json'],$body)['status']===200,'Standard PHP header');
$m->threshold=30;
check($m->response($base+['HTTP_CONTENT_TYPE'=>'application/json'],$body)['status']===200 && $m->threshold===80.0,'Symcon header accepts filter update');
check($m->response($base+['CONTENT_TYPE'=>'','HTTP_CONTENT_TYPE'=>'application/json'],'{"action":"scan"}')['status']===200 && $m->scans===1,'Empty standard key falls back for search');
check($m->response($base+['CONTENT_TYPE'=>'  ','HTTP_CONTENT_TYPE'=>' Application/JSON ; charset=UTF-8 '],$body)['status']===200,'Whitespace, mixed case and charset');
check($m->response($base+['CONTENT_TYPE'=>'text/plain','HTTP_CONTENT_TYPE'=>'application/json'],$body)['status']===415,'Conflicting standard header is not overridden');
check($m->response($base+['HTTP_CONTENT_TYPE'=>'text/plain'],$body)['status']===415,'Non-JSON Symcon header rejected');
check($m->response($base,$body)['status']===415,'Absent media type rejected');
check($m->response($base+['HTTP_CONTENT_TYPE'=>'application/json'],'not json')['status']===422,'Malformed JSON rejected');
check($m->response($base+['HTTP_CONTENT_TYPE'=>'application/json'],'')['status']===422,'Empty JSON body rejected');
check($m->response($base+['HTTP_CONTENT_TYPE'=>'application/json'],str_repeat('x',16385))['status']===413,'Request size limit');
$bad=$base;$bad['HTTP_X_BATTERY_CSRF']='bad';
check($m->response($bad+['HTTP_CONTENT_TYPE'=>'application/json'],$body)['status']===403,'CSRF remains enforced');
$bad=$base;$bad['HTTP_ORIGIN']='https://other.example';
check($m->response($bad+['HTTP_CONTENT_TYPE'=>'application/json'],$body)['status']===403,'Origin remains enforced');
$GLOBALS['authenticated']=false;
check($m->response($base+['HTTP_CONTENT_TYPE'=>'application/json'],$body)['status']===401,'Expired session remains blocked');
$GLOBALS['authenticated']=true;$m->warn=true;
$before=ob_get_level();ob_start();$response=$m->response($base+['HTTP_CONTENT_TYPE'=>'application/json'],'{"action":"scan"}');$output=ob_get_clean();
check($output===''&&$response['status']===503,'PHP warning cannot corrupt response');
check(json_decode($response['body'],true,512,JSON_THROW_ON_ERROR)['error']!=='','Warning yields structured error JSON');
check(count(array_filter($m->debug,static fn($s)=>str_contains($s,'Cannot auto-convert')))>0,'Warning recorded in Debug');
check(ob_get_level()===$before,'Output buffers restored');
$m->warn=false;$m->emit=true;ob_start();$response=$m->response($base+['HTTP_CONTENT_TYPE'=>'application/json'],'{"action":"scan"}');$output=ob_get_clean();
check($output===''&&$response['status']===200&&isset(json_decode($response['body'],true,512,JSON_THROW_ON_ERROR)['threshold']),'Incidental output cannot corrupt success JSON');
echo "Webhook JSON compatibility: $count assertions passed.\n";
