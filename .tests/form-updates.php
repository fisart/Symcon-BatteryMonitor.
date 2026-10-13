<?php
declare(strict_types=1);
set_error_handler(static function($n,$s,$f,$l){throw new ErrorException($s,0,$n,$f,$l);});
class IPSModule {
    public int $InstanceID=900002;
    public array $values=['Threshold'=>30.0,'LastScan'=>'2026-10-13T12:00:00+02:00','Debug'=>''];
    public array $attributes=['Inventory'=>'[]'];
    public array $fields=[];
    public function GetValue($key){return $this->values[$key];}
    public function SetValue($key,$value): void {$this->values[$key]=$value;}
    public function ReadAttributeString($key): string {return $this->attributes[$key];}
    public function ReadPropertyInteger($key): int {return 30;}
    public function ReadPropertyBoolean($key): bool {return false;}
    public function UpdateFormField($key,$parameter,$value): void {
        if (is_array($value)||is_object($value)) throw new RuntimeException('Cannot auto-convert complex form value; use JSON.');
        $this->fields[$key][$parameter]=$value;
    }
}
require_once __DIR__.'/../BatteryMonitor/module.php';
function check(bool $ok,string $reason): void {if(!$ok)throw new RuntimeException($reason);}
$m=new BatteryMonitor();
$m->attributes['Inventory']=json_encode([
 ['id'=>900010,'path'=>'Test device / Battery','kind'=>'percent','percent'=>21.0,'updated'=>1791880000,'stale'=>false],
 ['id'=>900011,'path'=>'Test Homematic / LOWBAT','kind'=>'low','percent'=>null,'updated'=>1791880000,'value'=>true]
]);
$m->SetThreshold(30.0);
check(is_string($m->fields['BatteryRows']['values']),'Percentage table must use JSON string');
$below=json_decode($m->fields['BatteryRows']['values'],true,512,JSON_THROW_ON_ERROR);check(count($below)===1&&$below[0]['id']===900010,'Percentage rows preserved');
$other=json_decode($m->fields['OtherRows']['values'],true,512,JSON_THROW_ON_ERROR);check(count($other)===1&&$other[0]['kind']==='low','Homematic warning rows preserved');
$m->SetThreshold(21.0);check($m->fields['BatteryRows']['values']==='[]','Empty filtered table must use JSON list');
check($m->values['BelowCount']===0&&$m->values['FoundCount']===1,'Status variables remain correct');
echo "Form update scalar/JSON compatibility: 5 assertions passed.\n";
