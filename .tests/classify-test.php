<?php
declare(strict_types=1);
set_error_handler(static function($n,$s,$f,$l){ throw new ErrorException($s,0,$n,$f,$l); });
require_once __DIR__.'/../BatteryMonitor/Discovery.php';
function check(bool $condition,string $message): void { if (!$condition) throw new RuntimeException($message); }
check(BatteryDiscovery::classify('LOWBAT','LOWBAT','~Battery',[],[],0)['kind']==='low','Homematic LOWBAT');
check(BatteryDiscovery::classify('LOW_BAT','LOW_BAT','~Battery',[],[],0)['kind']==='low','Homematic LOW_BAT');
check(BatteryDiscovery::classify('Batterie','batteryStatus_percentage','~Battery.100',['Associations'=>[['Value'=>0]]],[],1)['kind']==='percent','Battery profile with associations');
check(BatteryDiscovery::classify('Batteriespannung','BATTERY_STATE','~Volt',[],[],2)['kind']==='voltage','Homematic BATTERY_STATE must not be percent');
check(BatteryDiscovery::classify('Battery','Battery','Tempest_volt',['Suffix'=>' V'],[],2)['kind']==='voltage','Tempest voltage');
check(BatteryDiscovery::classify('Battery Status','Battery_Status','Tempest_battery_status',['Associations'=>[['Value'=>0],['Value'=>1]]],[],1)['kind']==='status','Tempest charge state');
check(BatteryDiscovery::classify('ERROR_BATTERY','ERROR_BATTERY','',[],[],1)['kind']==='status','Homematic battery error');
check(BatteryDiscovery::classify('Battery %','Dabc_Battery','',[],[],1)['kind']==='percent','FRITZ percent without profile');
check(BatteryDiscovery::classify('Battery Status','','',[],[],1)['kind']==='candidate','Unknown status must not silently become percent');
check(BatteryDiscovery::percent(0,100)===0.0,'Zero is a valid measured charge');
check(BatteryDiscovery::percent(101,100)===null,'Out of range');
check(BatteryDiscovery::percent(0.2,1)===20.0,'Fraction conversion');
$rows=[['kind'=>'percent','percent'=>29.9,'updated'=>1],['kind'=>'percent','percent'=>30,'updated'=>1],['kind'=>'percent','percent'=>0,'updated'=>0],['kind'=>'percent','percent'=>0,'updated'=>1]];
check(count(BatteryDiscovery::below($rows,30))===2,'Strict below and never-updated exclusion');
echo "PASS: battery classification, Homematic flags, valid ranges, fraction conversion and strict filter".PHP_EOL;
