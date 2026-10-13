<?php
declare(strict_types=1);
require_once __DIR__ . '/Discovery.php';
require_once __DIR__ . '/Webhook.php';

class BatteryMonitor extends IPSModule
{
    use BatteryMonitorWebhook;

    public function Create(): void
    {
        parent::Create();
        $this->RegisterPropertyFloat('DefaultThreshold',30.0);
        $this->RegisterPropertyInteger('StaleDays',30);
        $this->RegisterPropertyInteger('RefreshMinutes',0);
        $this->RegisterPropertyBoolean('WebEnabled',true);
        $this->RegisterPropertyInteger('VaultInstanceID',0);
        $this->RegisterPropertyInteger('PortalInstanceID',0);
        $this->RegisterPropertyBoolean('DebugEnabled',true);
        $this->RegisterPropertyString('Overrides','[]');
        $this->RegisterAttributeString('Inventory','[]');
        $this->RegisterAttributeString('LastDefault','');
        $this->RegisterAttributeString('WebCSRFKey',bin2hex(random_bytes(32)));
        $this->RegisterVariableFloat('Threshold','Show charge below (%)','',10);
        $this->RegisterVariableBoolean('Search','Search all battery variables','~Switch',20);
        $this->RegisterVariableInteger('FoundCount','Battery percentage variables','',30);
        $this->RegisterVariableInteger('BelowCount','Readings below threshold','',40);
        $this->RegisterVariableString('Results','Filtered battery readings','~HTMLBox',50);
        $this->RegisterVariableString('LastScan','Last search','',60);
        $this->RegisterVariableString('WebPath','Battery page webhook path','',70);
        $this->RegisterVariableString('Debug','Debug','~TextBox',80);
        $this->EnableAction('Threshold');
        $this->EnableAction('Search');
        $this->RegisterTimer('HookSetup',0,'BATMON_SetupHook($_IPS["TARGET"]);');
        $this->RegisterTimer('Startup',0,'BATMON_Startup($_IPS["TARGET"]);');
        $this->RegisterTimer('Refresh',0,'BATMON_Scan($_IPS["TARGET"]);');
        $this->RegisterMessage(0,10103);
    }

    public function ApplyChanges(): void
    {
        parent::ApplyChanges();
        $default = $this->ReadPropertyFloat('DefaultThreshold');
        if (!is_finite($default) || $default < 0 || $default > 100 || $this->ReadPropertyInteger('StaleDays') < 1 || $this->ReadPropertyInteger('RefreshMinutes') < 0) {
            $this->SetTimerInterval('Refresh',0); $this->SetTimerInterval('Startup',0);
            $this->SetStatus(200); $this->logDebug('Invalid threshold, stale age or refresh interval.'); return;
        }
        if ($this->ReadAttributeString('LastDefault') !== (string)$default) {
            $this->SetValue('Threshold',$default); $this->WriteAttributeString('LastDefault',(string)$default);
        }
        $this->SetValue('Search',false);
        $this->SetValue('WebPath',$this->webPath());
        $this->SetTimerInterval('Refresh',min(1440,$this->ReadPropertyInteger('RefreshMinutes'))*60000);
        if (IPS_GetKernelRunlevel() === 10103) {
            $this->SetTimerInterval('HookSetup',100); $this->SetTimerInterval('Startup',200);
        }
        $this->SetStatus(102);
    }

    public function Destroy(): void
    {
        // Remove only this instance's hook, preserving all other registrations.
        if (IPS_GetKernelRunlevel() === 10103 && IPS_SemaphoreEnter('ALPORT.WebhookControl',1000)) {
            try {
                $ids=IPS_GetInstanceListByModuleID(self::WEBHOOK_CONTROL);
                if (count($ids)===1 && !IPS_HasChanges((int)$ids[0])) {
                    $control=(int)$ids[0]; $hooks=json_decode((string)IPS_GetProperty($control,'Hooks'),true);
                    if (is_array($hooks)) {
                        $next=array_values(array_filter($hooks,function($h): bool { return !is_array($h) || ($h['Hook'] ?? '')!==$this->webPath() || (int)($h['TargetID'] ?? 0)!==$this->InstanceID; }));
                        if ($next!==$hooks) { IPS_SetProperty($control,'Hooks',json_encode($next,JSON_THROW_ON_ERROR)); IPS_ApplyChanges($control); }
                    }
                }
            } catch (Throwable $e) { /* Never block destruction over an unavailable webhook registry. */ }
            finally { IPS_SemaphoreLeave('ALPORT.WebhookControl'); }
        }
        parent::Destroy();
    }

    public function MessageSink($TimeStamp,$SenderID,$Message,$Data): void
    {
        if ($SenderID === 0 && $Message === 10103) { $this->SetTimerInterval('HookSetup',100); $this->SetTimerInterval('Startup',200); }
    }

    public function Startup(): void { $this->SetTimerInterval('Startup',0); $this->Scan(); }

    public function RequestAction($Ident,$Value): void
    {
        if ($Ident === 'Threshold') { if (!is_int($Value) && !is_float($Value)) throw new InvalidArgumentException('Threshold must be numeric.'); $this->SetThreshold((float)$Value); }
        elseif ($Ident === 'Search') { try { $this->Scan(); } finally { $this->SetValue('Search',false); } }
        else throw new InvalidArgumentException('Unknown action.');
    }

    public function SetThreshold(float $value): void
    {
        if (!is_finite($value) || $value < 0 || $value > 100) throw new InvalidArgumentException('Use a threshold between 0 and 100 percent.');
        $this->SetValue('Threshold',$value); $this->publish();
        $this->logDebug('Threshold changed to '.$value.'%; values equal to threshold are excluded.');
    }

    private function overrides(): array
    {
        $list = json_decode($this->ReadPropertyString('Overrides'),true,16,JSON_THROW_ON_ERROR);
        if (!is_array($list)) throw new InvalidArgumentException('Invalid overrides list.');
        $map = [];
        foreach ($list as $row) {
            if (!is_array($row) || !isset($row['VariableID'],$row['Mode']) || !in_array($row['Mode'],['percent100','percent1','low','voltage','ignore'],true)) throw new InvalidArgumentException('Invalid override.');
            $id = (int)$row['VariableID']; if ($id <= 0 || isset($map[$id])) throw new InvalidArgumentException('Overrides must use unique variable IDs.');
            $map[$id] = $row['Mode'];
        }
        return $map;
    }

    public function Scan(): string
    {
        if (!IPS_SemaphoreEnter('BATMON.Scan.'.$this->InstanceID,1000)) throw new RuntimeException('Battery search is already running.');
        try {
            $overrides = $this->overrides(); $rows=[]; $errors=0; $own=IPS_GetChildrenIDs($this->InstanceID);
            foreach (IPS_GetVariableList() as $id) {
                $id=(int)$id; if (in_array($id,$own,true) || ($overrides[$id] ?? '') === 'ignore') continue;
                try {
                    $v=IPS_GetVariable($id); $o=IPS_GetObject($id); $name=IPS_GetName($id);
                    $presentation=function_exists('IPS_GetVariablePresentation') ? IPS_GetVariablePresentation($id) : [];
                    $profileName=(string)($presentation['PROFILE'] ?? (($v['VariableCustomProfile'] ?? '') ?: ($v['VariableProfile'] ?? '')));
                    $profile=$profileName !== '' && IPS_VariableProfileExists($profileName) ? IPS_GetVariableProfile($profileName) : [];
                    $class=BatteryDiscovery::classify($name,(string)$o['ObjectIdent'],$profileName,$profile,$presentation,(int)$v['VariableType']);
                    if (isset($overrides[$id])) {
                        $mode=$overrides[$id]; $class=['kind'=>str_starts_with($mode,'percent') ? 'percent' : $mode,'scale'=>$mode === 'percent1' ? 1.0 : 100.0,'reason'=>'Explicit configuration override'];
                        if ($class['kind'] === 'percent' && !in_array((int)$v['VariableType'],[1,2],true) || $class['kind'] === 'low' && (int)$v['VariableType'] !== 0) throw new RuntimeException('Override type does not match variable '.$id);
                    }
                    if ($class['kind'] === 'other') continue;
                    $value=GetValue($id); $updated=(int)$v['VariableUpdated'];
                    $percent=$class['kind'] === 'percent' ? BatteryDiscovery::percent($value,$class['scale']) : null;
                    $row=['id'=>$id,'name'=>$name,'device'=>IPS_GetName((int)$o['ParentID']),'path'=>IPS_GetLocation($id),'profile'=>$profileName,
                        'kind'=>$class['kind'],'scale'=>$class['scale'],'reason'=>$class['reason'],'value'=>$value,'percent'=>$percent,'updated'=>$updated,'updatedText'=>$updated>0 ? date('Y-m-d H:i:s',$updated) : 'Never recorded',
                        'stale'=>$updated > 0 && time()-$updated > $this->ReadPropertyInteger('StaleDays')*86400,'warning'=>$class['kind']==='low' && $value === true];
                    $rows[]=$row;
                    if ($this->ReadPropertyBoolean('DebugEnabled')) $this->SendDebug('Battery discovery',json_encode($row,JSON_UNESCAPED_UNICODE),0);
                } catch (Throwable $e) { $errors++; $this->logDebug('Variable '.$id.': '.$e->getMessage()); }
            }
            usort($rows,static function(array $a,array $b): int { return ($a['percent'] ?? 101) <=> ($b['percent'] ?? 101) ?: strnatcasecmp($a['path'],$b['path']); });
            $this->WriteAttributeString('Inventory',json_encode($rows,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE));
            $this->SetValue('LastScan',date('c')); $this->publish(); $this->SetStatus(102);
            $counts=array_count_values(array_column($rows,'kind'));
            $this->logDebug('Search complete: '.json_encode($counts).'; below threshold '.$this->GetValue('BelowCount').'; read errors '.$errors.'.');
            return $this->GetReport();
        } catch (Throwable $e) { $this->SetStatus(201); $this->logDebug('Search failed: '.$e->getMessage()); throw $e; }
        finally { IPS_SemaphoreLeave('BATMON.Scan.'.$this->InstanceID); }
    }

    public function GetReport(): string
    {
        $rows=json_decode($this->ReadAttributeString('Inventory'),true) ?: [];
        return json_encode(['threshold'=>$this->GetValue('Threshold'),'lastScan'=>$this->GetValue('LastScan'),'staleDays'=>$this->ReadPropertyInteger('StaleDays'),
            'rows'=>$rows,'below'=>BatteryDiscovery::below($rows,(float)$this->GetValue('Threshold'))],JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    }

    private function publish(): void
    {
        $report=json_decode($this->GetReport(),true); $rows=$report['below'];
        $this->SetValue('FoundCount',count(array_filter($report['rows'],static function($r): bool { return $r['kind']==='percent'; })));
        $this->SetValue('BelowCount',count($rows));
        $e=static function($s): string { return htmlspecialchars((string)$s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); };
        $html='<h3>Battery charge below '.$e($report['threshold']).'%</h3><table style="border-collapse:collapse;width:100%"><tr><th align="left">Device / variable</th><th>Charge</th><th>Last update</th></tr>';
        foreach ($rows as $r) $html.='<tr><td style="padding:8px">'.$e($r['path']).' ('.$r['id'].')</td><td>'.$e($r['percent']).'%</td><td>'.$e(date('Y-m-d H:i:s',$r['updated'])).($r['stale'] ? ' — old reading' : '').'</td></tr>';
        $html.='</table>'.(!$rows ? '<p>No recorded percentage readings below the threshold.</p>' : '');
        $this->SetValue('Results',$html);
        $this->UpdateFormField('LiveThreshold','value',$report['threshold']);
        $this->UpdateFormField('BatteryRows','values',json_encode($rows,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE));
        $this->UpdateFormField('OtherRows','values',json_encode(array_values(array_filter($report['rows'],static function($r): bool { return $r['kind']!=='percent' || $r['percent']===null || $r['updated']===0; })),JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE));
        $this->UpdateFormField('ScanResult','caption',count($report['rows']).' battery-related variables found; '.count($rows).' percentage readings below '.$report['threshold'].'%.');
    }

    public function GetConfigurationForm(): string
    {
        $form=json_decode(file_get_contents(__DIR__.'/form.json'),true); $r=json_decode($this->GetReport(),true);
        foreach ($form['actions'] as &$a) {
            if (($a['name'] ?? '') === 'LiveThreshold') $a['value']=$r['threshold'];
            if (($a['name'] ?? '') === 'BatteryRows') $a['values']=$r['below'];
            if (($a['name'] ?? '') === 'OtherRows') $a['values']=array_values(array_filter($r['rows'],static function($r): bool { return $r['kind']!=='percent' || $r['percent']===null || $r['updated']===0; }));
            if (($a['name'] ?? '') === 'WebPath') $a['caption']=$this->webPath().' — open on the SecretsManager HTTPS origin.';
        }
        return json_encode($form,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE);
    }

    public function ClearDebug(): void { $this->SetValue('Debug',''); }
    private function logDebug(string $message): void
    {
        $lines=explode("\n",(string)$this->GetValue('Debug')); $lines[]=date('Y-m-d H:i:s').' | '.$message;
        $this->SetValue('Debug',substr(implode("\n",array_slice(array_filter($lines),-50)),-20000));
        if ($this->ReadPropertyBoolean('DebugEnabled')) $this->SendDebug('BatteryMonitor',$message,0);
    }
}

