<?php
declare(strict_types=1);

/** Pure classification: never infer a percentage from the current value alone. */
final class BatteryDiscovery
{
    public static function classify(string $name, string $ident, string $profileName, array $profile, array $presentation, int $type): array
    {
        $text = $name . ' ' . $ident . ' ' . $profileName;
        $battery = preg_match('/batt|akku|low[_ ]?bat|operating[_ ]?voltage/i', $text) === 1;
        if (!$battery) return ['kind'=>'other','scale'=>100.0,'reason'=>'No battery metadata'];
        if ($type === 0 && preg_match('/low|niedrig|leer|~Battery\b|schwach/i', $text)) {
            return ['kind'=>'low','scale'=>100.0,'reason'=>'Boolean battery warning'];
        }
        if (!in_array($type, [1,2], true)) return ['kind'=>'other','scale'=>100.0,'reason'=>'Not numeric'];
        if (preg_match('/voltage|spannung|volt/i', $text . ' ' . ($profile['Suffix'] ?? '') . ' ' . ($presentation['SUFFIX'] ?? ''))) {
            return ['kind'=>'voltage','scale'=>100.0,'reason'=>'Voltage; no percentage conversion'];
        }
        if (preg_match('/error|low[_ ]?bat|is[_ ]?low|charging|is[_ ]?charg|ladezustand/i', $text)) {
            return ['kind'=>'status','scale'=>100.0,'reason'=>'Status or enumeration, not a percentage'];
        }
        $unit = (string)($profile['Suffix'] ?? '') . (string)($presentation['SUFFIX'] ?? '');
        $explicit = preg_match('/~Battery\.100\b|percentage|percent|prozent|%|battery[_ ]?(level|charge)|akku[_ ]?(stand|ladung)|batteryChargeState/i', $text) === 1;
        if ($explicit || str_contains($unit,'%')) {
            $max = $profile['MaxValue'] ?? $presentation['MAX'] ?? 100;
            $scale = (float)$max === 1.0 ? 1.0 : 100.0;
            return ['kind'=>'percent','scale'=>$scale,'reason'=>$explicit ? 'Battery percentage metadata' : 'Battery with percent unit'];
        }
        if (!empty($profile['Associations'])) return ['kind'=>'status','scale'=>100.0,'reason'=>'Enumerated battery status, not percentage'];
        return ['kind'=>'candidate','scale'=>100.0,'reason'=>'Battery name without a confirmed percentage unit; select an override if known'];
    }

    public static function percent($value, float $scale): ?float
    {
        if (!is_int($value) && !is_float($value)) return null;
        $percent = (float)$value * 100.0 / $scale;
        return is_finite($percent) && $percent >= 0 && $percent <= 100 ? round($percent,2) : null;
    }

    public static function below(array $rows, float $threshold): array
    {
        return array_values(array_filter($rows, static function(array $r) use ($threshold): bool {
            return $r['kind'] === 'percent' && $r['percent'] !== null && $r['updated'] > 0 && $r['percent'] < $threshold;
        }));
    }
}
