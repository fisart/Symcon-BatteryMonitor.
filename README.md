# Battery Monitor

IP-Symcon module to discover battery-related variables, filter percentage readings below a selected threshold, and show a protected HTML dashboard.

## Installation

In Symcon, open **Module Control / Modules → Add** and use this repository URL:

```text
https://github.com/fisart/Symcon-BatteryMonitor..git
```

The repository name ends in a period, so its clone URL contains two periods before `git`. Select the `main` branch, then add an instance of **Fischer → Battery Monitor**.

The library has `library.json` at its root and the module files inside `BatteryMonitor`. The `.tests` directory is ignored by Symcon as a module directory.

Requirements: IP-Symcon 7 or later with PHP 8 and an enabled SecretsManager HTTPS portal that provides `SEC_IsPortalAuthenticated` and its session cookie API.

## Set up the instance

1. Select the correct SecretsManager instance in the form. Leaving this field at 0 selects automatically only if exactly one eligible enabled portal exists.
2. The vault must expose `SEC_IsPortalAuthenticated` and have `PortalEnabled=true` and a valid HTTPS `PortalOrigin`.
3. Set the default charge threshold, initially **30%**. Press Apply, then **Search all battery variables**.
4. Open the path in **Battery page webhook path**, `/hook/battery_monitor_<instanceID>`, on the **same HTTPS hostname and port as the SecretsManager portal**. You will be redirected to its authentication page if no valid session exists.
5. Optionally select your AlarmPortal instance to display a back link. To list this new page on an older portal that does not know its module ID, add the path as an Additional Page using the existing portal form.

Searching reads the Symcon object tree and values currently stored by device modules. It does not contact battery devices or force a device poll. A search runs once after applying settings / kernel startup. Automatic periodic searching is optional; the default is 0 (manual). A manual search is available in the form, in the HTML page, and through the Search variable below the instance.

## Threshold and readings

The active threshold is an editable float variable below the instance. The form and HTML page also provide threshold controls. They update the same active value. A changed **default threshold** in the property form resets the active value on Apply; unrelated setting changes preserve it.

The filter is **strictly less than** the threshold: a reading of 30% is excluded at a threshold of 30%. Set “Show all percentage readings” on the HTML page to see the entire detected percentage inventory, including 100%. Search by device, variable, full path or variable ID to narrow the table.

Detection supports:

- Percentage profiles such as `~Battery.100`, battery profiles with `%` units, and clear percentage names or identifiers such as `batteryStatus_percentage`, `Battery %` and `BatteryChargeState`.
- Fractional battery profiles with maximum 1, normalized to 0–100%.
- Custom/legacy profiles and current variable presentations.
- UniFi, Shelly, FRITZ, UPS, Nuki and other sources where the variable metadata identifies its meaning; no device vendor is excluded.
- Homematic `LOWBAT` / `LOW_BAT`, other Boolean low-battery flags, voltage and error/status values, shown separately.

A voltage such as 2.6 V, a charging/discharging status, and an `ERROR_BATTERY` code are never automatically converted to percent. Numeric “Battery Status”/“Batteriesstatus” variables without a unit are shown as **unconfirmed candidates**. In the form, use **Overrides** to explicitly identify a known percentage (0–100 or 0–1), Boolean low-battery flag or voltage; or ignore a variable. Apply the settings and search again.

A 0% reading is valid if it has been recorded. Variables whose update timestamp is zero are **unknown**, not measured empty batteries, and are excluded from the low-charge result. Readings outside 0–100% are invalid and excluded. Readings older than 30 days are marked **Old reading**; the age is configurable. They remain in the percentage result with their update time, since silently hiding old device readings could hide a real problem. Update timestamps refer to Symcon's recorded updates and do not prove that a physical device is online.

Each variable remains a separate entry, including mirrored objects. Device paths and IDs distinguish them. Counts are counts of variables, not unique physical devices.

## Variables below the instance

| Identifier | Purpose |
|---|---|
| Threshold | Active percentage threshold; accepts RequestAction |
| Search | Manual search action; returns to false after use |
| FoundCount | Number of percentage variables discovered |
| BelowCount | Number of recorded valid percentages below the threshold |
| Results | Formatted HTML table of the filtered percentage readings |
| LastScan | Time of last completed search |
| WebPath | Registered dashboard path / webhook setup error |
| Debug | Bounded debug string with search summaries, actions and errors |

Debug always retains the most recent 50 summary/error lines, capped at 20 KB. Detailed debugging additionally sends per-variable discovery data to the instance debug stream. No credentials or session tokens are written to the debug variable. The form includes **Clear debug variable**.

## Security

Every page and API request checks `SEC_IsPortalAuthenticated`. The module never offers an unprotected fallback. API requests with an expired session return 401. Browser commands use POST JSON with a token bound to the current SecretsManager session cookie (`SEC_PORTAL_V2_<vaultID>`) and check the portal host, request Origin and token. The page uses a nonce-based Content Security Policy, no external scripts, safe text insertion for variable names, and no-store response headers.

The protection follows the existing SecretsManager portal session policy, including its configured passkey/password options and expiry. This module does not change that policy.

## PHP functions

```php
BATMON_Scan($instanceID);                  // Full discovery; returns JSON report
BATMON_SetThreshold($instanceID, 30.0);   // Set active filter and refresh results
BATMON_GetReport($instanceID);            // Return the last inventory/filter as JSON
BATMON_SetupHook($instanceID);            // Register/unregister based on WebEnabled
BATMON_ClearDebug($instanceID);
```

## Validation

PHP 8.3 syntax checks and tests cover percentage classification, Homematic warnings, voltage/status exclusion, zero/out-of-range readings, fractional conversion, strict threshold comparison, and discovery against the complete uploaded settings snapshot. Module tests exercise the form and variables plus denied/allowed webhook access, expired sessions, host/Origin checks and CSRF protection with mocked Symcon/SecretsManager APIs. Dashboard DOM tests also cover search/filter controls, show-all mode, warnings, invalid input and safe device labels. Browser layout rendering was not available in this environment. No live installation or real passkey login was performed.

Personal settings, inventory reports, credentials and snapshot findings are not part of this repository. The `.tests/classify-test.php` script tests discovery classification and filtering without a Symcon installation; run it with `php .tests/classify-test.php`.

Symcon reference: [PHP library structure](https://www.symcon.de/en/service/documentation/developer-area/sdk-tools/sdk-php/structure/).


## 1.0.1 — JSON request compatibility

Both PHP's `CONTENT_TYPE` and Symcon's `HTTP_CONTENT_TYPE` are recognized for dashboard POST requests. When the standard key is absent or blank, the Symcon key is used. The body must still be valid JSON, and passkey sessions, Origin checks, CSRF tokens and request size limits remain enforced. This fixes “JSON body required” when applying a filter or starting a search on affected Symcon installations.

Regression checks: `php .tests/webhook-request.php`.


## 1.0.2 — Clean JSON search responses

The dynamic percentage and other-battery tables now pass JSON strings to Symcon's `UpdateFormField` API, rather than raw arrays. This prevents conversion warnings during searches and threshold changes. The webhook scopes PHP diagnostic handling to each request: warnings become exceptions recorded in Debug, and incidental output is kept out of the HTTP body. Authentication, Origin and CSRF checks remain enforced.

Regression tests: `php .tests/form-updates.php` and `php .tests/webhook-request.php`. They verify the form API's scalar-value requirement, both JSON header variants, warning/error JSON responses and successful responses containing no extra PHP output.
