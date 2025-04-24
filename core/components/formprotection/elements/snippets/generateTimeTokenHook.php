<?php
/**
 * generateTimeTokenHook
 *
 * A FormIt preHook for MODX that generates a time-based token for spam protection.
 * This hook generates a timestamped token which is then validated by the 
 * formProtectionHook to prevent bot submissions and form spam.
 *
 * @author Jay Gilmore <jay@modx.com>
 * @version 0.9
 * @date April 23, 2025
 * @package formit
 * @subpackage hooks
 *
 * PROPERTIES:
 * -------------------
 * [No configurable properties - uses system settings]
 *
 * SYSTEM SETTINGS:
 * -------------------
 * formit.spam_time_secret - Secret key used for token generation (default: changeme)
 *
 * USAGE:
 * 1. Add this hook as a preHook in your FormIt call:
 * [[!FormIt?
 *   &preHooks=`generateTimeTokenHook`
 *   &hooks=`formProtectionHook,email`
 *   ...
 * ]]
 *
 * 2. Add this hidden input to your form:
 * <input type="hidden" name="form_time_token" id="form_time_token" value="[[!+fi.form_time_token]]">
 */

$modx = $hook->modx;
// Hardcoded or use MODX system setting
$field = 'form_time_token'; 
$secret = $modx->getOption('formit.spam_time_secret', null, 'changeme');
$timestamp = time();
$hash = hash_hmac('sha256', $timestamp, $secret);
$token = $timestamp . ':' . $hash;
// Set the token as a FormIt placeholder
$hook->setValue($field, $token);
return true;