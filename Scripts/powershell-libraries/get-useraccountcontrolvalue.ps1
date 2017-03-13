function global:Get-UserAccountControlValue { 
param([int]$UserAccountControlValue) 

$result = ''
if ($UserAccountControlValue -ge 67108864) { $UserAccountControlValue = $UserAccountControlValue - 67108864; $result += "PARTIAL_SECRETS_ACCOUNT, "}
if ($UserAccountControlValue -ge 16777216) { $UserAccountControlValue = $UserAccountControlValue - 16777216; $result += "TRUSTED_TO_AUTH_FOR_DELEGATION, "}
if ($UserAccountControlValue -ge 8388608) { $UserAccountControlValue = $UserAccountControlValue - 8388608; $result += "PASSWORD_EXPIRED, "}
if ($UserAccountControlValue -ge 4194304) { $UserAccountControlValue = $UserAccountControlValue - 4194304; $result += "DONT_REQ_PREAUTH, "}
if ($UserAccountControlValue -ge 2097152) { $UserAccountControlValue = $UserAccountControlValue - 2097152; $result += "USE_DES_KEY_ONLY, "}
if ($UserAccountControlValue -ge 1048576) { $UserAccountControlValue = $UserAccountControlValue - 1048576; $result += "NOT_DELEGATED, "}
if ($UserAccountControlValue -ge 532480) { $UserAccountControlValue = $UserAccountControlValue - 532480; $result += "Domain controller, "}
if ($UserAccountControlValue -ge 524288) { $UserAccountControlValue = $UserAccountControlValue - 524288; $result += "TRUSTED_FOR_DELEGATION, "}
if ($UserAccountControlValue -ge 328226) { $UserAccountControlValue = $UserAccountControlValue - 328226; $result += "Disabled, Smartcard Required, Password Doesn’t Expire & Not Required, "}
if ($UserAccountControlValue -ge 328194) { $UserAccountControlValue = $UserAccountControlValue - 328194; $result += "Disabled, Smartcard Required, Password Doesn’t Expire, "}
if ($UserAccountControlValue -ge 262690) { $UserAccountControlValue = $UserAccountControlValue - 262690; $result += "Disabled, Smartcard Required, Password Not Required, "}
if ($UserAccountControlValue -ge 262658) { $UserAccountControlValue = $UserAccountControlValue - 262658; $result += "Disabled, Smartcard Required, "}
if ($UserAccountControlValue -ge 262656) { $UserAccountControlValue = $UserAccountControlValue - 262656; $result += "Enabled, Smartcard Required, "}
if ($UserAccountControlValue -ge 262144) { $UserAccountControlValue = $UserAccountControlValue - 262144; $result += "SMARTCARD_REQUIRED, "}
if ($UserAccountControlValue -ge 131072) { $UserAccountControlValue = $UserAccountControlValue - 131072; $result += "MNS_LOGON_ACCOUNT, "}
if ($UserAccountControlValue -ge 66082) { $UserAccountControlValue = $UserAccountControlValue - 66082; $result += "Disabled, Password Doesn’t Expire & Not Required, "}
if ($UserAccountControlValue -ge 66050) { $UserAccountControlValue = $UserAccountControlValue - 66050; $result += "Disabled, Password Doesn’t Expire, "}
if ($UserAccountControlValue -ge 66048) { $UserAccountControlValue = $UserAccountControlValue - 66048; $result += "Enabled, Password Doesn’t Expire, "}
if ($UserAccountControlValue -ge 65536) { $UserAccountControlValue = $UserAccountControlValue - 65536; $result += "DONT_EXPIRE_PASSWORD, "}
if ($UserAccountControlValue -ge 8192) { $UserAccountControlValue = $UserAccountControlValue - 8192; $result += "SERVER_TRUST_ACCOUNT, "}
if ($UserAccountControlValue -ge 4096) { $UserAccountControlValue = $UserAccountControlValue - 4096; $result += "WORKSTATION_TRUST_ACCOUNT, "}
if ($UserAccountControlValue -ge 2048) { $UserAccountControlValue = $UserAccountControlValue - 2048; $result += "INTERDOMAIN_TRUST_ACCOUNT, "}
if ($UserAccountControlValue -ge 546) { $UserAccountControlValue = $UserAccountControlValue - 546; $result += "Disabled, Password Not Required, "}
if ($UserAccountControlValue -ge 544) { $UserAccountControlValue = $UserAccountControlValue - 544; $result += "Enabled, Password Not Required, "}
if ($UserAccountControlValue -ge 514) { $UserAccountControlValue = $UserAccountControlValue - 514; $result += "Disabled Account, "}
if ($UserAccountControlValue -ge 512) { $UserAccountControlValue = $UserAccountControlValue - 512; $result += "Normal Account, "}
if ($UserAccountControlValue -ge 256) { $UserAccountControlValue = $UserAccountControlValue - 256; $result += "TEMP_DUPLICATE_ACCOUNT, "}
if ($UserAccountControlValue -ge 128) { $UserAccountControlValue = $UserAccountControlValue - 128; $result += "ENCRYPTED_TEXT_PWD_ALLOWED, "}
if ($UserAccountControlValue -ge 64) { $UserAccountControlValue = $UserAccountControlValue - 64; $result += "PASSWD_CANT_CHANGE, "}
if ($UserAccountControlValue -ge 32) { $UserAccountControlValue = $UserAccountControlValue - 32; $result += "PASSWD_NOTREQD, "}
if ($UserAccountControlValue -ge 16) { $UserAccountControlValue = $UserAccountControlValue - 16; $result += "LOCKOUT, "}
if ($UserAccountControlValue -ge 8) { $UserAccountControlValue = $UserAccountControlValue - 8; $result += "HOMEDIR_REQUIRED, "}
if ($UserAccountControlValue -ge 2) { $UserAccountControlValue = $UserAccountControlValue - 2; $result += "ACCOUNTDISABLE, "}
if ($UserAccountControlValue -ge 1) { $UserAccountControlValue = $UserAccountControlValue - 1; $result += "SCRIPT, "}
 return $result -replace (', $','')

}