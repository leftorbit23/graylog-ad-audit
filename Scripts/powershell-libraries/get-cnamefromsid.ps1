function global:Get-CNameFromSID { 
param([string]$SID) 

  $DN = Get-ADObject -Filter { objectSid -eq $SID} | Select-Object -ExpandProperty DistinguishedName

  return Get-CName ($DN)

} 
