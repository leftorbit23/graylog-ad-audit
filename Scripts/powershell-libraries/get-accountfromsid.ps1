function global:GET-AccountFromSID { 
param([string]$SID) 

  $objSID = New-Object System.Security.Principal.SecurityIdentifier `
     ($SID)
  $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])

  Return $objUser.Value
} 
