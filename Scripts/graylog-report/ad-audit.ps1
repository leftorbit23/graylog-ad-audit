#graylogserver
$graylogserver='https://graylogserver:12900'
#stream name (default stream introduced in Graylog v2.2.0)
$stream="000000000000000000000001"
#search range (in seconds)
$range=86400
#maximum number of results
$size=2000
#report sender
$sender="graylog@mydomain.com"
#report recipient
$recipient="sysadmin@mydomain.com"
#smtp server
$smtpserver="smtp.mydomain.com"
#define critical AD Groups (will be marked severity critical)
$ADCriticalGroups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins'

#load functions
. C:\Scripts\powershell-libraries\get-cname.ps1
. C:\Scripts\powershell-libraries\get-accountfromsid.ps1
. C:\Scripts\powershell-libraries\get-cnamefromsid.ps1
. C:\Scripts\powershell-libraries\get-useraccountcontrolvalue.ps1

CD C:\Scripts\graylog-report

$DbEventIds = Import-CSV 'data\ad-events.csv'

#Used by URLEncode
Add-Type -AssemblyName System.Web

#Set Graylog login credentials
$GLUser=’reportuser’ 
$GLPass=’######’
$GLSecurePass=Convertto-SecureString –String $GLPass –AsPlainText –force

## Password may also be stored encrypted
#$securestring = ConvertFrom-SecureString (ConvertTo-SecureString -AsPlainText -Force "abc123")
#$securestring="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
#$GLSecurePass=ConvertTo-SecureString $securestring

$cred=New-object System.Management.Automation.PSCredential $GLUser,$GLSecurePass




#######################
## 4728: A member was added to a security-enabled global group
## 4729: A member was removed from a security-enabled global group
## 4756: A member was added to a security-enabled universal group
## 4757: A member was removed from a security-enabled universal group
## 4761: A member was added to a security-disabled universal group
## 4762: A member was removed from a security-disabled universal group
## 4740: A user account was locked out
## 4767: A user account was unlocked
## 4724: An attempt was made to reset an accounts password
## 4722: A user account was enabled
## 4725: A user account was disabled
## 4738: A user account was changed
## 5139: A directory service object was moved
## 5136: A directory service object was modified (Used instead of 4781)
## 5141: A directory service object was deleted (Used instead of 4726)
## 5137: A directory service object was created (Used instead of 4720)
#######################
$query='Channel:Security AND ( 
            EventID:(4728 4729 4756 4757 4761 4762 4740 4767 4724 4722 4725 5139)
            OR (EventID:4738 AND NOT OldUacValue:"-")
            OR (EventID:5136 AND AttributeLDAPDisplayName:(sAMAccountName physicalDeliveryOfficeName description accountExpires telephoneNumber userAccountControl member pwdLastSet displayName givenName sn initials mDBStorageQuota mDBOverQuotaLimit mDBOverHardQuotaLimit))
            OR (EventID:(5141 5137) AND ObjectClass:(user group computer))
        ) AND NOT _exists_:Message'


$query=[System.Web.HttpUtility]::UrlEncode($query)

$GraylogResults = Invoke-RestMethod -Uri "$graylogserver/search/universal/relative?query=$query&range=$range&limit=$limit&filter=streams%3A$stream" -Headers @{"Accept"="application/json"} -Credential $cred 

$GraylogResults = $GraylogResults.messages.message

#$GraylogResults

if ($GraylogResults.Length -eq 0 ) { exit }

#Create correlation arrays. Allows us to combine multiple (delete&add) ldap events into a single event.
$OpCorrelationCount = @{}
$OpCorrelationPreviousValue = @{}
$GraylogResults | % {
  if ($_.OpCorrelationID.Length -gt 0 -and $_.AttributeLDAPDisplayName -gt 0) {
    $OpCorrelationCount[($_.OpCorrelationID.ToString())+($_.AttributeLDAPDisplayName.ToString())] += 1
    if ($_.OperationType -eq '%%14675') {
      $OpCorrelationPreviousValue[($_.OpCorrelationID.ToString())+($_.AttributeLDAPDisplayName.ToString())] = $_.AttributeValue.ToString()
    }
  }
}

#AttributeLDAPDisplayName lookup table for EventID 5136
$AttributeLDAPDisplayNameList = @{
 "sAMAccountName" = "Name";
 "displayName" = "Display Name";
 "givenName" = "First Name";
 "sn" = "Last Name";
 "initials" = "Initials";
 "physicalDeliveryOfficeName" = "Office";
 "description" = "Description";
 "telephoneNumber" = "Telephone Number";
 "mDBStorageQuota" = "Exchange Soft Quota"
 "mDBOverQuotaLimit" = "Exchange Send Quota";
 "mDBOverHardQuotaLimit" = "Exchange Hard Quota";
}

$email_body = ""
$AuditEventCount = 0

$GraylogResults| % {
  #If $skip is set to 1, the event will be ignored
  $skip=0
  $EventId = $_.EventId 

  # Get Event description from $DbEventIds
  $DbEventId = $DbEventIds | ? { $_.EventId -eq $EventID }
  # Use ObjectClass to set ObjectType if available. Otherwise use lookup from $DbEventId.
  if ($_.ObjectClass.length -ne 0) { $ObjectType =  (Get-Culture).textinfo.totitlecase($_.ObjectClass)  } else {  $ObjectType = $DbEventId.ObjectType }
  # Use TargetSid to set ObjectName if available. Otherwise use ObjectDN.
  if ($_.TargetSid.length -ne 0) {$ObjectName = (Get-CNameFromSID ($_.TargetSid))} else {  $ObjectName = (Get-CName($_.ObjectDN )) }
  # Set severity level
  if ($ADCriticalGroups -contains $_.TargetUserName ) {
    $Severity = '<b><font color=red>Critical</font></b>'
  } elseif  ($ADCriticalGroups -contains ($_.ObjectDN -match "CN=([^,]+)" | % { $Matches[1].ToString() }) ) {
    $Severity = '<b><font color=red>Critical</font></b>'
  } else {
    $Severity = 'Normal'
  }
  

  # EventId:(4728 4729 4756 4757 4761 4762)
  if ($EventId -eq '4728' -or $EventId -eq '4729' -or $EventId -eq '4756' -or $EventId -eq '4757'  -or $EventId -eq '4761' -or $EventId -eq '4762') {
    $Details = $DbEventId.Details + """" + (Get-CNameFromSID ($_.MemberSid)) + """" 
  # EventId:4740
  } elseif ($EventId -eq '4740') {
    if ($_.TargetDomainName.Length -eq 0 ) { $Workstation = '' } else { $Workstation = '(Workstation name: ' + $_.TargetDomainName + ')'}
    $Details = $DbEventId.Details + ' ' + $Workstation 
  # EventId:4738
  } elseif ($EventId -eq '4738') {
    $Details = $_.full_message -replace "`n","" -replace "`r","" -match "User Account Control:(.*)User Parameters:" | % {$Matches[1].Trim()}
  # EventId:5139
  } elseif ($EventId -eq '5139') {
    $Details = $DbEventId.Details + """" + (Get-CName($_.OldObjectDN )) + """ to """ + (Get-CName($_.NewObjectDN )) + """"
    $ObjectName = (Get-CName($_.OldObjectDN ))
  # EventId:5136 (LDAP Events)
  } elseif ($EventId -eq '5136') {
    # LDAP Add Operation
    if ($_.OperationType -eq '%%14674') {$LDAPOperationType = ' value added'}
    # LDAP Delete Operation
    if ($_.OperationType -eq '%%14675') {$LDAPOperationType = ' value deleted'}
    # Set Correlation Type to add/delete/none. Allows us to combine multiple (delete&add) ldap events into a single event.
    if ($OpCorrelationCount[($_.OpCorrelationID.ToString())+($_.AttributeLDAPDisplayName.ToString())] -ge 2 -and $_.OperationType -eq '%%14674') {
      $CorrelationType = 'add';
      $PreviousAttributeValue  = $OpCorrelationPreviousValue[($_.OpCorrelationID.ToString())+($_.AttributeLDAPDisplayName.ToString())]
    } elseif ($OpCorrelationCount[($_.OpCorrelationID.ToString())+($_.AttributeLDAPDisplayName.ToString())] -ge 2 -and $_.OperationType -eq '%%14675') {
      $CorrelationType = 'delete';
    } else {
      $CorrelationType = 'none';
    }          
    # EventId:5136 AND (sAMAccountName displayName givenName sn initials physicalDeliveryOfficeName description telephoneNumber mDBStorageQuota mDBOverQuotaLimit mDBOverHardQuotaLimit)
    $AttributeLDAPDisplayName = $_.AttributeLDAPDisplayName
    $AttributeValue = $_.AttributeValue
    # Loop through AttributeLDAPDisplayName lookup hash table
    $AttributeLDAPDisplayNameList.GetEnumerator() | % {
      if ($AttributeLDAPDisplayName -eq $_.Name ) {
        if ($CorrelationType -eq 'add') {$Details = $_.Value + " changed from """ +  ( $PreviousAttributeValue )+ """ to """ + ($AttributeValue)  + """ "
        } elseif  ($CorrelationType -eq 'delete') {$skip=1
        #} else {$Details = "Name changed to """ + $AttributeValue  + """"}
        } else {$Details = $_.Value + " """ + $AttributeValue  + """ $LDAPOperationType"}
      }
    }
    # EventId:5136 AND accountExpires
    if ($_.AttributeLDAPDisplayName -eq 'accountExpires' ) { 
      if ($_.AttributeValue -eq 0  -or $_.AttributeValue -eq 9223372036854775807) { $AccountExpires = 'Never' } else { $AccountExpires = Get-Date (Get-Date ([DateTime]::FromFileTime($_.AttributeValue)).ToString()).ToUniversalTime() -Format G}
      if ($CorrelationType -eq 'add') {
        if ($PreviousAttributeValue -eq 0 -or $PreviousAttributeValue -eq 9223372036854775807) { $PreviousAccountExpires = 'Never' } else { $PreviousAccountExpires = Get-Date (Get-Date ([DateTime]::FromFileTime($_.AttributeValue)).ToString()).ToUniversalTime() -Format G}
        $Details = "Account Expires changed from """ +  ( $PreviousAccountExpires )+ """ to """ + ($AccountExpires)  + """ "
      } elseif  ($CorrelationType -eq 'delete') {$skip=1
      } else {$Details = "Account Expires """ + $AccountExpires  + """ $LDAPOperationType"}      
    }
    # EventId:5136 AND userAccountControl
    if ($_.AttributeLDAPDisplayName -eq 'userAccountControl' ) { 
      if ($CorrelationType -eq 'add') {$Details = "User Access changed from """ +  (Get-UserAccountControlValue( $PreviousAttributeValue  )  )+ """ to """ + (Get-UserAccountControlValue($_.AttributeValue))  + """ "
      } elseif  ($CorrelationType -eq 'delete') {$skip=1
      } else {$Details = "User Access """ + (Get-UserAccountControlValue($_.AttributeValue))  + """ $LDAPOperationType"}
    }    
    # EventId:5136 AND member
    if ($_.AttributeLDAPDisplayName -eq 'member' ) {
      $Details = "Directory Service group modified:  """ + (Get-CName ($_.AttributeValue))  + """ $LDAPOperationType"
    }
    # EventId:5136 AND pwdLastSetl
    if ($_.AttributeLDAPDisplayName -eq 'pwdLastSet' ) { 
      if ($CorrelationType -eq 'add' -and $_.AttributeValue -eq -1) { $Details = "User is not required to change password at next logon" 
      } elseif ($CorrelationType -eq 'add' -and $_.AttributeValue -eq 0) { $Details = "User must change password at next logon" 
      } else { $skip=1 }
    }    

  # Use $DbEventId lookup for default Details
  } else {
    $Details = $DbEventId.Details
  }
  # If skip is not equal to 0, the event will be skipped
  if ($skip -eq 0) {
    $email_body += "<font size=+2>Changes to Active Directory Objects</font>"
    $email_body += "<table>" ; 
    $email_body += "<tr><td colspan=2>--------------------------------------------------</td></tr>" ; 
    $email_body += "<tr><td width=140>Severity</td><td>" + $Severity + "</td></tr>" ; 
    $email_body += "<tr><td colspan=2>--------------------------------------------------</td></tr>" ; 
    $email_body += "<tr><td>Change Type:</td><td>" + $DbEventId.ChangeType + "</td></tr>" ; 
    $email_body += "<tr><td>Object Type:</td><td>" + $ObjectType + "</td></tr>" ; 
    $email_body += "<tr><td>When Changed:</td><td>" + (Get-Date    $_.timestamp -format G ) + "</td></tr>" ; 
    $email_body += "<tr><td>Who Changed:</td><td>" + (Get-AccountFromSID ($_.SubjectUserSid)) + "</td></tr>" ; 
    $email_body += "<tr><td>Where Changed:</td><td>" + $_.source + "</td></tr>" ; 
    $email_body += "<tr><td colspan=2>--------------------------------------------------</td></tr>" ; 
    $email_body += "<tr><td>Object Name:</td><td>" + $ObjectName + "</td></tr>" ; 
    $email_body += "<tr><td>Details:</td><td>" + $Details + "</td></tr>" ; 
    $email_body += "<tr><td colspan=2>--------------------------------------------------</td></tr>" ;
    $email_body += "</table><br/><br/>" ;
    $AuditEventCount +=1
  }
}
#$email_body

if ($email_body.Length -gt 0) { 
  $msg=new-object System.Net.Mail.MailMessage
  $msg.From=$sender
  $msg.to.Add($recipient)
  $msg.Subject="AD Audit - $AuditEventCount Event(s)"
  $msg.IsBodyHtml=$true
  $msg.Body="<html><body> 
  $email_body
  </body></html>"
  $smtp=new-object System.Net.Mail.SmtpClient
  $smtp.host=$smtpserver
  $smtp.Send($msg)
}
