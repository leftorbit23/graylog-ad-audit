# Graylog AD Audit

## Description

This Powershell script can be scheduled to run either daily or as frequently as you like to report on changes in the Active Directory.

Disclaimer: It's only configured to search for specific event ids, so there may be other critical events that are not captured.


## Prerequisites

- Graylog server
 - Must be configured to collect logs from all Domain Controllers
- Graylog user 
 - User must have access to a stream that contains Domain Controller security events
 - User's timezone should be set to your local time
- PowerShell (Tested with version 4)
- Active Directory Module for Powershell
- Domain user to run the script with

## Installation

Download the Scripts folder and place it under C:\
Open ad-audit.ps1 in an editor and change the config settings.
Run manually or schedule it to run from task scheduler.

