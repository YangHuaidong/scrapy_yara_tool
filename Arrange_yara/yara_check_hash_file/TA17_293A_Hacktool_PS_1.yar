rule TA17_293A_Hacktool_PS_1 {
  meta:
    author = Spider
    comment = None
    date = 2017-10-21
    description = Auto-generated rule - file 72a28efb6e32e653b656ca32ccd44b3111145a695f6f6161965deebbdc437076
    family = PS
    hacker = None
    hash1 = 72a28efb6e32e653b656ca32ccd44b3111145a695f6f6161965deebbdc437076
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://www.us-cert.gov/ncas/alerts/TA17-293A
    threatname = TA17[293A]/Hacktool.PS.1
    threattype = 293A
  strings:
    $x1 = "$HashFormat = '$krb5tgs$23$*ID#124_DISTINGUISHED NAME: CN=fakesvc,OU=Service,OU=Accounts,OU=EnterpriseObjects,DC=asdf,DC=pd,DC=f" ascii
    $x2 = "} | Where-Object {$_.SamAccountName -notmatch 'krbtgt'} | Get-SPNTicket @GetSPNTicketArguments" fullword ascii
  condition:
    ( filesize < 80KB and 1 of them )
}