rule GetUserSPNs_VBS {
  meta:
    author = Spider
    comment = None
    date = 2016-05-21
    description = Auto-generated rule - file GetUserSPNs.vbs
    family = None
    hacker = None
    hash1 = 8dcb568d475fd8a0557e70ca88a262b7c06d0f42835c855b52e059c0f5ce9237
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/skelsec/PyKerberoast
    threatname = GetUserSPNs[VBS
    threattype = VBS.yar
  strings:
    $s1 = "Wscript.Echo \"User Logon: \" & oRecordset.Fields(\"samAccountName\")" fullword ascii
    $s2 = "Wscript.Echo \" USAGE:        \" & WScript.ScriptName & \" SpnToFind [GC Servername or Forestname]\"" fullword ascii
    $s3 = "strADOQuery = \"<\" + strGCPath + \">;(&(!objectClass=computer)(servicePrincipalName=*));\" & _" fullword ascii
  condition:
    2 of them
}