rule Recon_Commands_Windows_Gen1 {
  meta:
    author = Spider
    comment = None
    date = 2017-07-10
    description = Detects a set of reconnaissance commands on Windows systems
    family = Gen1
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = ['Internal Research', 'https://goo.gl/MSJCxP']
    score = 60
    threatname = Recon[Commands]/Windows.Gen1
    threattype = Commands
  strings:
    $s1 = "netstat -an" ascii
    $s2 = "net view" ascii fullword
    $s3 = "net user" ascii fullword
    $s4 = "whoami" ascii
    $s5 = "tasklist /v" ascii
    $s6 = "systeminfo" ascii
    $s7 = "net localgroup administrators" ascii
    $s8 = "net user administrator" ascii
    $s9 = "regedit -e " ascii
    $s10 = "tasklist /svc" ascii
    $s11 = "regsvr32 /s /u " ascii
    $s12 = "CreateObject(\"WScript.Shell\").RegWrite" ascii
    $s13 = "bitsadmin /rawreturn /transfer getfile" ascii
    $s14 = "wmic qfe list full" ascii
    $s15 = "schtasks.exe /create " ascii nocase
    $s16 = "wmic share get" ascii
    $s17 = "wmic nteventlog get" ascii
    $s18 = "wevtutil cl " ascii
    $s19 = "sc query type= service" ascii
    $s20 = "arp -a " ascii
    $fp1 = "avdapp.dll" fullword wide
    $fp2 = "keyword.command.batchfile" ascii
    $fp3 = ".sublime-settings" ascii
  condition:
    filesize < 1000KB and 4 of them
    and not 1 of ($fp*)
}