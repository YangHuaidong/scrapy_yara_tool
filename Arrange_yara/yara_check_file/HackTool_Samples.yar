rule HackTool_Samples {
  meta:
    author = Spider
    comment = None
    date = None
    description = Hacktool
    family = None
    hacker = None
    judge = unknown
    reference = None
    score = 50
    threatname = HackTool[Samples
    threattype = Samples.yar
  strings:
    $a = "Unable to uninstall the fgexec service"
    $b = "Unable to set socket to sniff"
    $c = "Failed to load SAM functions"
    $d = "Dump system passwords"
    $e = "Error opening sam hive or not valid file"
    $f = "Couldn't find LSASS pid"
    $g = "samdump.dll"
    $h = "WPEPRO SEND PACKET"
    $i = "WPE-C1467211-7C89-49c5-801A-1D048E4014C4"
    $j = "Usage: unshadow PASSWORD-FILE SHADOW-FILE"
    $k = "arpspoof\\Debug"
    $l = "Success: The log has been cleared"
    $m = "clearlogs [\\\\computername"
    $n = "DumpUsers 1."
    $o = "dictionary attack with specified dictionary file"
    $p = "by Objectif Securite"
    $q = "objectif-securite"
    $r = "Cannot query LSA Secret on remote host"
    $s = "Cannot write to process memory on remote host"
    $t = "Cannot start PWDumpX service on host"
    $u = "usage: %s <system hive> <security hive>"
    $v = "username:domainname:LMhash:NThash"
    $w = "<server_name_or_ip> | -f <server_list_file> [username] [password]"
    $x = "Impersonation Tokens Available"
    $y = "failed to parse pwdump format string"
    $z = "Dumping password"
  condition:
    1 of them
}