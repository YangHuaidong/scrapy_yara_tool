rule EQGRP_sploit {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-16"
    description = "EQGRP Toolset Firewall - from files sploit.py, sploit.py"
    family = "None"
    hacker = "None"
    hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
    hash2 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "print \"[+] Connecting to %s:%s\" % (self.params.dst['ip'], self.params.dst['port'])" fullword ascii
    $s2 = "@overridable(\"Must be overriden if the target will be touched.  Base implementation should not be called.\")" fullword ascii
    $s3 = "@overridable(\"Must be overriden.  Base implementation should not be called.\")" fullword ascii
    $s4 = "exp.load_vinfo()" fullword ascii
    $s5 = "if not okay and self.terminateFlingOnException:" fullword ascii
    $s6 = "print \"[-] keyboard interrupt before response received\"" fullword ascii
    $s7 = "if self.terminateFlingOnException:" fullword ascii
    $s8 = "print 'Debug info ','='*40" fullword ascii
  condition:
    ( uint16(0) == 0x2123 and filesize < 90KB and 1 of ($s*) ) or ( 4 of them )
}