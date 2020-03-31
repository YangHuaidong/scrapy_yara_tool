rule Netview_Hacktool {
  meta:
    author = Spider
    comment = None
    date = 2016-03-07
    description = Network domain enumeration tool - often used by attackers - file Nv.exe
    family = None
    hacker = None
    hash = 52cec98839c3b7d9608c865cfebc904b4feae0bada058c2e8cdbd561cfa1420a
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://github.com/mubix/netview
    score = 60
    threatname = Netview[Hacktool
    threattype = Hacktool.yar
  strings:
    $s1 = "[+] %ws - Target user found - %s\\%s" fullword wide
    $s2 = "[*] -g used without group specified - using \"Domain Admins\"" fullword ascii
    $s3 = "[*] -i used without interval specified - ignoring" fullword ascii
    $s4 = "[+] %ws - Session - %s from %s - Active: %d - Idle: %d" fullword wide
    $s5 = "[+] %ws - Backup Domain Controller" fullword wide
    $s6 = "[-] %ls - Share - Error: %ld" fullword wide
    $s7 = "[-] %ls - Session - Error: %ld" fullword wide
    $s8 = "[+] %s - OS Version - %d.%d" fullword ascii
    $s9 = "Enumerating Logged-on Users" fullword ascii
    $s10 = ": Specifies a domain to pull a list of hosts from" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 500KB and 2 of them ) or 3 of them
}