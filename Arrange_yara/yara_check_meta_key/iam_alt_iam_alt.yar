rule iam_alt_iam_alt {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-10"
    description = "Auto-generated rule - file iam-alt.exe"
    family = "None"
    hacker = "None"
    hash = "2ea662ef58142d9e340553ce50d95c1b7a405672acdfd476403a565bdd0cfb90"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00' */
    $s1 = "IAM-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii /* PEStudio Blacklist: strings */ /* score: '43.00' */
    $s2 = "This tool allows you to change the NTLM credentials of the current logon session" fullword ascii /* PEStudio Blacklist: strings */ /* score: '31.00' */
    $s3 = "username:domainname:lmhash:nthash" fullword ascii /* PEStudio Blacklist: strings */ /* score: '15.00' */
    $s4 = "Error in cmdline!. Bye!." fullword ascii /* score: '12.00' */
    $s5 = "Error: Cannot open LSASS.EXE!." fullword ascii /* score: '12.00' */
    $s6 = "nthash is too long!." fullword ascii /* score: '8.00' */
    $s7 = "LSASS HANDLE: %x" fullword ascii /* score: '5.00' */
  condition:
    uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}