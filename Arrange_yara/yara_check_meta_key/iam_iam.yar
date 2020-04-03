rule iam_iam {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-07-10"
    description = "Auto-generated rule - file iam.exe"
    family = "None"
    hacker = "None"
    hash = "8a8fcce649259f1b670bb1d996f0d06f6649baa8eed60db79b2c16ad22d14231"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii /* PEStudio Blacklist: strings */ /* score: '59.00' */
    $s2 = "iam.exe -h administrator:mydomain:"  ascii /* PEStudio Blacklist: strings */ /* score: '40.00' */
    $s3 = "An error was encountered when trying to change the current logon credentials!." fullword ascii /* PEStudio Blacklist: strings */ /* score: '33.00' */
    $s4 = "optional parameter. If iam.exe crashes or doesn't work when run in your system, use this parameter." fullword ascii /* PEStudio Blacklist: strings */ /* score: '30.00' */
    $s5 = "IAM.EXE will try to locate some memory locations instead of using hard-coded values." fullword ascii /* score: '26.00' */
    $s6 = "Error in cmdline!. Bye!." fullword ascii /* score: '12.00' */
    $s7 = "Checking LSASRV.DLL...." fullword ascii /* score: '12.00' */
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}