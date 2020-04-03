rule CN_Honker_Webshell_dz_phpcms_phpbb {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file dz_phpcms_phpbb.txt"
    family = "None"
    hacker = "None"
    hash = "33f23c41df452f8ca2768545ac6e740f30c44d1f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "if($pwd == md5(md5($password).$salt))" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "function test_1($password)" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = ":\".$pwd.\"\\n---------------------------------\\n\";exit;" fullword ascii
    $s4 = ":user=\".$user.\"\\n\";echo \"pwd=\".$pwd.\"\\n\";echo \"salt=\".$salt.\"\\n\";" fullword ascii
  condition:
    filesize < 22KB and all of them
}