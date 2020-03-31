rule CN_Honker_Intersect2_Beta {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Script from disclosed CN Honker Pentest Toolset - file Intersect2-Beta.py
    family = Beta
    hacker = None
    hash = 3ba5f720c4994cd4ad519b457e232365e66f37cc
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/Intersect2.Beta
    threattype = Honker
  strings:
    $s1 = "os.system(\"ls -alhR /home > AllUsers.txt\")" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "os.system('getent passwd > passwd.txt')" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "os.system(\"rm -rf credentials/\")" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x2123 and filesize < 50KB and 2 of them
}