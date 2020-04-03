rule CN_Honker_Intersect2_Beta {
    meta:
        description = "Script from disclosed CN Honker Pentest Toolset - file Intersect2-Beta.py"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "Disclosed CN Honker Pentest Toolset"
        date = "2015-06-23"
		score = 70
        hash = "3ba5f720c4994cd4ad519b457e232365e66f37cc"
    strings:
        $s1 = "os.system(\"ls -alhR /home > AllUsers.txt\")" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "os.system('getent passwd > passwd.txt')" fullword ascii /* PEStudio Blacklist: strings */
        $s3 = "os.system(\"rm -rf credentials/\")" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        uint16(0) == 0x2123 and filesize < 50KB and 2 of them
}