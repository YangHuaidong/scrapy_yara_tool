rule item_old {
    meta:
        description = "Chinese Hacktool Set - file item-old.php"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "daae358bde97e534bc7f2b0134775b47ef57e1da"
    strings:
        $s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
        $s3 = "$sHash = md5($sURL);" fullword ascii
    condition:
        filesize < 7KB and 2 of them
}