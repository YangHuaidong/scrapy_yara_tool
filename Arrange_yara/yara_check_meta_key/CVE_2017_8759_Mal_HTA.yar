rule CVE_2017_8759_Mal_HTA {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-14"
    description = "Detects malicious files related to CVE-2017-8759 - file cmd.hta"
    family = "None"
    hacker = "None"
    hash1 = "fee2ab286eb542c08fdfef29fabf7796a0a91083a0ee29ebae219168528294b5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Error = Process.Create(\"powershell -nop cmd.exe /c" fullword ascii
  condition:
    ( uint16(0) == 0x683c and filesize < 1KB and all of them )
}