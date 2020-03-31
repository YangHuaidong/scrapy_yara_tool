rule CVE_2017_8759_SOAP_txt {
   meta:
      description = "Detects malicious file in releation with CVE-2017-8759 - file exploit.txt"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
      date = "2017-09-14"
      hash1 = "840ad14e29144be06722aff4cc04b377364eeed0a82b49cc30712823838e2444"
   strings:
      $s1 = /<soap:address location="http[s]?:\/\/[^"]{8,140}.hta"/ ascii wide
      $s2 = /<soap:address location="http[s]?:\/\/[^"]{8,140}mshta.exe"/ ascii wide
   condition:
      ( filesize < 200KB and 1 of them )
}