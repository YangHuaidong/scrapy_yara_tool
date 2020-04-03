rule Fake_AdobeReader_EXE
    {
    meta:
      description = "Detects an fake AdobeReader executable based on filesize OR missing strings in file"
      date = "2014-09-11"
      author = "Florian Roth"
      score = 50
      nodeepdive = 1
      nodeepdive = 1
    strings:
      $s1 = "Adobe Systems" ascii
      $fp1 = "Adobe Reader" ascii wide
      $fp2 = "Xenocode Virtual Appliance Runtime" ascii wide
    condition:
      uint16(0) == 0x5a4d and
      filename matches /AcroRd32.exe/i and
      not $s1 in (filesize-2500..filesize)
      and not 1 of ($fp*)
}