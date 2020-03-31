rule TopHat_BAT {
   meta:
      description = "Auto-generated rule - file cgen.bat"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-the-tophat-campaign-attacks-within-the-middle-east-region-using-popular-third-party-services/#appendix"
      date = "2018-01-29"
      hash1 = "f998271c4140caad13f0674a192093092e2a9f7794a7fbbdaa73ae8f2496c387"
      hash2 = "0fbc6fd653b971c8677aa17ecd2749200a4a563f9dd5409cfb26d320618db3e2"
   strings:
      $s1 = "= New-Object IO.MemoryStream(,[Convert]::FromBase64String(\"" ascii
      $s2 = "goto Start" fullword ascii
      $s3 = ":Start" fullword ascii
   condition:
      filesize < 5KB and all of them
}