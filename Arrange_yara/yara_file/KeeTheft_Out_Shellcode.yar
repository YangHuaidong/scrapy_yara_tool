rule KeeTheft_Out_Shellcode {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file Out-Shellcode.ps1"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29"
      hash1 = "2afb1c8c82363a0ae43cad9d448dd20bb7d2762aa5ed3672cd8e14dee568e16b"
   strings:
      $x1 = "Write-Host \"Shellcode length: 0x$(($ShellcodeLength + 1).ToString('X4'))\"" fullword ascii
      $x2 = "$TextSectionInfo = @($MapContents | Where-Object { $_ -match '\\.text\\W+CODE' })[0]" fullword ascii
   condition:
      ( filesize < 2KB and 1 of them )
}