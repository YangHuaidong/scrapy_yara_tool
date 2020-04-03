rule Invoke_WMIExec_Gen_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-14"
    description = "Detects Invoke-WmiExec or Invoke-SmbExec"
    family = "None"
    hacker = "None"
    hash1 = "140c23514dbf8043b4f293c501c2f9046efcc1c08630621f651cfedb6eed8b97"
    hash2 = "7565d376665e3cd07d859a5cf37c2332a14c08eb808cc5d187a7f0533dc69e07"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Invoke-WMIExec " ascii
    $x2 = "$target_count = [System.math]::Pow(2,(($target_address.GetAddressBytes().Length * 8) - $subnet_mask_split))" fullword ascii
    $s1 = "Import-Module $PWD\\Invoke-TheHash.ps1" fullword ascii
    $s2 = "Import-Module $PWD\\Invoke-SMBClient.ps1" fullword ascii
    $s3 = "$target_address_list = [System.Net.Dns]::GetHostEntry($target_long).AddressList" fullword ascii
    $x4 = "Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0" ascii
  condition:
    1 of them
}