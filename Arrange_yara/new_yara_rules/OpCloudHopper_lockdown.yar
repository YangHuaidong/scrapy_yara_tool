rule OpCloudHopper_lockdown {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Tools related to Operation Cloud Hopper"
    family = "None"
    hacker = "None"
    hash1 = "8ca61cef74573d9c1d19b8191c23cbd2b7a1195a74eaba037377e5ee232b1dc5"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/maaaaz/impacket-examples-windows"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "lockdown.dll" fullword ascii
    $s3 = "mfeann.exe" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}