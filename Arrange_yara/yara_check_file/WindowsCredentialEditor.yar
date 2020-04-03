rule WindowsCredentialEditor
{
    meta:
       description = "Windows Credential Editor"
      threat_level = 10
      score = 90
    strings:
      $a = "extract the TGT session key"
      $b = "Windows Credentials Editor"
    condition:
       all of them
}