rule APT_MAL_CN_Wocao_xserver_csharp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Strings from the CSharp version of XServer"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "static void ServerX(int ListenPort)" ascii wide
    $b = "public class xserver" ascii wide
    $c = "[xserver]::Main($args);" ascii wide
    $d = "add rule name=powershell dir=in localport=47000 action=allow" ascii wide
    $e = "string TempFile = file_path + \".CT\";" ascii wide
    $f = "Port = 256 * RecvBuf[AddrLen + 5] + RecvBuf[AddrLen + 6];"
    $g = "CliSock.Send(new byte[] { 0x05, 0x00 });"
  condition:
    1 of them
}