rule APT_MAL_CN_Wocao_Agent_Csharp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Strings from CSharp version of Agent"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "mysend(client_sock, new byte[] { 0x16, 0x00 }, 2);" ascii wide
    $b = "Dns.GetHostAddresses(sip.Remove(sip.Length - 1));" ascii wide
    $c = "Port = 256 * buf[4] + buf[5];" ascii wide
    $d = "Port = 256 * buf[AddrLen] + buf[AddrLen + 1];" ascii wide
    $e = "StartTransData(CliSock" ascii wide
    $f = "static void ForwardTransmit(object ft_data)" ascii wide
    $key = "0x4c, 0x1b, 0x68, 0x0b, 0x6a, 0x18, 0x09, 0x41, 0x5a, 0x36, 0x1f, 0x56, 0x26, 0x2a, 0x03, 0x44, 0x7d, 0x5f, 0x03, 0x7b, 0x07, 0x6e, 0x03, 0x77, 0x30, 0x70, 0x52, 0x42, 0x53, 0x67, 0x0a, 0x2a" ascii wide
    $key_raw = { 4c 1b 68 0b 6a 18 09 41 5a 36 1f 56 26 2a 03 44 7d 5f 03 7b 07 6e 03 77 30 70 52 42 53 67 0a 2a }
  condition:
    1 of them
}