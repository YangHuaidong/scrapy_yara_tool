rule APT_Neuron2_Loader_Strings {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Rule for detection of Neuron2 based on strings within the loader"
    family = "None"
    hacker = "None"
    hash = "51616b207fde2ff1360a1364ff58270e0d46cf87a4c0c21b374a834dd9676927"
    judge = "black"
    reference = "None"
    referer = "https://otx.alienvault.com/pulse/5dad718fa5ec6c21e85c1c66"
    threatname = "None"
    threattype = "None"
  strings:
    $ = "dcom_api" ascii
    $ = "http://*:80/OWA/OAB/" ascii
    $ = "https://*:443/OWA/OAB/" ascii
    $ = "dcomnetsrv.cpp" wide
    $ = "dcomnet.dll" ascii
    $ = "D:\\Develop\\sps\\neuron2\\x64\\Release\\dcomnet.pdb" ascii
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and 2 of them
}