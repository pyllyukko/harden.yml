rule GoldenHelper
{
    meta:
        author = "SpiderLabs"
        variant = "GoldenSpy"
        filetype = "exe_dll"
        features = "UAC bypass,Updater,Dropper,ServiceDLL"
        version = "2.0"

    strings:
        $str1 = "WMPAssis_AddReg" wide ascii
        $str2 = "wmsma.inf" wide ascii
        $str3 = "taxhelper" wide ascii
        $str4 = "WMP Assistant Patch" wide ascii
        $str5 = "Elevation:Administrator" wide ascii

condition:
   (uint16(0) == 0x5A4D) and 4 of ($str*)
}
