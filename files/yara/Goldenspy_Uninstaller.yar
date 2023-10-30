

rule Goldenspy_Uninstaller
{
meta:
            author = "SpiderLabs"
            malware_family = "GoldenSpy"
            filetype =  "exe_dll"
            version = "4.0"
    
strings:

            $str1 = "taskkill /IM svm.exe /IM svmm.exe /F" ascii
            $str2 = "\\svm.exe -stopProtect" ascii
            $str3 = "\\svmm.exe -u" ascii
            $str4 = "\\VCProject\\dgs\\Release\\" ascii
            $str5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\svm" ascii
            $str6 = "\\svmm.exe -stopProtect" ascii
            $str7 = "\\svm.exe -u" ascii
            $str8 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\svm.exe" ascii
            $str9 = "dGFza2tpbGwgL0lNIHN2bS5leGUgL0lNIHN2bW0uZXhlIC9GIA" ascii
            $str10 = "c3ZtLmV4ZSAtc3RvcFByb3RlY3Q" ascii
            $str11 = "XHN2bW0uZXhlIC11" ascii
            $str12 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cVW5pbnN0YWxsXHN2bQ" ascii
            $str13 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cQXBwIFBhdGhzXHN2bS5leGU" ascii
            $str14 = "XHN2bS5leGUgLXU" ascii
            $str15 = "c3ZtbS5leGUgLXN0b3BQcm90ZWN0" ascii
            $str16 = {4951538BCEE8[0-10]8D4C2424[0-10]8D44243C[0-4]68[0-20]83C4088B5004C644247404}
            $str17 = {535556578D4C2414[0-10]8D44242C68[0-10]50C744247C[0-10]83C4088B7004C64424[0-50]8BFE83C9FF33C0}


condition:    

    (uint16(0) == 0x5A4D) and 4 of ($str*) 
    
}
