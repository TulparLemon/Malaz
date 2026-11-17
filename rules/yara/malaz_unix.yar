/*
 * Malaz — Unix-Regelset (ELF/Linux + Mach-O/macOS)
 * ------------------------------------------------
 * Ergänzt das Default-Set um statische Indikatoren für Linux-/IoT- und
 * macOS-Schadsoftware. Der Live-VM-Test (MalwareBazaar-Korpus) zeigte:
 * ELF-Daten machen die Mehrzahl der Verfehlten aus, weil der Windows-
 * Defender Linux-Malware kaum kennt und die generische Entropie-Heuristik
 * nur die "lauten" Binaries trifft.
 *
 * Alle Regeln fordern die jeweilige Datei-Magic PLUS mehrere Verhaltens-
 * marker — einzelne Strings wie "busybox" oder "curl" kommen auch in
 * harmlosen Binaries vor und dürfen allein nie genügen.
 *
 * Magic-Konstanten (YARA liest Big-Endian):
 *   ELF:          0x7F454C46  ("\x7fELF")
 *   Mach-O x86:   0xCEFAEDFE, x64: 0xCFFAEDFE, BE-Varianten: 0xFEEDFACE/F
 *   Mach-O fat:   0xCAFEBABE  (identisch zu Java-Class — cpu_type-Prüfung)
 */

rule ELF_IoT_Botnet
{
    meta:
        severity = "high"
        description = "ELF mit typischen IoT-Botnet-Markern (Watchdog-Kill, Busybox, Telnet-Ausbreitung)"
        weight = 30
    strings:
        $watchdog = "/dev/watchdog" nocase
        $misc     = "/dev/misc" nocase
        $busybox  = "busybox" nocase
        $telnet   = "telnet" nocase
        $botnet   = "BOT_" nocase
        $killer   = "killer" nocase
        $initd    = "/etc/init.d" nocase
        $resolv   = "RESOLV_CONF" nocase
    condition:
        uint32(0) == 0x464C457F and
        (
            $watchdog or $misc or $botnet or
            3 of ($busybox, $telnet, $killer, $initd, $resolv)
        )
}

rule ELF_Botnet_Family_Markers
{
    meta:
        severity = "high"
        description = "ELF mit Namen/Markern bekannter Linux-Botnet-Familien (Mirai-Abkoemmlinge, Gafgyt, Tsunami, …)"
        weight = 30
    strings:
        $s1 = "mirai" nocase
        $s2 = "gafgyt" nocase
        $s3 = "bashlite" nocase
        $s4 = "lizardstresser" nocase
        $s5 = "tsunami" nocase
        $s6 = "kaiten" nocase
        $s7 = "roflcopter" nocase
        $s8 = "zollard" nocase
        $s9 = "hakai" nocase
        $s10 = "omni" ascii
    condition:
        uint32(0) == 0x464C457F and 2 of them
}

rule ELF_Cryptominer
{
    meta:
        severity = "high"
        description = "ELF mit Krypto-Mining-Markern (Stratum-Pools, XMRig/CryptoNight)"
        weight = 30
    strings:
        $s1 = "stratum+tcp" nocase ascii
        $s2 = "xmrig" nocase
        $s3 = "cryptonight" nocase
        $s4 = "minerd" nocase
        $s5 = "nicehash" nocase
        $s6 = "donate-level" nocase ascii
        $s7 = "max-cpu-usage" nocase ascii
    condition:
        uint32(0) == 0x464C457F and 2 of them
}

rule ELF_Dropper_Download_Chain
{
    meta:
        severity = "medium"
        description = "ELF mit typischer Dropper-Kette: Download per wget/curl, Ausfuehrung aus /tmp, chmod"
        weight = 25
    strings:
        $wget  = "wget" nocase
        $curl  = "curl" nocase
        $http  = "http" nocase
        $tmp   = "/tmp/" nocase
        $chmod = "chmod" nocase
        $sh    = "/bin/sh" nocase
    condition:
        uint32(0) == 0x464C457F and
        1 of ($wget, $curl) and $http and 2 of ($tmp, $chmod, $sh)
}

rule ELF_UPX_Packed
{
    meta:
        severity = "medium"
        description = "ELF, gepackt mit UPX (haeufige Tarnung von Linux-Malware)"
        weight = 25
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "$Info: This file is packed with the UPX" ascii
    condition:
        uint32(0) == 0x464C457F and 1 of them
}

rule MachO_Dropper_Behavior
{
    meta:
        severity = "high"
        description = "Mach-O (macOS) mit typischen Dropper-/Persistenz-Markern (osascript, LaunchAgents, shell-Drop)"
        weight = 30
    strings:
        $osa    = "osascript" nocase
        $launch = "launchctl" nocase
        $agents = "LaunchAgents" nocase
        $daemon = "LaunchDaemons" nocase
        $dosh   = "do shell script" nocase ascii
        $curl   = "curl" nocase
        $chmod  = "chmod +x" nocase ascii
        $plist  = ".plist" nocase
    condition:
        (
            uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or
            uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE or
            uint32(0) == 0xBEBAFECA
        ) and
        2 of ($osa, $launch, $agents, $daemon, $dosh, $chmod) and
        1 of ($curl, $plist, $osa)
}
