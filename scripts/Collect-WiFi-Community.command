#!/bin/bash
set -u
set -o pipefail
export LC_ALL=C
umask 077

if [ "$(uname -s)" != Darwin ]; then
    echo 'Run this command in the installed macOS desktop.'
    exit 1
fi
if [ ! -t 0 ]; then
    echo 'Open this command in Terminal to record a connection attempt.'
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    exec /usr/bin/sudo /bin/bash "$0" "$@"
fi

base="$(cd "$(dirname "$0")" && pwd)" || exit 1
out="$(/usr/bin/mktemp -d "$base/WiFiCommunity-$(date +%Y%m%d-%H%M%S)-XXXXXX")" || exit 1
printf 'started\tfinished\tcommand\tstatus\n' > "$out/status.tsv"
/bin/cp "$0" "$out/collector.command"
stream_pid=''
sample_pid=''
packet_pids=''
live_start=''

capture() {
    local name="$1" started status
    shift
    started="$(date '+%Y-%m-%d %H:%M:%S %z')"
    {
        printf 'Started: %s\nCommand: ' "$started"
        printf '%q ' "$@"
        printf '\n'
        "$@"
    } > "$out/$name.txt" 2>&1
    status=$?
    printf '%s\t%s\t%s\t%s\n' "$started" "$(date '+%Y-%m-%d %H:%M:%S %z')" "$name" "$status" >> "$out/status.tsv"
}

collect_crash_reports() {
    /bin/mkdir -p "$out/crash-reports" || return 1
    /usr/bin/find /Library/Logs/DiagnosticReports -maxdepth 2 -type f -mtime -7 \
        \( -iname '*panic*' -o -name 'Kernel*' -o -name 'shutdown_stall*' \
        -o -name 'Sleep Wake Failure*' \) -print0 |
        while IFS= read -r -d '' report; do
            printf '%s\n' "$report"
            /bin/cp -p "$report" "$out/crash-reports/" || return 1
        done
}

stop_live() {
    local pid status
    for pid in "$sample_pid" "$stream_pid" $packet_pids; do
        [ -n "$pid" ] || continue
        kill -TERM "$pid" 2>/dev/null
        wait "$pid"
        status=$?
        printf '%s\t%s\tlive-process-%s\t%s\n' "$live_start" "$(date '+%Y-%m-%d %H:%M:%S %z')" "$pid" "$status" >> "$out/status.tsv"
    done
    sample_pid=''
    stream_pid=''
    packet_pids=''
}
trap stop_live EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wifi_interfaces="$(/usr/sbin/networksetup -listallhardwareports | /usr/bin/awk '/Hardware Port: (Wi-Fi|AirPort)/ { getline; print $2 }')"
printf '%s\n' "$wifi_interfaces" > "$out/wifi-interfaces.txt"

dhcp_state() {
    local interface
    for interface in $wifi_interfaces; do
        printf '\nWi-Fi interface: %s\n' "$interface"
        /usr/sbin/ipconfig getifaddr "$interface"
        /usr/sbin/ipconfig getpacket "$interface"
        /usr/sbin/netstat -I "$interface" -b
    done
}

# Every property published under the "AirportItlwm-" prefix, one "key<TAB>value"
# row each. Names are discovered at run time: Fix12 renamed several of them
# (user_eapol_rx_delivered and neighbours), so matching a fixed key list returns
# nothing on a newer driver and hides the regression.
dump_prefix() {
    /usr/sbin/ioreg -p IOService -l -w 0 2>/dev/null | /usr/bin/awk '
        /"AirportItlwm-/ {
            line = $0
            sub(/^[ \t]+/, "", line)
            if (!match(line, /"AirportItlwm-[^"]*"/))
                next
            key = substr(line, RSTART + 1, RLENGTH - 2)
            rest = substr(line, RSTART + RLENGTH)
            sub(/^[ \t]*=[ \t]*/, "", rest)
            printf "%s\t%s\n", key, rest
        }
    '
}

framework_layout() {
    local framework='/System/Library/PrivateFrameworks/IO80211.framework/Versions/A'
    /bin/ls -la "$framework"
    /usr/bin/file "$framework/IO80211"
    /usr/bin/codesign -dvv "$framework/IO80211"
    if [ -f /System/Library/CoreServices/OpenCore-Legacy-Patcher.plist ]; then
        /usr/bin/plutil -p /System/Library/CoreServices/OpenCore-Legacy-Patcher.plist
    fi
}

extension_paths() {
    local bundle
    /usr/bin/find /Library/Extensions /System/Library/Extensions /Library/StagedExtensions \
        -maxdepth 4 -type d \( -iname '*airport*.kext' -o -iname '*itlwm*.kext' -o -iname '*80211*.kext' -o -iname '*skywalk*.kext' \)
    for bundle in /Volumes/*/EFI/OC/Kexts/*[Ii]tlwm*.kext /Volumes/*/EFI/OC/Kexts/*80211*.kext /Volumes/*/EFI/OC/Kexts/*[Ss]kywalk*.kext; do
        if [ -d "$bundle" ]; then
            printf '%s\n' "$bundle"
        fi
    done
}

extension_metadata() {
    local bundle
    while IFS= read -r bundle; do
        [ -d "$bundle" ] || continue
        printf '\nBundle: %s\n' "$bundle"
        /usr/bin/plutil -p "$bundle/Contents/Info.plist"
    done < "$out/extension-paths.txt"
}

snapshot() {
    local phase="$1"
    capture "$phase-pci" /usr/sbin/ioreg -p IOService -r -c IOPCIDevice -d 2 -l -w 0
    capture "$phase-wrapper" /usr/sbin/ioreg -p IOService -r -c IOPCIEDeviceWrapper -l -w 0
    capture "$phase-wifi-interface" /usr/sbin/ioreg -p IOService -r -c IO80211Interface -l -w 0
    capture "$phase-wifi-infra" /usr/sbin/ioreg -p IOService -r -c IO80211InfraInterface -l -w 0
    capture "$phase-wifi-driver" /usr/sbin/ioreg -p IOService -r -c AirportItlwm -l -w 0
    capture "$phase-airport-prefix" dump_prefix
    capture "$phase-ifconfig" /sbin/ifconfig -a
    capture "$phase-wifi-status" /usr/bin/wdutil info
    capture "$phase-dhcp-state" dhcp_state
    capture "$phase-kernel-buffer" /sbin/dmesg
    capture "$phase-network-state" /usr/sbin/scutil --nwi
    capture "$phase-routes" /usr/sbin/netstat -rn
    capture "$phase-wifi-profiler" /usr/sbin/system_profiler -timeout 30 -detailLevel full SPAirPortDataType
}

{
    date
    /usr/bin/sw_vers
    /usr/bin/uname -a
    /usr/bin/id
    /usr/sbin/sysctl kern.boottime
} > "$out/environment.txt" 2>&1

echo 'Wi-Fi community collector: Sequoia / Tahoe, no required build UUID.'
echo 'The archive includes SSIDs, MAC/IP addresses and authentication log metadata.'
echo 'Do not enter passwords here. Share the archive privately with the developer.'
printf '\nProblem (not detected / no networks / missing band / cannot join / drops / slow): '
IFS= read -r problem || exit 1
printf 'Target SSID (network name only): '
IFS= read -r target || exit 1
printf 'Adapter model, AP band/channel/security if known: '
IFS= read -r details || exit 1
printf 'Problem: %s\nTarget: %s\nDetails: %s\n' "$problem" "$target" "$details" > "$out/attempt.txt"

echo 'Collecting driver, PCI matching, boot arguments and framework versions...'
capture loaded-kexts /usr/bin/kmutil showloaded
capture hardware-ports /usr/sbin/networksetup -listallhardwareports
capture boot-source /usr/sbin/ioreg -p IODeviceTree -r -n chosen -d 1 -l -w 0
capture boot-args /usr/sbin/sysctl kern.bootargs
capture framework-layout framework_layout
capture extension-paths extension_paths
capture extension-metadata extension_metadata
capture crash-reports collect_crash_reports
capture kext-load-log /usr/bin/log show --last 24h --info --style compact --predicate \
    '(process == "kernelmanagerd" OR process == "kextd") AND (eventMessage CONTAINS[c] "itlwm" OR eventMessage CONTAINS[c] "IO80211" OR eventMessage CONTAINS[c] "IOSkywalk")'
airport_pid="$(/usr/bin/pgrep -x airportd | /usr/bin/head -n 1)"
if [ -n "$airport_pid" ]; then
    capture airportd-vmmap /usr/bin/vmmap "$airport_pid"
fi
snapshot before

live_start="$(date '+%Y-%m-%d %H:%M:%S %z')"
printf 'Attempt window starts: %s\n' "$live_start" >> "$out/attempt.txt"
predicate='process == "airportd" OR process == "wifid" OR process == "wifip2pd" OR process == "eapolclient" OR process == "configd" OR process == "IPConfiguration" OR process == "bootpd" OR process == "kernelmanagerd" OR (process == "kernel" AND (eventMessage CONTAINS[c] "itlwm" OR eventMessage CONTAINS[c] "iwx" OR eventMessage CONTAINS[c] "iwm" OR eventMessage CONTAINS[c] "80211" OR eventMessage CONTAINS[c] "EAPOL" OR eventMessage CONTAINS[c] "firmware" OR eventMessage CONTAINS[c] "watchdog" OR eventMessage CONTAINS[c] "DBRG"))'
/usr/bin/log stream --level debug --style compact --predicate "$predicate" > "$out/live-log.txt" 2>&1 &
stream_pid=$!
for interface in $wifi_interfaces; do
    # Protocol summaries only: no packet payload dump or pcap containing credentials.
    /usr/sbin/tcpdump -n -e -tttt -l -s 96 -i "$interface" \
        'ether proto 0x888e or (udp and (port 67 or port 68))' > "$out/$interface-eapol-dhcp.txt" 2>&1 &
    packet_pids="$packet_pids $!"
done
: > "$out/property-timeline.tsv"
(
    trap - EXIT INT TERM
    while :; do
        stamp="$(date '+%Y-%m-%d %H:%M:%S %z')"
        dump_prefix > "$out/.sample-properties"
        sample_status=$?
        /usr/bin/awk -v s="$stamp" '{ printf "%s\t%s\n", s, $0 }' \
            "$out/.sample-properties" >> "$out/property-timeline.tsv"
        {
            printf '%s\n' "$stamp"
            /bin/cat "$out/.sample-properties"
            printf 'property-query-status=%s\n' "$sample_status"
            /sbin/ifconfig -a | /usr/bin/awk '
                /^[[:alnum:]_.-]+:/ { print; next }
                /^[[:space:]]+status:/ { print }
            '
            for interface in $wifi_interfaces; do
                /usr/sbin/netstat -I "$interface" -b
            done
        } >> "$out/state-timeline.txt"
        sleep 1
    done
) 2>&1 &
sample_pid=$!

echo
echo 'Recording started. Open the Wi-Fi list and reproduce ONE problem now.'
echo 'For a missing hotspot, keep it enabled and open the Wi-Fi list.'
echo 'For a connection failure, attempt joining and allow the automatic retry.'
echo 'Return here and press Enter after the result. Auto-stop after 180 seconds.'
IFS= read -r -t 160 finished_attempt
read_status=$?
printf 'Result entered: %s\nTerminal read status: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$read_status" >> "$out/attempt.txt"
sleep 20
stop_live
snapshot after
capture recent-log /usr/bin/log show --last 15m --info --debug --style compact --predicate "$predicate"

/bin/rm -f "$out/.sample-properties"

# Key inventory plus the keys that only showed up during the attempt window. A
# field renamed by a newer driver appears as a new key instead of vanishing.
/usr/bin/awk -F'\t' '
    NF < 3 { next }
    {
        key = $2
        if (!(key in first)) { first[key] = $1; order[++n] = key }
        last[key] = $1
        count[key]++
        value[key] = $3
    }
    END {
        printf "%-44s %7s  %-24s %-24s %s\n", "key", "samples", "first", "last", "lastvalue"
        for (i = 1; i <= n; i++) {
            key = order[i]
            printf "%-44s %7d  %-24s %-24s %s\n", key, count[key], first[key], last[key], value[key]
        }
    }
' "$out/property-timeline.tsv" > "$out/key-inventory.txt"

for phase in before after; do
    /usr/bin/awk -F'\t' '$1 ~ /^AirportItlwm-/ { print $1 }' \
        "$out/$phase-airport-prefix.txt" | /usr/bin/sort > "$out/keys-$phase.txt"
done
/usr/bin/comm -13 "$out/keys-before.txt" "$out/keys-after.txt" > "$out/keys-new-after-attempt.txt"

archive="$out.tar.gz"
if /usr/bin/tar -czf "$archive" -C "$base" "$(basename "$out")"; then
    /bin/rm -r -- "$out" || exit 1
    if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
        /usr/sbin/chown "$SUDO_UID:$SUDO_GID" "$archive" || exit 1
    fi
    trap - EXIT
    printf '\nDONE: %s\nSend this tar.gz privately for analysis.\n' "$archive"
else
    printf 'Archive failed. Evidence retained at: %s\n' "$out"
    exit 1
fi
