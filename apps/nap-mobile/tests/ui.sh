#!/bin/bash
# ui.sh dump | tap "<text>"   — drive Android system screens by their text
A=~/Library/Android/sdk/platform-tools/adb
dump() { $A shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; $A shell cat /sdcard/ui.xml | grep -o 'text="[^"]\+"[^>]*bounds="[^"]*"' | sed 's/ resource-id.*bounds=/ @ /'; }
case "$1" in
  dump) dump ;;
  tap)
    line=$(dump | grep -m1 -i "text=\"$2\"")
    [ -z "$line" ] && { echo "no '$2'"; exit 1; }
    nums=$(echo "$line" | grep -o '\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]' | tr -c '0-9\n' ' ')
    read x1 y1 x2 y2 <<< "$nums"
    $A shell input tap $(( (x1+x2)/2 )) $(( (y1+y2)/2 )); echo "tapped $2" ;;
esac
