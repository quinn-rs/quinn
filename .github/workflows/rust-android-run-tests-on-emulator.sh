#!/bin/bash
set -e

adb wait-for-device
while [[ -z "$(adb shell getprop sys.boot_completed | tr -d '\r')" ]]; do sleep 1; done

any_failures=0
for test in $(find target/${{ matrix.target }}/debug/deps/ -type f -executable ! -name "*.so" -name "*-*"); do
    adb push "$test" /data/local/tmp/
    adb shell chmod +x /data/local/tmp/$(basename "$test")
    adb shell /data/local/tmp/$(basename "$test") || any_failures=1
done

exit $any_failures
