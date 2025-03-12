zip -r zygisk-module.zip .
adb push zygisk-module.zip /data/local/tmp/
adb shell su -c magisk --install-module /data/local/tmp/zygisk-module.zip