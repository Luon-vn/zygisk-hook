# Library files
```
zygisk/x86.so
zygisk/x86_64.so
zygisk/armeabi-v7a.so
zygisk/arm64-v8a.so
```

# Install
```
zip -r zygisk-module.zip .
adb push zygisk-module.zip /data/local/tmp/
adb shell su -c magisk --install-module /data/local/tmp/zygisk-module.zip
```