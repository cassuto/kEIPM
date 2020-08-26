#!/bin/sh
TARGET_UNAME=`uname -r`
cp ./share/keipm.conf $1/etc/modules-load.d/keipm.conf
cp ./bin/keipm.ko $1/lib/modules/$TARGET_UNAME/keipm.ko
cp ./share/modules.dep $1/lib/modules/$TARGET_UNAME/modules.dep

./bin/keipm_cli --sign --sys $1 ./share/keipm_builtin_keys/user.der
