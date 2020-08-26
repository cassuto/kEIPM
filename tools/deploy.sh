#!/bin/sh
if [ -z "$1" ] ; then
    echo You must spec a root path of target system!
    exit 1
fi

TARGET_UNAME=`uname -r`
cp ./share/keipm.conf $1/etc/modules-load.d/keipm.conf
if [ "$?" != 0 ] ; then
   exit $?
fi
cp ./bin/keipm.ko $1/lib/modules/$TARGET_UNAME/keipm.ko
if [ "$?" != 0 ] ; then
   exit $?
fi
# Auto install module
CMD_INSMOD="/sbin/insmod /lib/modules/$TARGET_UNAME/keipm.ko"
echo Install kernel module....
echo "#!/bin/sh -e" > $1/etc/rc.local
echo "$CMD_INSMOD" >> $1/etc/rc.local
if [ "$?" != 0 ] ; then
   exit $?
fi
chmod +x $1/etc/rc.local
if [ "$?" != 0 ] ; then
   exit $?
fi

echo Running signature....
./bin/keipm_cli --sign --sys $1 ./share/keipm_builtin_keys/user.der
