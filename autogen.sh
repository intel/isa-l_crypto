#!/bin/sh -e

autoreconf --install --symlink -f

SYSTEM=`uname -s`

libdir() {
        if [ $SYSTEM = "Linux" ] ; then
                echo $(cd $1/$(gcc -print-multi-os-directory); pwd)
        elif [ $SYSTEM = "Darwin" ] ; then
                echo "/usr/lib"
        #elif [ $SYSTEM = "Windows" ] ; then 
        #        echo ""
        fi
}

args="--prefix=/usr --libdir=$(libdir /usr/lib)"

echo
echo "----------------------------------------------------------------"
echo "Initialized build system. For a common configuration please run:"
echo "----------------------------------------------------------------"
echo
echo "./configure HAVE_AS_KNOWS_AVX512=0 HAVE_AS_KNOWS_SHANI=0 AS=yasm $args"
echo
