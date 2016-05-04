libtoolize
aclocal -I m4
autoheader
automake -c -a --foreign
autoconf
