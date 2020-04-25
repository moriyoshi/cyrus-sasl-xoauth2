libtoolize
install -d m4
aclocal -I m4
autoheader
automake -c -a --foreign
autoconf
