dnl> 
dnl> Perl check
dnl> 
AC_CHECK_TOOL(PERL, perl)
if test "x$ac_cv_prog_ac_ct_PERL" = "xperl"; then

AC_MSG_CHECKING(whether perl development environment is present)
ac_save_CFLAGS="$CFLAGS"
ac_save_LIBS="$LIBS"
CFLAGS="$CFLAGS `perl -MExtUtils::Embed -e ccopts`"
LIBS="$LIBS `perl -MExtUtils::Embed -e ldopts`"
AC_TRY_RUN([
#include <EXTERN.h>
#include <perl.h>

int main ()
{
  if (perl_alloc() != NULL)
    return 0;	/* success */
  else
    return 1;	/* failure */
}
], ac_cv_perl_dev_installed=yes, ac_cv_perl_dev_installed=no,
   [echo $ac_n "cross compiling; assumed OK... $ac_c"
    ac_cv_perl_dev_installed=yes])
CFLAGS="$ac_save_CFLAGS"
LIBS="$ac_save_LIBS"
if test "$ac_cv_perl_dev_installed" = yes ; then
  AC_MSG_RESULT(yes)
   PERL_LIB=`perl -MExtUtils::Embed -e ldopts`
   PERL_INC=`perl -MExtUtils::Embed -e ccopts`
   AC_DEFINE_UNQUOTED(HAVE_PERL, 1, [PERL is supported])
else
  AC_MSG_RESULT(no)
  echo "Please install the perl module ExtUtils::Embed in order to enable perl support in ntop"
fi

else
   AC_MSG_WARN("Perl is missing, ntop won't be compiled with perl support")
fi


dnl> 
AC_SUBST(PERL_LIB)
AC_SUBST(PERL_INC)
