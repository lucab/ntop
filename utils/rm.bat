@echo off
rem
rem This is a crude version of rm, sufficient for compiling
rem ntop under MinGW.  Put it somewhere in your path.
rem
rem Note that this should go away, and die a proper, albeit
rem horrible death, if somebody can find a source for 
rem fileutils-4.1 (or a newer version) which has rm in it!
rem
rem  Burton M. Strauss III <Burton@ntopsupport.com> - June 2002 
rem

if /%1 == / goto :usage
if /%1 == /--version goto :version
if /%1 == /--help goto :usage
if /%1 == /-i goto :usage
if /%1 == /-d goto :usage
if /%1 == /-r goto :usage
if /%1 == /-R goto :usage

if /%1 == /-v shift
if /%1 == /--verbose shift
if /%1 == /-f shift

:loop
if /%1 == / goto :done
if not exist %1 goto :oops
echo Deleting %1...
del %1
goto :common

:oops
echo ***ERROR: Unable to delete %1, file does not exist!

:common
shift
goto :loop

:usage
echo Usage:  rm [-f][-v] file [, file ...]
echo    Note: -f and -v are ignored, they are forced by this .bat file
echo    Note: No other parameters are supported, and this
echo          help text is printed so you don't think it 
echo          might have worked!
echo.
:version
echo   version 0.2 (14Jun2002)
echo.
:done
