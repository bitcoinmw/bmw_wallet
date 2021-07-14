cargo clean

git clone https://github.com/bitcoinmw/win32_helpers
bzip2 -dc win32_helpers/llvm_openssl_win32.tar.bz2 | tar xvf -

rem We want to trigger ssl static for all rust projects.
set LIBCLANG_PATH=%cd%\LLVM_OpenSSL-Win32
set OPENSSL_LIB_DIR=%cd%\LLVM_OpenSSL-Win32\lib\
set OPENSSL_INCLUDE_DIR=%cd%\LLVM_OpenSSL-Win32\include\
set OPENSSL_STATIC=yes

rustup toolchain install stable-i686-pc-windows-msvc
call .ci\win32_cargo.bat +stable-i686-pc-windows-msvc test --all
