# FEX - Fast usermode x86 and x86-64 emulator for arm64

FEX allows you to run x86 and x86-64 binaries on an arm64 host, similar to qemu-user and box86.

It has native support for a rootfs overlay, so you don't need to chroot, as well as some thunklibs so it can forward things like GL to the host.

FEX presents a Linux 5.0 interface to the guest, and supports both arm64 and x86-64 as hosts.

FEX is very much work in progress, so expect things to change.

## Binaries built
- FEXLoader, loads and runs elf files
- FEXConfig, a gui to configure FEX
- IRLoader, used to run IR tests
- TestHarness & TestHarnessRunner, used to run asm unit tests
- UnitTestGenerator, not used right now
- Opt, ?

## Dependencies
* cpp-optparse
* imgui
* json-maker
* tiny-json
* clang
* clang-tidy if you want the code cleaned up
* cmake
* python3
* x86 and x86-64 cross compilers (if thunks are enabled)
* nasm (if unit tests are enabled)

## Building FEX, creating a thunked rootfs and running glxgears
Rough instructions to get you started

### Building FEXLoader and thunklibs
- Install the x86 and x86-64 cross compilers if on arm64 (gcc-x86-64-linux-gnu for ubuntu)
- Clone fex
- mkdir build && cd build
- export BUILDDIR=\`pwd\`
- cmake -G Ninja .. # Make also works, but we prefer ninja
- ccmake . # Enable Thunks, set CMAKE_BUILD_TYPE to 'RelWithDebInfo'
- ninja FEXLoader guest-libs host-libs # just running ninja will also work, but take more time

### Setting up a rootfs from scratch (assuming ubuntu 20.04 host here)
- sudo apt install qemu-user-static
- mkdir ~/rootfs
- cd ~/rootfs
- wget http://cdimage.ubuntu.com/ubuntu-base/releases/20.04/release/ubuntu-base-20.04.1-base-amd64.tar.gz # `lsb_release -a` can tell you which version you need
- mkdir 20.04
- cd 20.04
- tar -xf ../ubuntu-base-20.04.1-base-amd64.tar.gz
- sudo mount -o /dev dev
- sudo mount -o /tmp tmp
- cp /usr/bin/qemu-x86_64-static usr/bin/
- sudo chroot .
- echo nameserver 8.8.8.8 > /etc/resolv.conf
- apt update
- apt install mesa-utils
- exit

### Installing X11 and GL thunks to the rootfs
- export $ROOTFS=~/rootfs/20.04
- unlink $ROOTFS/usr/lib/x86_64-linux-gnu/libX11.so.6
- ln -s $BUILDDIR/Guest/libX11-guest.so $ROOTFS/usr/lib/x86_64-linux-gnu/libX11.so.6
- unlink $ROOTFS/usr/lib/x86_64-linux-gnu/libGL.so.1
- ln -s $BUILDDIR/Guest/libGL-guest.so $ROOTFS/usr/lib/x86_64-linux-gnu/libGL.so.1

### Running glxgears
- $BUILDDIR/Bin/FEXLoader -R $ROOTFS -t $BUILDDIR/Host -- $ROOTFS/usr/bin/glxgears