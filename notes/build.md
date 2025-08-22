# Commands

Note that the devices I use for testing are ESP-32 devices from M5stack. This
guide assumes a `~/Documents/repos` directory where all repositories will exist.
I have not even attempted to make this work on non-Linux systems, but the below
instructions should be adaptable.

## Node Customization

Several node implementations are provided in the `devices` directory. You can
modify the `mpnode.py` file to customize the node's behavior before you deploy.
If you do not want it frozen into the firmware, you can instead use it as a
`main.py` file; freezing it into the firmware makes deployment easier (the
standard `main.py` file could be boiled down to just 2 lines:
`from mpnode import start; start()`, but I included other things to make it more
useful for experimentation).

## Environment Setup

First, clone the micropython repo, and either clone the micropycelium repo or
unpack a release:

```bash
REPOSDIR=$HOME/Documents/repos
pushd $REPOSDIR
git clone https://github.com/micropython/micropython.git
git clone https://github.com/k98kurz/micropycelium.git
# or
wget -O micropycelium-v0.1.0-prerelease4.zip https://github.com/k98kurz/micropycelium/archive/refs/tags/v0.1.0-prerelease4.zip
unzip micropycelium-v0.1.0-prerelease4.zip
mv micropycelium-0.1.0-prerelease4 micropycelium
popd
```

Second, if you are using ESP32, ensure that the esp-idf tool is installed
somewhere and configured:

```bash
REPOSDIR=$HOME/Documents/repos
pushd $REPOSDIR
git clone -b v5.2.2 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh
popd
```

Then set the paths for the local forks/clones of the micropython and
micropycelium repos, as well as the device to which the firmware will be
deployed and the mpnode code to use (optional; you can bundle your own
node; this just makes the main.py file 2 lines and thus easier to deploy):

```bash
REPOSDIR=$HOME/Documents/repos
source $REPOSDIR/esp-idf/export.sh
MICROPYTHON_PATH=$REPOSDIR/micropython
MICROPYCELIUM_PATH=$REPOSDIR/micropycelium
DEVICE=/dev/ttyACM0
MPNODE=M5StampS3
BOARD=ESP32_GENERIC_S3
# or
DEVICE=/dev/ttyACM1
MPNODE=M5StickC-PLUS2
BOARD=ESP32_GENERIC
# or
DEVICE=/dev/ttyUSB0
MPNODE=generic_esp32
BOARD=ESP32_GENERIC
# or
MPNODE=M5Stamp-C3
BOARD=ESP32_GENERIC_C3
# or
MPNODE=M5stamp-Pico
BOARD=M5STACK_Stamp_PICO
```

NB: to use the M5Stack Stamp Pico, the board definition must be copied to the
local micropython repository with the following:

```bash
cp -r $MICROPYCELIUM_PATH/devices/micropython_boards/M5STACK_Stamp_PICO $MICROPYTHON_PATH/ports/esp32/boards/
```

Also note that this will not work with the current prerelease but instead requires cloning the repo.

NB: currently, the M5Stamp-C3/C3U freezes without any error message after a few
hundred milliseconds and becomes unresponsive. I have not diagnosed why.

## Build and Deploy Firmware

If you want to include the
[micropython file editor](https://github.com/k98kurz/micropython-file-editor) in
the firmware, clone the repo then copy it with the following:

```bash
cp $REPOSDIR/micropython-file-editor/editor.py $MICROPYTHON_PATH/ports/esp32/modules/
```

Then build the single file module of micropycelium and copy it to the correct
path within the micropython fork and deploy to connected device:

```bash
pushd $MICROPYCELIUM_PATH
mkdir build
python make.py > build/micropycelium.py
python make.py mpnode $MPNODE > build/mpnode.py
cd $MICROPYTHON_PATH
cp "$MICROPYCELIUM_PATH/build/micropycelium.py" ports/esp32/modules/
cp "$MICROPYCELIUM_PATH/build/mpnode.py" ports/esp32/modules/
make -j -C ports/esp32 BOARD=$BOARD submodules
make -j -C ports/esp32 BOARD=$BOARD
make -j -C ports/esp32 BOARD=$BOARD PORT=$DEVICE deploy
popd
```

Note that if there are any other custom modules you want to include in the
firmware, they need to be copied before the `make` commands are run.

## Build With Custom C Library

The below example is for a library that did not meet the performance
requirements for use in this project. Pairing down the libsodium library will be
the next step in trying to build a fast and reliable PKI.

```bash
pushd $MICROPYTHON_PATH
make -j -C ports/esp32 BOARD=$BOARD clean
make -j -C ports/esp32 BOARD=$BOARD USER_C_MODULES=$MICROPYTHON_PATH/examples/tweetnacl/micropython.cmake
make -j -C ports/esp32 BOARD=$BOARD PORT=$DEVICE deploy
popd
```

## Erase Flash

In case of file system errors, erase the flash then reflash the firmware:

```bash
pushd $MICROPYTHON_PATH
esptool.py --chip esp32 -p $DEVICE erase_flash
make -j -C ports/esp32 BOARD=$BOARD PORT=$DEVICE deploy
popd
```
