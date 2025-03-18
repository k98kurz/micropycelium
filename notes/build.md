# Commands

Note that the devices I use for testing are ESP-32 devices from M5stack. This
guide assumes a `~/Documents/repos` directory where all repositories will exist.

## Node Customization

Several node implementations are provided in the `devices` directory. Modify
the `mpnode.py` file to customize the node's behavior before you deploy. If you
do not want it frozen into the firmware, you can instead use it as a main.py
file; freezing it into the firmware makes deployment easier (main.py file is
just 2 lines).

## Environment Setup

First, if you are using ESP32, ensure that the esp-idf tool is installed
somewhere and configured:

```bash
pushd ~/Documents/repos
git clone --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh
popd
```

Then set the paths for the local forks/clones of the micropython and
micropycelium repos, as well as the device to which the firmware will be
deployed and the mpnode code to use (optional; you can bundle your own
node; this just makes the main.py file 2 lines and thus easier to deploy):

```bash
source ~/Documents/repos/esp-idf/export.sh
MICROPYTHON_PATH=$HOME/Documents/repos/micropython
MICROPYCELIUM_PATH=$HOME/Documents/repos/micropycelium
DEVICE=/dev/ttyACM0
MPNODE=generic_esp32
# or
MPNODE=M5stamp-Pico
# or
MPNODE=M5StickC-PLUS2
```

## Build and Deploy Firmware

Then build the single file module of micropycelium and copy it to the correct
path within the micropython fork and deploy to connected device:

```bash
python make.py > build/micropycelium.py
pushd $MICROPYTHON_PATH/ports/esp32
cp "$MICROPYCELIUM_PATH/build/micropycelium.py" modules/
cp "$MICROPYCELIUM_PATH/devices/$MPNODE/mpnode.py" modules/
make submodules && make
make PORT=$DEVICE deploy
popd
```

Note that if there are any other custom modules you want to include in the
firmware, they need to be copied before the `make` commands are run.

## Build With Custom C Library

The below example is for a library that did not meet the performance
requirements for use in this project. Pairing down the libsodium library will be
the next step in trying to build a fast and reliable PKI.

```bash
make clean && make USER_C_MODULES=$MICROPYTHON_PATH/examples/tweetnacl/micropython.cmake
make PORT=$DEVICE deploy
```

## Erase Flash

In case of file system errors, erase the flash then reflash the firmware:

```bash
pushd $MICROPYTHON_PATH/ports/esp32
esptool.py --chip esp32 -p $DEVICE erase_flash
make PORT=$DEVICE deploy
popd
```
