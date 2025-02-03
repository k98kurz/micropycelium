# Commands

Note that the devices used in testing were ESP-32 devices from M5stack.

## Environment Setup

First set the paths for the local forks/clones of the micropython and
micropycelium repos:

```bash
MICROPYTHON_PATH=$HOME/Documents/repos/micropython
MICROPYCELIUM_PATH=$HOME/Documents/repos/micropycelium
```

## Build and Deploy Firmware

Then build the single file module of micropycelium and copy it to the correct
path within the micropython fork and deploy to connected device:

```bash
python make.py > build/micropycelium.py
pushd $MICROPYTHON_PATH/ports/esp32
cp $MICROPYCELIUM_PATH/build/micropycelium.py modules/
make submodules && make && make PORT=/dev/ttyACM0 deploy
```

## Build With Custom C Library

The below example is for a library that did not meet the performance
requirements for use in this project. Pairing down the libsodium library will be
the next step in trying to build a fast and reliable PKI.

```bash
make clean && make USER_C_MODULES=$MICROPYTHON_PATH/examples/tweetnacl/micropython.cmake
make PORT=/dev/ttyACM0 deploy
```
