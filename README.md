# Ledger Zcash app
![stability-wip](https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CircleCI](https://circleci.com/gh/Zondax/ledger-zcash.svg?style=shield&circle-token=f7bfa1caae727ee77067c189f633e81398f78708)](https://circleci.com/gh/Zondax/ledger-zcash)

**This app is still work in progress!**

Please:

- **Do not use in production**
- **Do not use a Ledger device with funds for development purposes.**
- **Have a separate and marked device that is used ONLY for development and testing**

Tip:

- In releases, you will find a precompiled test app. If you are just curious, you can run `zxtool.sh` and avoid building.


## Preconditions

- Be sure you checkout submodules too:

    ```
    git submodule update --init --recursive
    ```

- Install `node > v13.0`. We typically recommend using `n`
- Install Docker CE
    - Instructions can be found here: https://docs.docker.com/install/
- You will need python 3 and then run
    - `make deps`

## How to build ?

> We like clion or vscode but let's have some reproducible command line steps
>

- Building the app itself

    If you installed the what is described above, just run:
    ```bash
    make
    ```

## Running tests

- Running rust tests (x64)

    If you installed the what is described above, just run:
    ```bash
    make rust_tests
    ```

- Running C/C++ tests (x64)

    If you installed the what is described above, just run:
    ```bash
    make cpp_tests
    ```

- Running device emulation+integration tests!!

   ```bash
    Use Zemu! Explained below!
    ```

## How to test with Zemu?

> What is Zemu?? Great you asked!!
> As part of this project, we are making public a beta version of our internal testing+emulation framework for Ledger apps.
>
> Npm Package here: https://www.npmjs.com/package/@zondax/zemu
>
> Repo here: https://github.com/Zondax/zemu

Let's go! First install everything:
> At this moment, if you change the app you will need to run `make` before running the test again.

```bash
make zemu_install
```

Then you can run JS tests:

```bash
make zemu_test
```

To run a single specific test:

> At the moment, the recommendation is to run from the IDE. Remember to run `make` if you change the app.

## How to debug a ledger app?

You can use vscode or clion to debug the app. We recommend using CLion but we provide a vscode (unsupported) configuration too.

### Preconditions

If you are using CLion, you need to a configuration file in your home directory: `$HOME/.gdbinit` with the following content:

```
set auto-load local-gdbinit on
add-auto-load-safe-path /
```

### Warnings

There are a few things to take into account when enabling Ledger App debugging:

- Once you enable the local .gdbinit that is located in your project workspace. You **will break** local Rust debugging in your host. The reason is that debugging unit tests will use the same `.gdbinit` configuration that sets the environment to ARM. We are looking at some possible fixes. For now, if you want to debug unit tests instead of the ledger app, you need to comment out the lines in `.gdbinit`

### Debugging

1. Build your app

    ```Makefile
    make
    ```

2. Define your debug scenario

    Open `tests/zemu/tools/debug.mjs` and look for the line:

    ```
    /// TIP you can use zemu commands here to take the app ...
    ```

    You can adjust this code to get the emulator to trigger a breakpoint in your app:
    - send clicks
    - send APDUs, etc

3. Launch the emulator in debug mode

    > If you didnt install Zemu yet (previous section), then run `make zemu_install`

    ```Makefile
    make zemu_debug
    ```

    The emulator will launch and immediately stop. You should see a black window

4. Configure Clion debugger

    Your configuration should look similar to this:

     ![image](docs/img/clion_debugging.png)

    Check that the path mappings are correct

5. Start CLion debugger

    You will hit a breakpoint in main.
    Add breakpoints in other places and continue.

    Enjoy :)

## Using a real device

## How to prepare your DEVELOPMENT! device:

>  You can use an emulated device for development. This is only required if you are using a physical device
>
>    **Please do not use a Ledger device with funds for development purposes.**
>>
>    **Have a separate and marked device that is used ONLY for development and testing**

   There are a few additional steps that increase reproducibility and simplify development:

**1 - Ensure your device works in your OS**
- In Linux hosts it might be necessary to adjust udev rules, etc.

  Refer to Ledger documentation: https://support.ledger.com/hc/en-us/articles/115005165269-Fix-connection-issues

**2 - Set a test mnemonic**

Many of our integration tests expect the device to be configured with a known test mnemonic.

- Plug your device while pressing the right button

- Your device will show "Recovery" in the screen

- Double click

- Run `make dev_init`. This will take about 2 minutes. The device will be initialized to:

   ```
   PIN: 5555
   Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young
   ```

**3 - Add a development certificate**

- Plug your device while pressing the right button

- Your device will show "Recovery" in the screen

- Click both buttons at the same time

- Enter your pin if necessary

- Run `make dev_ca`. The device will receive a development certificate to avoid constant manual confirmations.

