# pngshot

pngshot is a plugin to make screenshots good again.

## Features

* Takes screenshots in png format
* No watermark
* Take screenshots in any app

## Installation

Download from the [Releases section](https://github.com/xyzz/pngshot/releases).

Copy `pngshot.suprx` to `ur0:tai` and add `ur0:tai/pngshot.suprx` below `*main` in `ur0:tai/config.txt`.

Note that this was only tested with retail SceShell. If, for some reason, you have some weird modifications done to your SceShell, this plugin will probably crash your Vita.

## Usage

Press PS button + Start to take a screenshot. You can access screenshots with the Photos app, or from `ux0:picture/SCREENSHOT`.

## Additional notes

To compile this plugin from source, you need a custom build of libpng (the one in vdpm will not work). Check out `libpng` directory for a working `VITABUILD`.
