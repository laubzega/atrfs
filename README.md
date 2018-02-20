# atrfs (2018/02/18)
pyfuse-based filesystem for Atari 8-bit ATR images

This is a first stab at a filesystem for mounting ATR files that hold images of
Atari 8-bit disks. So far only tested with SD, ED and DD Atari DOS images.
Unoptimized to almost comedic degree, but rightly so, given the minuscule volume
of data it pushes around.

Mostly read-only: delete and rename are now in. Work in progress. Void where prohibited.


USAGE:

atrfs diskname.atr /mountpoint

Comments? Suggestions? Flowers? mileksmyk@gmail.com
