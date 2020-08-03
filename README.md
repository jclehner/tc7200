# Technicolor TC7200.20 / TC7200.U

Random notes on the firmware of the Technicolor cable modem we've
all learned to hate.

A few bits of information are strewn accros the interwebs:

* http://www.boards.ie/vbulletin/showthread.php?t=2057147563
* http://pastebin.com/E9MtQpb9
* https://news.ycombinator.com/item?id=7584466
* https://hackaday.io/project/3441-technicolor-tc7200-cable-modem
* https://wikidevi.com/wiki/Technicolor_TC7200

**WARNING** Tinkering with your cable modem is likely against your
ISP's TOS. Used units can often be found on eBay.

## Hardware

* SoC: Broadcom BCM3383A2
* 128 MB DDR2 RAM
* 1 MB SPI Flash: Macronix MX25L8005 (bootloader, permnv, dynnv)
* 64 MB NAND Flash: Micron NAND512W3A2SN6E
* WiFi: 1x mPCIe (BCM43228, VID 0x14e4, PID 0x4359) (board has
  unpopulated second mPCIe slot, presumably for concurrent dual band)

The SoC contains two processors, one for the eCos-based cable modem
firmware, and one "application processor", which runs Linux. RAM is
shared between the two processors.

## Software

This device actually contains two operating systems:

* Cable modem firmware (eCos)
* NAS/Mediaserver software (Linux)

The UPC web interface runs entirely in eCos, the Linux part is
left unused. Since the bootloader is unlocked, and has the `Read memory`,
`Write memory`, and `Jump to arbitrary address` options, we can use
`bcm2dump` from `bcm2-utils` to dump the firmware.

The flash partition map displayed by the bootloader is as follows:

```
Name           Size           Offset
=====================================
bootloader   0x00010000     0x00000000
image1       0x006c0000     0x01ac0000
image2       0x006c0000     0x02180000
linux        0x00480000     0x02840000
linuxapps    0x019c0000     0x00100000
permnv       0x00010000     0x00010000
dhtml        0x00240000     0x03ec0000
dynnv        0x00020000     0x000e0000
linuxkfs     0x01200000     0x02cc0000
```

These partitions are not actually located on one single device. The
TC7200 contains 1 MB of SPI NOR flash, and a 64 MB NAND flash chip.
The same partition map, reordered:

```
NOR:
bootloader   0x00010000     0x00000000
permnv       0x00010000     0x00010000
dynnv        0x00020000     0x000e0000

NAND:
linuxapps    0x019c0000     0x00100000
image1       0x006c0000     0x01ac0000
image2       0x006c0000     0x02180000
linux        0x00480000     0x02840000
linuxkfs     0x01200000     0x02cc0000
dhtml        0x00240000     0x03ec0000
```

Note that the NAND partitions in this table are offset by `0x100000`, so
the `linuxapps` partition actually starts at NAND offset 0.

`image1` and `image2` are cable modem firmware images. The firmware (including
the web ui) is based on Broadcom's BFC (Broadband Foundation Classes), which
in turn uses the eCos operating system. Usually, `image2` is the currently used
firmware, while `image1` contains an older version, used as a failsafe option.

`linux` is a Linux kernel image, `linuxkfs` is the root filesystem,
`linuxapps` contains additional software. `dhtml` is unused, at least on
the TC7200.U.

All images are wrapped in Broadcom's
[ProgramStore](https://github.com/Broadcom/aeolus/tree/master/ProgramStore)
format (open sourced by Broadcom!). The `linuxkfs` and `linuxapps` images
use [UBIFS](http://www.linux-mtd.infradead.org/doc/ubifs.html).

The whole Linux part is unused in the UPC version, but is used the unbranded
version (Technicolor TC 7200.20) as a NAS / media server (hence the USB port).
The manual for the TC 7200.20 can be found [here](http://www.docfoc.com/download/documents/user-manual-technicolor-tc720020pke1331-d49eu-u2-rohsv15). 

The boot process is as follows:

1. The bootloader loads the cable modem firmware: usually `image2`, but
   can be forced to load `image1` by pressing `1` at the bootloader prompt.
2. The cable modem firmware boots the linux kernel and establishes a
   communication link (ITC) between the two operating systems.

### Linux

Even though the Linux part is not used in the UPC version, it will happily
boot and try to request an IP address using DHCP. In older firmware versions
(before STD6.01.27), this request was granted by the modem's builtin DHCP
server (if activated), hogging the `192.168.0.10` address by default. The
MAC is hard-coded as `00:10:95:de:ad:07`. The current CM firmware ignores
the DHCP request, but it will continue to broadcast `DHCPDISCOVER` messages
forever. Let's answer its cries for help:

```
$ sudo dnsmasq -d --dhcp-range 192.168.0.5,192.168.0.6 -i enp4s0
[...]
dnsmasq-dhcp: DHCPDISCOVER(enp4s0) 00:10:95:de:ad:07 
dnsmasq-dhcp: DHCPOFFER(enp4s0) 192.168.0.6 00:10:95:de:ad:07 
dnsmasq-dhcp: DHCPREQUEST(enp4s0) 192.168.0.6 00:10:95:de:ad:07 
dnsmasq-dhcp: DHCPACK(enp4s0) 192.168.0.6 00:10:95:de:ad:07
[...]
```

Pointing your browser to `192.168.0.6` will redirect you to `192.168.0.1`,
but there are some hidden pages: 

* `/cgi-bin/get-logs.cgi`: dmesg, syslog, `ps` and `/proc/meminfo`
* `/cgi-bin/settings.cgi`: enable/disable zeroconf, Firefly (mt-daapd), CUPS (not working)
* `/cgi-bin/lsmounts.cgi`: list mounted devices


### CM firmware

As mentioned above, the actual cable modem firmware is based on Broadcom's
BFC, which in turn uses the eCOS real-time OS. By default, the serial
console is disabled, but can be enabled.

#### Enabling the console
##### Via telnet

There may be a telnet server listening on `192.168.0.1`, `192.168.100.1` or
the CM IP (`10.X.Y.Z`). You can try the following login/pw combinations:

* `admin` / `admin`
* `admin` / `password`
* `euskaltel` / `euskaltel`
* `MSO` / `gzcatvadmin`
* `admin` / `@m3r!c@m0v!L` (not kidding)
* `upccsr` / `PleaseChangeMe` (firmware before STD6.01.27 (?))

Once logged in, enter super-user mode:

```
Console> su

Password:  () [] brcm
Proceed with caution!
Type 'exit' to return.

Console> /thomson/console on

Storing value to nonvol...
Console is read/write.

CM> exit


CM> exit

Bye bye...
```

Now, if you reboot your device, you have full access to the serial
console. The level of access is the same as provided on the telnet
console after using `su`.

In my case, neither of the logins worked, because the username and password
were set via `SNMP` after modem registration. Also, the telnet server is
not accessible from the LAN side on `STD6.02.11`, only on `STD6.01.27`, and
only on the CM IP (`10.X.Y.Z`).

##### Via a patched firmware image
Since the bootloader allows booting a TFTP-downloaded image, we can
dump the firmware, patch it to always the console, boot it, and
enable the console in the non-vol settings. That way, the console can
be used in the unmodified firmware.

```
$ bcm2dump dump -d /dev/ttyUSB0 -a flash -o image1 -f image1.bin
$ ProgramStore -x -f image1.bin -o image1.out
$ hexedit image1.out
0x5af0f4: 34420002 1040000a -> 3403002 1000000a
$ ProgramStore -f image1.out -c 4 -a 0x80004000 -s 0xa825 -o image1.mod.bin
```

`bsdiff` patch coming soon! 

After that, boot the modified firmware using the bootloader's
`g) Download and run from RAM` option. Once at the `CM> prompt`,
type the following command:

```
CM> /thomson/console on

Storing value to nonvol...
Console is read/write.
```

Now reboot the device, and the console will be activated in the unmodified firmware
too (the settings are lost if you perform a factory reset!).

##### Via SNMP

On your computer, run:

`$ snmpset -v 2c -c public 192.168.0.1 1.3.6.1.4.1.4413.2.2.2.1.9.1.2.1.0 i 0`
`$ snmpset -v 2c -c public 192.168.0.1 1.3.6.1.4.1.4413.2.2.2.1.9.1.2.1.0 i 1`
`$ snmpset -v 2c -c public 192.168.0.1 1.3.6.1.4.1.4413.2.2.2.1.9.1.2.1.0 i 2`

`$ snmpset -v 2c -c public 192.168.0.1 1.3.6.1.4.1.4413.2.99.1.1.2.99.2863.105.1.0 i 2`

#### Changing settings

The eCos console is quite powerful, so I'll give only a brief overview of
what you could do. Most settings are found under `/non-vol`.

###### Display IP addresses:

eCos uses different IP stacks for various functions:

* IP1: (CM IP)
* IP2: `192.168.100.1`
* IP3: (public IP)
* IP4: ?
* IP5: `192.168.0.1`, `192.168.1.1`
* IP6: (EMTA IP)
* IP7: (virtual ethernet)

To display all ips:

```
CM> /ip_hal/ip_addr_show
```

###### Port passthrough

Using this option you can enable passhthrough on one or more ethernet ports.
If enabled, devices connected to that ethernet port will be served
with a public IP via DHCP (similar to a pure cable modem). This may be disabled
by your ISP.

```
CM> cd /non-vol/thomsonBfc
CM/NonVol/Thomson BFC Vendor NonVol> pt_interfacemask 0x10000
CM/NonVol/Thomson BFC Vendor NonVol> pt_interfaces 0x10000
CM/NonVol/Thomson BFC Vendor NonVol> write dyn
```

###### Telnet access

To enable telnet access on `192.168.0.1` (IP stack 5,
`0x1 << 5 = 0x10`) *only*:

```
CM> cd /non-vol/userif
CM/NonVol/User Interface NonVol> telnet_enable true
CM/NonVol/User Interface NonVol> telnet_ipstacks 0x10
CM/NonVol/User Interface NonVol> user_name <username>
CM/NonVol/User Interface NonVol> password <password>
CM/NonVol/User Interface NonVol> write dyn
```

###### Enable USB sharing

```
CM> cd /non-vol/msc
CM/NonVol/MSC NonVol> usb_enable 1
CM/NonVol/MSC NonVol> write dyn
```

###### Enable NAS 
```
CM> /non-vol/nas/enable 1
CM> /non-vol/nas/write dyn
```

###### Clearing the event log

```
CM> /event_log/flush
CM> /snmp/set bfcEventLogReset.0 int 1
CM> /snmp/set bfcEventLogReset.0 int 2
```


### SNMP

Some interesting MIBs:

* `bfcSerialConsoleMode.0` / `1.3.6.1.4.1.4413.2.2.2.1.9.1.2.1.0` (`INTEGER`:  `0` = disabled, `2` = read/write)
* `tceBFCConsoleMode.0` / `1.3.6.1.4.1.4413.2.99.1.1.2.99.2863.105.1.0` (`INTEGER`:  `0` = disabled, `2` = read/write)
* `bfcEventLogReset.0` / `1.3.6.1.4.1.4413.2.2.2.1.9.1.3.3.0` (`INTEGER`: `1` = reset, `2` = ? (default))
* `cmTelnetUserName.0`  / `1.3.6.1.4.1.2863.205.1.1.75.2.0` (`STRING`)
* `cmTelnetPassword.0` / `1.3.6.1.4.1.2863.205.1.1.75.3.0` (`STRING`)
* `cmTelnetIpStackInterfaces.0` / `1.3.6.1.4.1.2863.205.1.1.75.1.0` (`STRING`,
	`\x80\x00` = IP1, `\x40\x00` = IP2, `\x20\x00` = IP3, `\x10\x00` = <none>)
* `cmModemReset.0` / `1.3.6.1.4.1.2863.205.1.1.63.0` (`NUMBER`)
* `cmHttpUsername.0` / `1.3.6.1.4.1.2863.205.1.1.78.6.0` (`STRING`)
* `cmHttpUserPassword.0` / `1.3.6.1.4.1.2863.205.1.1.78.7.0` (`STRING`)
* `cmMiniFirewallEnable.0` / `1.3.6.1.4.1.4413.2.2.2.1.2.1.3.0` (`INTEGER`, `2` = ? (default))
* `docsDevNmAccessIp.1` / `1.3.6.1.2.1.69.1.2.1.2.1` (`IPADDRESS`)
* `docsDevNmAccessInterfaces.1` / `1.3.6.1.2.1.69.1.2.1.6.1` (`0x40` = cable, `0x80` = ethernet, `0xc0`, `0x00` = both)

#### Dumping images 1, 2 and 3

The exact sizes of image 1/2 and 3 can be found in the partition table
(image 3 is `linux`):
```
Flash Partition information:
```

Dumping time for these images is reasonable: around 4 hours for image1/2,
and around 2.5 hours for image3 - nothing that can't be done overnight.

##### LNXD6.02.07-kernel-20140224.bin

Some interesting strings:
```
Linux version 2.6.30-1.0.10mp1 [] (wtchen@localhost.localdomain) (gcc version 4.2.3) #1 Mon Feb 24 14:21:58 CST 2014
BUILD OPTIONS: ROOTFS_IMAGE_NAME=LNX1010mp1.LxG3383TP1-rootfs-140224.bin APPS_IMAGE_NAME=LNX1010mp1.LxG3383TP1-apps-140224.bin FS_KERNEL_IMAGE_NAME=LNX1010mp1.LxG3383TP1-kernel-140224.bin PCIMAGE=bv16_ilbc_faxr PCTYPE=15 LIBOPT=n ASKEY_NANDFLASH_PAD_SIZE=10 ASKEY_NANDFLASH_PAGE_SIZE=512 ASKEY_NANDFLASH_BLOCK_SIZE=16384 PID=A825 PROFILE=93383LxGTP1Nand
```

#### Dumping ALL images

Another interesting bootloader option:
```
  j) Jump to arbitrary address
```

Let's try to jump somewhere...

```
Jump to arbitrary address (hex): 0x80000000

******************** CRASH ********************

EXCEPTION TYPE: 10/Reserved instruction
TP0
r00/00 = 00000000 r01/at = 83f90000 r02/v0 = 80000000 r03/v1 = 00000001 
r04/a0 = 83f8e3c0 r05/a1 = 00000000 r06/a2 = 80000000 r07/a3 = 00000000 
r08/t0 = 00000020 r09/t1 = 00000000 r10/t2 = 00000029 r11/t3 = 0000003a 
r12/t4 = 20000000 r13/t5 = 000000a8 r14/t6 = 00000000 r15/t7 = 00000000 
r16/s0 = 942100d8 r17/s1 = 00000000 r18/s2 = 1dcd6500 r19/s3 = 0337f980 
r20/s4 = 94210084 r21/s5 = 000063d8 r22/s6 = 6dadfd7c r23/s7 = 0000fc14 
r24/t8 = 00000002 r25/t9 = 00001021 r26/k0 = 6dadfd7c r27/k1 = 83f8b16c 
r28/gp = 3555ab87 r29/sp = 87ffff40 r30/fp = 00000215 r31/ra = 83f86fd0 

pc   : 0x80000000               sr  : 0x00000002
cause: 0x00008028               addr: 0x00000000
```

Lots of references to addresses around `0x83f80000` - JACKPOT again. The
bootloader code is loaded at this address. In the bootloader logs, there's
a reference to `NandFlashRead`.

```
0x83f8cef0:	"NandFlashRead: Reading offset 0x%x, length 0x%x\n"
0x83f8cf24: "NandFlashRead error: Buffer not word-aligned!\n"
...
```

This helps us pinpoint the address of `NandFlashRead` at `0x83f831b4`. Let's
try this:

```
Jump to arbitrary address (hex): 0x83f831b4
NandFlashRead: Reading offset 0x0, length 0x83f831b4
```

Now let's write some very simple code:
```
#define NandFlashRead 0x83f831b4

main:
	; destination buffer
	li $a0, 0x85000000
	; offset
	li $a1, 0x0
	; length
	li $a2, 0x200

	li $t0, NandFlashRead
	jr $t0
```

which compiles to

```
partcopy.o:     file format elf32-tradbigmips

Disassembly of section .text:

00000000 <main>:
   0:   3c048500        lui     a0,0x8500
   4:   24050000        li      a1,0
   8:   24060200        li      a2,512
   c:   3c0883f8        lui     t0,0x83f8
  10:   350831b4        ori     t0,t0,0x31b4
  14:   01000008        jr      t0
  18:   00000000        nop
  1c:   00000000        nop
```

Dumping memory at `0x85000000` after executing this code, yields:

```
00000000  a8 25 00 00 01 00 01 ff  52 02 00 02 00 00 59 20  |.%......R.....Y |
00000010  80 00 00 00 44 42 10 00  30 20 10 20 04 30 26 20  |....DB..0 . .0& |
00000020  21 20 30 33 2d 30 30 31  30 30 30 20 04 2c 20 41  |! 03-001000 ., A|
00000030  20 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  | ...............|
00000040  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000050  00 00 00 00 00 40 00 00  04 82 a4 a0 58 00 00 00  |.....@......X...|
00000060  00 00 20 20 02 00 0c 10  28 22 ab 11 20 11 40 03  |..  ....(".. .@.|
...
```

Not perfect, but the signature (`a8 25`) is there!




#### Flashing images

The `d) Download to flash` option turns out to be **extremely** powerful:

```
Destination image
  0 = bootloader
  1/2 = CM image
  3 = Linux kernel image
  4 = Linux apps
  8 = Linux rootfs image
(0-3)[2]:
```

To ignore bad CRC:

w 83F87630 0

#### eCos

IP Stacks:


###### Enabling pass-through

Allows a device connected to a specific LAN-port to receive
a public IP:

```
# Enable port 4 (0x1 << 4 = 0x10000)
> cd /non-vol/thomsonBfc
> pt_interfaces 0x10000
> pt_interfacemask 0x10000
> write
```

###### Enabling the console

Enabling serial console from successful telnet login:

```
> su
(enter password "brcm")
> /thomson/console on
```

ThomBfcNonVolSettings:

# TWG850

1.3.6.1.4.1.4491.2.4.1.1.2.2.0 = user
1.3.6.1.4.1.4491.2.4.1.1.2.3.0 = pw
1.3.6.1.4.1.4491.2.4.1.1.2.4.0 = enable
