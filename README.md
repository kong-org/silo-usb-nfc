# KONG SiLo USB NFC Tool

## Description

Node script for verifying KONG SiLos via a NFC USB reader such as the [ACR-122](https://www.acs.com.hk/en/products/3/acr122u-usb-nfc-reader/). Learn more about SiLos at [KONG Cash](https://kong.cash/) and [KONG Land](https://kong.land/).

## Environment

Tested on MacOS and Raspbian with `node` 17.1.0 and `npm` 8.1.2. 

## Arguments

- `command`: The command code sent to the SiLo. See possible command codes referenced below.
- `block`: The desired blockhash to include within the SiLo signature. If blank, a random number is used.
- `to_addr`: The desired Ethereum address to include within the SiLo signature. If blank, a random number is used.
- `pubkey`: Force usage of another ECDSA P256 public key in order to validate the signature. Useful when validating a `tertiaryPublicKey` signature on a subsequent tap.
- `json`: Indicate via boolean whether or not to print out certain SiLo values in a JSON blob. Note that under command `00` these values are missing the `tertiaryPublicKey`. NOTE: requires an `export` dir to be present in the root project directory to be created.
- `verify`: Boolean, use the script in verification mode; if a corresponding JSON file exists for a SiLo in `/export`, this command will move the file to `/verify` if the device successfully generates a signature. NOTE: requires `export` and `verify` dirs to be present in the root project directory.
- `scanonce`: Boolean, activate with `=y`, will kill script after scanning a single SiLo.

### SiLo Command Codes

The first generation SiLo's, including KONG Cash and KONG Passports, will accept the following command codes:

- `00`: Generate a signature from a 32 byte input (typically a hash comprised of a random number and recent blockhash or a user's address and recent blockhash)
- `55`: This is a special command with only a limited set of uses. It will generate a signature using the ECDSA keypair associated with `tertiaryPublicKey`. It first generation SiLo's it can be used a maximum of 5 times before refusing to sign additional data.
- `56`: This is a special command that will reveal the `tertiaryPublicKey` which is not normally shown in any of the NDEF records.

## Exmaple

```
node src/scan.js --command=00 --block=3c2877a9a9701eb80ce3974a14e0a1ab80308c1cb9907c5a0a30f4c0945c3180
```

### Scan Output

```
7:12:27 PM – ACS ACR122U PICC Interface info: card detected {
  atr: <Buffer 3b 8f 80 01 80 4f 0c a0 00 00 03 06 03 00 03 00 00 00 00 68>,
  standard: 'TAG_ISO_14443_3',
  type: 'TAG_ISO_14443_3',
  uid: '04368dfae26480'
}
7:12:27 PM – ACS ACR122U PICC Interface info: configBytes <Buffer 29 32 f8 48>
7:12:27 PM – ACS ACR122U PICC Interface info: outputRecord:
7:12:28 PM – info: externalPublicKey 'cecf98ac1ddc55d1215b4d10497e3d2a6aecf4e0ee3d14fdf8c743b4965caceb09ddd61ac5bd48a6982ab640b707a9f334606fe79fda742d6c991e7bb3a7ebf8'
7:12:28 PM – info: internalPublicKey '793dda69c0c1876755ec65fe2f3e170ac536c5f81d139add2fcf51b97c141c62343e400ccae8402a7f55372cb0363ea6e36256bc4ec567b37b3159a04e86e51e'
7:12:28 PM – info: hardwareRevisionNumber '01010101'
7:12:28 PM – info: serialNumber '0303030303030303'
7:12:28 PM – info: firmwareNumber '02020202'
7:12:28 PM – info: nxpI2cSerial '07070707070707'
7:12:28 PM – info: nxp804Serial '08080808080808080808080808080808'
7:12:28 PM – info: atecc608aSerial '012375caa68af184ee'
7:12:28 PM – info: smartContractAddress '0606060606060606060606060606060606060606'
7:12:28 PM – info: configZoneBytes '012375ca00006002a68af184ee015100c000006889a08aa089a089a089a089a089a089a000000000000000000000000000000000ffffffff00000000ffffffff000000000000000000000000000000000000000000000000fcd9000000000000310071003100310031003100310031001c0070007000700070003c003c003c00'
7:12:28 PM – info: externalPublicKeyHash '91465a1d2058d1a93c5261bd25dea32673f0feb10fc89fb01aaeb2abe8815a19'
7:12:28 PM – info: toAddress 'af42d5dff2c8398110525555b48d7f156a498680'
7:12:28 PM – info: blockNumber '3c2877a9a9701eb80ce3974a14e0a1ab80308c1cb9907c5a0a30f4c0945c3180'
7:12:28 PM – info: combinedHash '02e4f2407ae858587db2cbe0854da033b0c008efc19e6a26f059292cfdbace2a'
7:12:28 PM – ACS ACR122U PICC Interface info: crcBuffer <Buffer 14 e1>
7:12:28 PM – ACS ACR122U PICC Interface info: inputBufferWrite
7:12:29 PM – ACS ACR122U PICC Interface info: readLastIcBlockAfterWrite: <Buffer 00 00 00 00>
7:12:31 PM – ACS ACR122U PICC Interface info: read outputRecord:
7:12:32 PM – ACS ACR122U PICC Interface info: lastHash '02e4f2407ae858587db2cbe0854da033b0c008efc19e6a26f059292cfdbace2abe'
7:12:32 PM – ACS ACR122U PICC Interface info: externalSignature '0c3a3ec09d2c9720d11554a842d56aabb63efbead2d0f01adc0c530bde212436d9a2f5684bfd2c7c8ed741b341fb967d522dc4d47a60aa1d91a0484f680dc6bb'
7:12:32 PM – ACS ACR122U PICC Interface info: internalSignature '5a579c8bb6b6ae93e1339c6c58717cd160bd41f1e69ee0997d5e9faac039227dafd3c655eb48788000d6dcdde5fd42b664be2dc87e1c72a699de12418401ee3a'
7:12:32 PM – ACS ACR122U PICC Interface info: counter '00'
7:12:32 PM – ACS ACR122U PICC Interface info: verfication worked? true
7:12:32 PM – ACS ACR122U PICC Interface info: read diagnostic:
7:12:33 PM – ACS ACR122U PICC Interface info: debugBytes:  'Tag written\x00'
```

## Notes

### NFC Scanner

You must have an NFC scanner in order to use this script. Occasionally driver issues require system reboot. Tested with the ACR122U-A9 scanner.

### KONG Cash note values.

```
1 KONG   = 1000000000000000000
5 KONG   = 5000000000000000000
10 KONG  = 10000000000000000000
20 KONG  = 20000000000000000000
50 KONG  = 50000000000000000000
100 KONG = 100000000000000000000
500 KONG = 500000000000000000000
```
