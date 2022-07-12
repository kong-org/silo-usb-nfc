/**
 * @name scan.js
 * @description SiLo NFC USB scan script
 */

 const { exec } = require('node:child_process');
const { helpers, crypto, elliptic } = require('../lib/helpers.js');
const { logger } = require('../lib/pretty-logger.js');

const { NFC } = require('nfc-pcsc');
const crc  = require('crc'); // we need a specific crc, 'crc16ccitt'
const argv = require('minimist')(process.argv.slice(2));
const fs   = require('fs');
var QRCode = require('qrcode')

const nfc = new NFC();

logger.info(`command`, argv['command']);
logger.info(`block number`, argv['block']);
logger.info(`to address`, argv['to_addr']);
logger.info(`validation pub key`, argv['pubkey']);
logger.info(`export json`, argv['json']);
logger.info(`kill after single scan`, argv['scanonce'])
logger.info(`verify json`, argv['verify'])
logger.info(`devices to match`, argv['matchFile'])

//
// ARGUMENTS
//
// --command=
// Usage: The desired command code against a Kong unit. For example, '00' for a 
// standard signature operation or '55' for a minting operation.
//
// --block=
// Usage: Add the desired blockhash to feed into the Kong signature; if blank a second 
// random number is generated.
//
// --to_addr=
// Usage: Add the desired to address to feed into the Kong signature; if blank a second 
// random number is generated.
//
// --pubkey=
// Usage: Manually change the public key which is used to validate the signature.
//
// --json
// Usage: Indicate via boolean whether or not to print out certain SiLo values in a JSON 
// blob, requires command 56.
//
// --verify
// Usage: Indicate via boolean whether or not to verify a SiLo's functionality by moving
// its corresponding JSON file from /export to /verified.
//
// --scanonce
// Usage: Kill the script after an individual scan.
//
// --matchFile
// Usage: Match devices listed in a file.
//
// --testMatch
// Usage: Primary public key hash of test device to match.
//
// --saveSig
// Usage: Save the signature from the device.


var command = '00';
var blockNumber = crypto.randomBytes(32).toString('hex'); // TODO: swap with actual blockNumber
var toAddress = '0000000000000000000000000000000000000000';
var userPubkey = null;
var exportJSON = false;
var exportSig = false;
var matchFile = null;
var matchDevices = [];
var testMatch = null;

if (argv['command']) { command = argv['command'] }
if (argv['json']) { exportJSON = true }
if (argv['saveSig']) { exportSig = true }

argv['block'] ? blockNumber = argv['block'] : logger.info(`no block number given, using random number: ` + blockNumber);
argv['to_addr'] ? toAddress = argv['to_addr'] : logger.info(`no to address given using blank value:` + toAddress);
argv['pubkey'] ? userPubkey = argv['pubkey'].toString('hex') : logger.info(`no pubkey given, using externalPublicKey after read`);
argv['matchFile'] ? matchFile = argv['matchFile'] : logger.info(`no file device match file given.`);
argv['testMatch'] ? testMatch = argv['testMatch'] : logger.info(`no testMatch device given.`)

logger.info(`to be hashed`, '0x' + argv['to_addr'] + argv['block'])

var commandCode = command.toString();

logger.info(`command code: ` + commandCode)

//
// INIT
//

// Hardware Model
var hardwareModelAtecc608a = Buffer.from('ATECC608A');
var atecc608a = '0x' + crypto.createHash('sha256').update(hardwareModelAtecc608a).digest('hex');

var hardwareModelAtecc608b = Buffer.from('ATECC608B');
var atecc608b = '0x' + crypto.createHash('sha256').update(hardwareModelAtecc608b).digest('hex');

logger.info(`ATECC608A hash`, atecc608a)
logger.info(`ATECC608B hash`, atecc608b)

// Match Devices
// In order to export, we will want to use options --to_addr, --json, --block with --command 00
if (matchFile) {
  try {
    matchDevices = JSON.parse(fs.readFileSync(matchFile, 'utf8'));
    logger.info(`stored devices to match is `, matchDevices.length)
  } catch(e) {
    logger.info(`failed to load`, matchFile)
  }
}

// Locate a device in match devices.
function renderDevice(externalPublicKeyHash) {

      let foundDevice = matchDevices.find(o => o.primaryPublicKeyHash === '0x' + externalPublicKeyHash);

      if (foundDevice) {
        if (foundDevice.name) {
          logger.info(`check out that sweet`, foundDevice.name)
        }

        if (foundDevice.poap) {
          QRCode.toString(foundDevice.poap,{type:'terminal'}, function (err, url) {
            console.log(url)
          })
        }
        
        if (foundDevice.image) {
          exec(`open ${foundDevice.image}`);
        }
      } else {
        logger.info(`no device found.`)        
      }
}

// Save a device signatures.
function saveDevice(externalPublicKey, primaryPublicKeyHash, combinedHash, externalSignature, verficationKey) {

  // For creating a file proving a device was scanned.
  var partialDict = {};

  partialDict['primaryPublicKey'] = ['0x' + externalPublicKey.slice(0, 64),'0x' + externalPublicKey.slice(-64)]
  partialDict['primaryPublicKeyHash'] = primaryPublicKeyHash;
  partialDict['digest'] = '0x' + combinedHash;
  partialDict['signature'] = '0x' + externalSignature;
  partialDict['signingKey'] = verficationKey;  

  fs.writeFileSync(`./signatures/${primaryPublicKeyHash}.json`, JSON.stringify(partialDict), 'utf8', (err, res) => {

    if (!err) {
        console.log('saving signature for the device: ' + primaryPublicKeyHash);
    } else if (err) {
        console.log(err);
    }

  })
}

if (matchDevices && testMatch) {
  logger.info(`test matching device `, testMatch)
  renderDevice(testMatch)
  saveDevice("test-primaryPublicKey", '0x' + testMatch, "test-combinedHash", "test-externalSignature", "test-verficationKey")
}

nfc.on('reader', async reader => {

  logger.info(`device attached`, reader);

  reader.aid = 'F000000001';

  reader.on('card', async card => {

    logger.info(`card detected`, reader, card);

    try {

      /*
      |
      | Initial NFC Read Command
      |
      */

      var tag = Buffer.alloc(0); 

      const configBytes = await reader.read(0xe8, 4);
      logger.info(`configBytes`, reader, configBytes);

      logger.info(`outputRecord:`, reader);

      // Read the static record and dynamically locked record
      for (var i = 0x00; i < 0x63; i ++ ) {
        var page = await reader.read(i, 4);
        //logger.info(`data read`, reader, page);
        //data.copy(tag, i * 4, 0, 4);
        tag = Buffer.concat([tag, page]);
      }

      // logger.info(`inputRecord:`, reader);

      // Read input record prior to write
      //   for (var i = 0xB0; i < 0xCA; i ++ ) {
      //     const data = await reader.read(i, 4);
      		// logger.info(`data read`, reader, data);
      //   }

      // 70 - 73	4	74	01 x 4	>> Hardware Revision Number
      // 74 - 77	4	78	02 x 4	>> Firmware Number
      // 78 - 85	8	86	03 x 8	>> Serial Number (created by us, read each time from atecc?)
      // 86 - 149	64	150	04 x 64	>> Public Key 1 (For Signatures of External Data) (read each time from atecc?)
      // 150 - 213	64	214	05 x 64	>> Public Key 2 (For Signatures of Internal Random Number Only) (read each time from atecc?)
      // 214 - 233	20	234	06 x 20	>> Smart Contract Address (read each time from atecc?)
      // 234 - 240	7	241	07 x 7	>> NXP i2c serial number
      // 241 - 256	16	257	08 x 16	>> NXP MCU serial number
      // 257 - 265	9	266	09 x 9	>> atecc608a serial number
      // 266 - 393	128	394	01 x 128	>> Config Zone Bytes (read each time from atecc?)

      var hardwareRevisionNumber = tag.toString('hex').slice(140, 148);
      var firmwareNumber = tag.toString('hex').slice(148, 156);
      var serialNumber = tag.toString('hex').slice(156, 172);
      var externalPublicKey = tag.toString('hex').slice(172, 300);
      var internalPublicKey = tag.toString('hex').slice(300, 428);
      var smartContractAddress = tag.toString('hex').slice(428, 468);
      var nxpI2cSerial = tag.toString('hex').slice(468, 482);
      var nxp804Serial = tag.toString('hex').slice(482, 514);
      var atecc608aSerial = tag.toString('hex').slice(514, 532);
      var configZoneBytes = tag.toString('hex').slice(532, 788);
      
      var externalPublicKeyHash = crypto.createHash('sha256').update(externalPublicKey, 'hex').digest('hex');

      logger.info(`externalPublicKey`, externalPublicKey);
      logger.info(`internalPublicKey`, internalPublicKey);
      // logger.info(`hardwareRevisionNumber`, hardwareRevisionNumber); -- unused in v1 SiLo
      // logger.info(`serialNumber`, serialNumber); -- unused in v1 SiLo
      // logger.info(`firmwareNumber`, firmwareNumber); -- unused in v1 SiLo
      // logger.info(`nxpI2cSerial`, nxpI2cSerial); -- unused in v1 SiLo 
      // logger.info(`nxp804Serial`, nxp804Serial); -- unused in v1 SiLo
      logger.info(`atecc608aSerial`, atecc608aSerial);
      // logger.info(`smartContractAddress`, smartContractAddress); -- unused in v1 SiLo
      logger.info(`configZoneBytes`, configZoneBytes);			

      logger.info(`externalPublicKeyHash`, externalPublicKeyHash);

      /*
      |
      | Input Record NFC Write Command
      |
      */       

      // Create the random number and get the block number that we'll sign
      // var randomNumber = crypto.randomBytes(32).toString('hex');

      // Create the buffers to be hashed
      const addressBuffer = Buffer.from(toAddress, 'hex');
      const blockBuffer = Buffer.from(blockNumber, 'hex');
      const combinedBuffer = Buffer.concat([addressBuffer,blockBuffer]);

      // Create the sha256 of the randomNumber and blockNumber
      const combinedHash = crypto.createHash('sha256').update(combinedBuffer).digest('hex');

      logger.info(`combinedHash`, combinedHash);

      // Address padding.
      var toAddressInputRecord = toAddress + '000000000000000000000000';

      // Create CRC buffer with safe alloc to ensure that we don't accidentally CRC with something shorter
      const crcBuffer = Buffer.alloc(2);

      var inputCrc = crc.crc16ccitt(helpers._hexToBytes(
            commandCode +
            toAddressInputRecord +
            blockNumber +
            combinedHash
            )
          )  

      crcBuffer.writeUInt16BE(inputCrc);

      logger.info(`crcBuffer`, reader, crcBuffer);

      // Create the input record
      var inputBuffer = Buffer.concat([
          	Buffer.from('550063','hex'),
          	Buffer.from(commandCode, 'hex'),
          	Buffer.from(toAddressInputRecord, 'hex'),
          	Buffer.from(blockNumber, 'hex'),
          	Buffer.from(combinedHash, 'hex'),
          	Buffer.from(crcBuffer),
          	Buffer.from('FE00', 'hex')
          ]);

      //logger.info(`command buffer`, inputBuffer);

      logger.info(`inputBufferWrite`, reader);

      await helpers._delay(200);

      // Write input record
      const writtenData = await reader.write(0xB0, inputBuffer);

      /*
      |
      | Confirmation NFC Read Command
      |
      */      

      // Confirmation read after write
      const readLastIcBlockAfterWrite = await reader.read(0xCB, 4);  

      logger.info(`readLastIcBlockAfterWrite:`, reader, readLastIcBlockAfterWrite); 

      /*
      |
      | Output NFC Read Command
      |
      */

      // Required delay before reading result from tag
      if (commandCode == '55' || commandCode == '00') {
        await helpers._delay(2500);
      } else {
        await helpers._delay(2500);
      }

      var outputBuffer = Buffer.alloc(0)

      logger.info(`read outputRecord:`, reader);

      // Read input record after write
      for (var i = 0x64; i < 0xA5; i ++ ) {
        var page = await reader.read(i, 4);
        // logger.info(`data read`, reader, page);
        outputBuffer = Buffer.concat([outputBuffer, page]);
      }    

      // Grab the last hash and signature for comparison
      var lastHash = outputBuffer.toString('hex').slice(130, 196);
      var externalSignature = outputBuffer.toString('hex').slice(258, 386);
      var internalSignature = outputBuffer.toString('hex').slice(386, 514); // Provisioning public key for command 0x55
      var counter = outputBuffer.toString('hex').slice(514, 516);

      logger.info(`lastHash`, reader, lastHash);
      logger.info(`externalSignature`, reader, externalSignature);
      logger.info(`internalSignature`, reader, internalSignature);
      logger.info(`counter`, reader, counter);


      var verficationKey = externalPublicKey

      if (commandCode == '55' || commandCode == '56') {verficationKey = internalSignature} // Special case where the provisioning public key is store where the internal signature goes
      if (userPubkey) {verficationKey = userPubkey}

      const verfication = await helpers._verifySignature(combinedHash, verficationKey, externalSignature);

      logger.info(`verfication worked?`, reader, verfication);

      // Required confirmation read after checking sig
      const readLastIcBlockAfterSig = await reader.read(0xCB, 4);  

      /******************
      * Diagnostic Read *
      ******************/

      await helpers._delay(200);

      logger.info(`read diagnostic:`, reader);
      var debugBytes = Buffer.alloc(0);

      // Read back output records
      for (var i = 0xAC; i < 0xAF; i ++ ) {
        var page = await reader.read(i, 4);
        debugBytes = Buffer.concat([debugBytes, page]);
        // logger.info(`data read`, reader, page);
      }

      var stringDebugBytes = debugBytes.toString('ascii');

      logger.info('debugBytes: ', reader, stringDebugBytes);

      await helpers._delay(100);

      // If a device is found, then render information about it.
      if (matchDevices) {
        renderDevice(externalPublicKeyHash);
      }

      //
      // EXPORT JSON or VERIFY
      //
      if (stringDebugBytes == "Tag written\u0000") { 

        var primaryPublicKeyHash = '0x' + crypto.createHash('sha256').update(externalPublicKey, 'hex').digest('hex');

        if (exportSig) {
          saveDevice(externalPublicKey, primaryPublicKeyHash, combinedHash, externalSignature, verficationKey);
        }

        if (exportJSON) {
          // Create dictionary to hold it all.
          var completeDict = {};

          // Create hashes.
          // 1
          completeDict['primaryPublicKey'] = ['0x' + externalPublicKey.slice(0, 64),'0x' + externalPublicKey.slice(-64)]
          completeDict['primaryPublicKeyHash'] = primaryPublicKeyHash;

          // 2
          completeDict['secondaryPublicKey'] = ['0x' + internalPublicKey.slice(0, 64),'0x' + internalPublicKey.slice(-64)]
          completeDict['secondaryPublicKeyHash'] = '0x' + crypto.createHash('sha256').update(internalPublicKey, 'hex').digest('hex');

          // 3 - NOTE: we can only access this key with a 0x56 command or 0x55 (warning, 0x55 provisions)
          if (commandCode == '55' || commandCode == '56') {
            completeDict['tertiaryPublicKey'] = ['0x' + verficationKey.slice(0, 64),'0x' + verficationKey.slice(-64)]
            completeDict['tertiaryPublicKeyHash'] = '0x' + crypto.createHash('sha256').update(verficationKey, 'hex').digest('hex');
          }

          // Hardware Manufacturer
          var hardwareManufacturer = Buffer.from('Microchip Technology Inc.');
          completeDict['hardwareManufacturer'] = '0x' + crypto.createHash('sha256').update(hardwareManufacturer).digest('hex');

          // Hardware Model -- NOTE: this must be manually modified for ATECC608B chips.
          var hardwareModel = Buffer.from('ATECC608A');
          completeDict['hardwareModel'] = '0x' + crypto.createHash('sha256').update(hardwareModel).digest('hex');

          // Hardware Serial
          var hardwareSerial = Buffer.from(atecc608aSerial);
          completeDict['hardwareSerial'] = '0x' + crypto.createHash('sha256').update(hardwareSerial).digest('hex');       

          // Hardware Config -- NOTE: we slice out the serial number and an incrementing i2c byte
          var configZoneBytesMinusSerial = configZoneBytes.slice(8, 16) + configZoneBytes.slice(26, 28) + configZoneBytes.slice(30, 256)
          var config = new Buffer.from(configZoneBytesMinusSerial)
          completeDict['hardwareConfig'] = '0x' + crypto.createHash('sha256').update(config, 'hex').digest('hex');

          // Store.
          console.log(completeDict);    

          if (fs.existsSync(`../export/${primaryPublicKeyHash}.json`)) { 
            console.log('Found existing JSON for pubic key hash.')
          } else {
            if(commandCode == '56') {
              fs.writeFile(`../export/${primaryPublicKeyHash}.json`, JSON.stringify(completeDict), 'utf8', (err, res) => {

                  if (!err) {
                      console.log('Successfully exported JSON for device with public key hash: ' + primaryPublicKeyHash);
                  } else if (err) {
                      console.log(err);
                  }

              })           
            } else { 
              console.log('Refusing to export, missing param required for smart contract or not command 0x56');
            }          
          };
     
        } else if (argv['verify']) {
          if (fs.existsSync(`../export/${primaryPublicKeyHash}.json`)) { 
            console.log('Found existing JSON for pubic key hash, moving: ' + `${primaryPublicKeyHash}`)
            fs.rename(`../export/${primaryPublicKeyHash}.json`, `../verified/${primaryPublicKeyHash}.json`, (err) => {
              if (err) throw err;
              console.log('Move complete');
            });
          } else if (fs.existsSync(`../verified/${primaryPublicKeyHash}.json`)) {
            console.log('Already verified successfully.')
          } else {
            console.log('WARNING: no JSON file found to verify: ' + `${primaryPublicKeyHash}`);       
          };          
        }

      } else {
        console.log('Refusing to export, bad debugBytes message');
      }      

    } catch (err) {
    	logger.error(`error when reading data`, reader, err);
    }

    if (argv['scanonce']) {
      process.exit();
    }
	});

  reader.on('error', err => {
    logger.error(`an error occurred`, reader, err);
  });

  reader.on('end', () => {
    logger.info(`device removed`, reader);
  });


});

nfc.on('error', err => {
  logger.error(`an error occurred`, err);
});
