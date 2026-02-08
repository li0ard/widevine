<p align="center">
    <a href="https://github.com/li0ard/widevine/">
        <img src="https://raw.githubusercontent.com/li0ard/widevine/main/.github/logo.svg" alt="widevine logo" title="widevine" width="120" /><br>
    </a><br>
    <b>@li0ard/widevine</b><br>
    <b>Simple Widevine CDM implementation</b>
    <br>
    <a href="https://li0ard.is-cool.dev/widevine">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/widevine/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/widevine" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/widevine"><img src="https://img.shields.io/npm/v/@li0ard/widevine" /></a>
    <a href="https://jsr.io/@li0ard/widevine"><img src="https://jsr.io/badges/@li0ard/widevine" /></a>
    <br>
    <hr>
</p>

## Installation

```bash
# from NPM
npm i @li0ard/widevine

# from JSR
bunx jsr add @li0ard/widevine 
```

## Example

```ts
import { CDM, PSSH, Device, DeviceType, KeyType } from "@li0ard/widevine";

const device = Device.decode(
    DeviceType.ANDROID,
    Buffer.from("....", "base64"),
    Buffer.from("....", "base64")
);

const cdm = new CDM(device);
const sessionId = cdm.open();

const pssh = PSSH.decode(Buffer.from("....", "base64"));

const challenge = cdm.get_license_challenge(sessionId, pssh);
const license = await (await fetch(`https://cwip-shaka-proxy.appspot.com/no_auth`, {
    method: "POST",
    body: challenge
})).arrayBuffer();

for(const key of cdm.parse_license(sessionId, new Uint8Array(license)))
    console.log(`- [${KeyType[key.type]}] ${bytesToHex(key.kid)}:${bytesToHex(key.key)}`);

cdm.close(sessionId);
```

## Links

- [Widevine](https://widevine.com) - Widevine (and Widevine icon) by Google
- [pywidevine](https://github.com/devine-dl/pywidevine) - An Open Source Python Implementation of Widevine CDM (greatly inspired)