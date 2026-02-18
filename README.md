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
    <a href="https://npmjs.com/package/@li0ard/widevine"><img src="https://img.shields.io/npm/v/@li0ard/widevine" />
    <br>
    <hr>
</p>

> [!CAUTION]
> - **Project doesn't provide private key and Client ID for any purposes**
> - **Project doesn't condone piracy or any action against the terms of the DRM systems**
> - **Project is for study and research only. Please don't use it for commercial purposes**

## Features
- Support privacy mode with Service certificates
- Support `.wvd` deserialization
- Strictly typed API

## Installation

```bash
npm i @li0ard/widevine
```

## Example

```ts
import { CDM, PSSH, Device, DeviceType, KeyType } from "@li0ard/widevine";

const device = Device.decode(
    DeviceType.ANDROID,
    Buffer.from("....", "base64"),
    Buffer.from("....", "base64")
) // Device.fromWvd(....);

const cdm = new CDM(device);
const sessionId = cdm.open();

const pssh = PSSH.decode(Buffer.from("....", "base64"));

const challenge = cdm.getLicenseChallenge(sessionId, pssh);
const license = await (await fetch(`https://cwip-shaka-proxy.appspot.com/no_auth`, {
    method: "POST",
    body: challenge
})).arrayBuffer();

for(const key of cdm.parseLicense(sessionId, new Uint8Array(license)))
    console.log(`- [${KeyType[key.type]}] ${bytesToHex(key.kid)}:${bytesToHex(key.key)}`);

cdm.close(sessionId);
```

## Links

- [Widevine](https://widevine.com) - Widevine (and Widevine icon) by Google
- [pywidevine](https://github.com/devine-dl/pywidevine) - An Open Source Python Implementation of Widevine CDM (greatly inspired)