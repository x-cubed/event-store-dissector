# Event Store Binary Protocol Dissector for Wireshark

This LUA script gives Wireshark the ability to dissect packets used by the [Event Store](https://eventstore.org) binary protocol. The protocol uses a few fixed headers at the start of each PDU, followed by data encoded using [Protocol Buffers](https://developers.google.com/protocol-buffers/). This dissector handles the basic header information, and will make use of the [dex/protobuf_dissector](https://github.com/dex/protobuf_dissector) to handle the data, if it is installed alongside. Currently, the Protocol Buffers dissector can add significantly to the time taken to parse the file, so you can skip installing it if you just want to see the basics.

This plugin will automatically attempt to parse packets sent as TCP on port 1113. If you are running Event Store on non-standard ports, you can use the *Analyze -> Decode As...* menu item in Wireshark to decode specific TCP streams.

## Installation steps

1. Install [Wireshark](https://wireshark.org/).

2. Create your Wireshark plugins folder, if it doesn't already exist. For Windows users, it should be **%APPDATA%\Wireshark\plugins**

3. Optionally, install the [dex/protobuf_dissector](https://github.com/dex/protobuf_dissector) following the instructions in that repository.

4. Install this dissector by copying the **files** folder and the **event-store.lua** file into your Wireshark plugins folder.

5. Run Wireshark and start exploring packet captures of [Event Store](https://eventstore.org) communications.