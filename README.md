# ln-rs


WIP

library to integrate lighting into rust projects

## Implemented Lightning Backends
- :heavy_check_mark: [CLNrpc](https://github.com/ElementsProject/lightning#using-the-json-rpc-interface)
- :construction: [Greenlight](https://github.com/Blockstream/greenlight)
- :construction: [ldk-node](https://github.com/lightningdevkit/ldk-node)

## Functions Supported

| Node Functions                        | CLN RPC            | Greenlight         | LDK                |
| --------------------------------------| -------------------| ------------------ | ------------------ | 
| Wait for invoice any invoice payment  | :heavy_check_mark: | :heavy_check_mark: | :construction:     | 
| Get new invoice                       | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Pay invoice                           | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Check status of invoice               | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |

## Node Mangement Functions

| Node Functions            | CLN RPC            | Greenlight         | LDK                |
| --------------------------| -------------------| ------------------ | ------------------ | 
| Get new on-chain address  | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | 
| Pay on chain              | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | 
| Open a new channel        | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Close channel             | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| List channels             | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Get node balance          | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Connect to peer           | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| List connected peers      | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Get new invoice           | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Pay invoice               | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
 
## License

Code is under the [BSD 3-Clause License](LICENSE-BSD-3)

## Contribution

All contributions welcome.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.

## Contact

I can be contacted for comments or questions on nostr at _@thesimplekid.com (npub1qjgcmlpkeyl8mdkvp4s0xls4ytcux6my606tgfx9xttut907h0zs76lgjw) or via email tsk@thesimplekid.com.
