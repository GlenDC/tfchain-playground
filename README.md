# tfchain-playground

A playground for mini tfchain-related experiments.

## Experiments

### MultiSigScanner

An experiment to test how feasable it is to scan —using a public web explorer— a seed for all multisig wallets it is part of.

> NOTE: It is important to know that this experimental scanner does not assume the user knows the key range,
> and instead scans as far as it has to go, with the assumption that the key range only expands
> if a key is used in the last `1024` keys of the currently known range.

#### Conclusion

Seems reasonable in situations where the user doesn't mind to wait a bit, as tests show it takes up to 10 seconds
for a wallet with about 3500 keys (scanning up to around 4000).

#### How to run

```log
$ go run ./cmd/multisigscanner/main.go > scan.log 2>&1
Seed Mnemonic: 
2018/08/02 19:39:11 scanning keys for multisig addresses using https://explorer.testnet.threefoldtoken.com...
2018/08/02 19:39:12 send key 0/2025 to scan (max keys: 100000000)...

... 

2018/08/02 19:39:12 send key 70/2025 to scan (max keys: 100000000)...
2018/08/02 19:39:12 send key 71/2025 to scan (max keys: 100000000)...
2018/08/02 19:39:12 ignorning uh (2) 014d60f6ab43da4f5c16acfb2f7fca1f6cf994e5d00a68954f53aeda0f99383740d6f062a8b5d5 as we received status code 400
2018/08/02 19:39:12 ignorning uh (5) 0109d94fb4fa1abc17fae699435de8ceabde621940463e76f8c5266bb39113877426f8d75961b0 as we received status code 400
2018/08/02 19:39:12 ignorning uh (1) 0150acb0a949916a605ac62db20ba4c64e2d399412a20a088fc994f28373e0572e150ecb2f0d5e as we received status code 400
2018/08/02 19:39:12 send key 72/2025 to scan (max keys: 100000000)...
2018/08/02 19:39:12 send key 73/2025 to scan (max keys: 100000000)...

...

2018/08/02 19:39:12 send key 101/2025 to scan (max keys: 100000000)...
2018/08/02 19:39:12 uh (25) 0199f4f21fc13ceb22da91d4b1701e67556a7c23f118bc5b1b15b132433d07b2496e093c4f4cd6 is not part of any multisig wallet
2018/08/02 19:39:12 send key 102/2025 to scan (max keys: 100000000)...
2018/08/02 19:39:12 uh (26) 01a41da15cfd2aa4ee60d36ef1ec3ca303037c0c07092e939a7a38232a96f4d3265fea619c6389 is not part of any multisig wallet
2018/08/02 19:39:12 send key 103/2025 to scan (max keys: 100000000)...
2018/08/02 19:39:12 ignorning uh (32) 01eb038ea13eb5a0547d5d0a6f73857b38cc0e3123a7adfb1afea0290523fe4e1de4b70eba9519 as we received status code 400
2018/08/02 19:39:12 send key 104/2025 to scan (max keys: 100000000)...

...

2018/08/02 19:39:17 ignorning uh (2504) 01783dc58cf096aa9a4f9e4bdc23ea2b5fd5acec6a05c8e2c8926bd8351d3de1da9ad3028dded0 as we received status code 400
2018/08/02 19:39:17 send key 2571/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 ignorning uh (2499) 016005651d09744e1feeaed4211cf4388ebb592864e56fbd15aedbaa6360c10b7bea52aedad68b as we received status code 400
2018/08/02 19:39:17 send key 2572/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 uh (2500) 01b650391f06c6292ecf892419dd059c6407bf8bb7220ac2e2a2df92e948fae9980a451ac0a6aa is part of 1 multisig wallets: {0359aaaa311a10efd7762953418b828bfe2d4e2111dfe6aaf82d4adf6f2fb385688d7f86510d37}
2018/08/02 19:39:17 send key 2573/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 uh (2503) 01b447f395035669d8b12395e35e4fadebef97b3b1a78d43bfb3202ed87d8d2a1a5e2f5559d2af is part of 1 multisig wallets: {0308750198054e77953a11a065718b94914627a368e17dcade9625913c79b65386ffbc3e8c835a}
2018/08/02 19:39:17 send key 2574/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 ignorning uh (2507) 0138b23572b8d3362ecda35c0b9a88c7d0e1f2e5655ce9071dcba1f571b7451535a91cf55ca944 as we received status code 400
2018/08/02 19:39:17 send key 2575/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 uh (2505) 0105765ed4881fed0770cb6db6982952382ed42eb19e57d6e9874277083694150932c34d1e619b is not part of any multisig wallet
2018/08/02 19:39:17 send key 2576/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 uh (2506) 01f538aed78b986ad00a43f75127fac85546f779286b277c1e917f6299ead4c179090f9e6fb078 is not part of any multisig wallet
2018/08/02 19:39:17 send key 2577/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 uh (2502) 016be573258cd26a9a5e643b6bdcfaac0cfce3bbc8d068a48b2f45c21654419f160d410b66c815 is not part of any multisig wallet
2018/08/02 19:39:17 send key 2578/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 uh (2501) 0114df42a3bb8303a745d23c47062a1333246b3adac446e6d62f4de74f5223faf4c2da465e76af is part of 3 multisig wallets: {0308750198054e77953a11a065718b94914627a368e17dcade9625913c79b65386ffbc3e8c835a 03321a17f048df123c1937ae92ed80a2fe16a5b13c95b4438be582b468d03f81638c3711300288 0359aaaa311a10efd7762953418b828bfe2d4e2111dfe6aaf82d4adf6f2fb385688d7f86510d37}
2018/08/02 19:39:17 send key 2579/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 uh (2508) 0112221af172280b3703428e016ab83bfcff2b11f4d559350b76e4bdfed429654c30a9787e6abb is not part of any multisig wallet
2018/08/02 19:39:17 send key 2580/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 uh (2509) 01760678721c92e057f1179ef64c08b911e8d2a89f67ba5aff73fa81d734b49b6794e07d93fab2 is not part of any multisig wallet
2018/08/02 19:39:17 send key 2581/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 ignorning uh (2512) 01c33cad4ac3c32eb7b50d2ec7c8878f45ce22521616aa7a6f59ef191428126b91c3cf10ba971a as we received status code 400
2018/08/02 19:39:17 send key 2582/3049 to scan (max keys: 100000000)...
2018/08/02 19:39:17 ignorning uh (2514) 014459c05900c43d353367ce9d28d7fe701d82ba34186adcd91b2bdd6fb8edb9048f9937297873 as we received status code 400
2018/08/02 19:39:17 send key 2583/3049 to scan (max keys: 100000000)...

...

2018/08/02 19:39:20 ignorning uh (4066) 01dd89ce978cf148a6103677583151d2b10ed30bf8fa017e242a8c0a869a74d32bbf4c906bf077 as we received status code 400
2018/08/02 19:39:20 ignorning uh (4068) 01d869e7a47827084ebbdc4bf9d875989004f3db691212a0c048948c73c72d82a86abbfafc9477 as we received status code 400
2018/08/02 19:39:20 ignorning uh (4069) 012b0abf1d35bf82a0d714cdcb2fde74dfa6798bb1e5c1136079f26561b3357b6abcdbb5a5c5bc as we received status code 400
2018/08/02 19:39:20 ignorning uh (4070) 01f31b56cbc5d6a3ee8de91923a6551af607d38d4da951f5b496b0704328c0f6ec18036630d19a as we received status code 400
2018/08/02 19:39:20 ignorning uh (4071) 01c6615e4410ac27922206a0c404f8d997de2a64f7f21d945a9df850357dcaa798bada95a9496c as we received status code 400
2018/08/02 19:39:20 ignorning uh (4072) 019c38877dd86742fd48d035003848a6d826d18c732b60c75390f6ae7d198485c5eb1b7d28cf41 as we received status code 400
2018/08/02 19:39:20 scan channel 4/8 closed
2018/08/02 19:39:20 scan channel 5/8 closed
2018/08/02 19:39:20 scan channel 8/8 closed
2018/08/02 19:39:20 scan channel 1/8 closed
2018/08/02 19:39:20 scan channel 7/8 closed
2018/08/02 19:39:20 scan channel 3/8 closed
2018/08/02 19:39:20 scan channel 2/8 closed
2018/08/02 19:39:20 scan channel 6/8 closed
used 20 wallet address(es):
0199f4f21fc13ceb22da91d4b1701e67556a7c23f118bc5b1b15b132433d07b2496e093c4f4cd6 01a41da15cfd2aa4ee60d36ef1ec3ca303037c0c07092e939a7a38232a96f4d3265fea619c6389 01b650391f06c6292ecf892419dd059c6407bf8bb7220ac2e2a2df92e948fae9980a451ac0a6aa 01b447f395035669d8b12395e35e4fadebef97b3b1a78d43bfb3202ed87d8d2a1a5e2f5559d2af 016be573258cd26a9a5e643b6bdcfaac0cfce3bbc8d068a48b2f45c21654419f160d410b66c815 0105765ed4881fed0770cb6db6982952382ed42eb19e57d6e9874277083694150932c34d1e619b 0114df42a3bb8303a745d23c47062a1333246b3adac446e6d62f4de74f5223faf4c2da465e76af 01f538aed78b986ad00a43f75127fac85546f779286b277c1e917f6299ead4c179090f9e6fb078 01760678721c92e057f1179ef64c08b911e8d2a89f67ba5aff73fa81d734b49b6794e07d93fab2 0112221af172280b3703428e016ab83bfcff2b11f4d559350b76e4bdfed429654c30a9787e6abb 015f233d889391479f17bfb9662272760caa88b7e2062d3efc32e8d51867fdad1a08ba2e938221 01135781890b5e86d0a843b3eabd744460ca6692e9b7df8febdaf05f4dfbd386ccdb4565b14510 01a75b03da048b933d2d04cc22283c170eb8300f1806b02bf7138f4092a3a385703864e427d165 01b20e5cfd38dd4f3fe85d04b43a04d603e8edb2c3978d6645c9fa94399c7e9603e5bf076b90e0 01dd80a9fb72a8674a8ca28f567d3fc8d1f137bb52e01fffa8152dede7029fffd73c1d00eae73e 016100180670694a77c8192e552fb971e148ef0d41b558530083dc073ef084acf1fa1d134bbad7 01a6b9d81b8f0ceab779d0a72c49de07a89a8871614fb8751cac3c13b3e427539617545c913b4e 019af4e42ad763279bad4e953ffac99612e8e7f3e9fc3205c29d3f1514f7eabc48cb8607b2d6e7 01f59e284402403d769f5d9e43d57bbac53e5128efa8e45bdeb0308ec220bee20af07e385ebf4d 011bd07f35bd4e3bd7440c6d61b4c4cd616e2a513691d74fee4327f22c9b007b12bdec6d30a62d
found 3 multisig address(es):
0308750198054e77953a11a065718b94914627a368e17dcade9625913c79b65386ffbc3e8c835a 03321a17f048df123c1937ae92ed80a2fe16a5b13c95b4438be582b468d03f81638c3711300288 0359aaaa311a10efd7762953418b828bfe2d4e2111dfe6aaf82d4adf6f2fb385688d7f86510d37
time it took to scan 4073 keys of given seed: 8.650348923s
```
