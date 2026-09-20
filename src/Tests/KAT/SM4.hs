module KAT.SM4
    ( katSM4
    ) where

import HexUtils
import KAT.Utils

-- source: GB/T 32907-2016 (SM4 block cipher) test vectors and nettle tests
katSM4 :: KATs
katSM4 =
    defaultKATs
        { kat_ECB =
            [ KAT_ECB
                (hs "0123456789abcdeffedcba9876543210")
                (hs "0123456789abcdeffedcba9876543210")
                (hs "681edf34d206965e86b3e94f536e4246")
            , KAT_ECB
                (hs "0123456789abcdeffedcba9876543210")
                (hs "000102030405060708090a0b0c0d0e0f")
                (hs "06989c613da668ad2a8df782e1a8f96a")
            , KAT_ECB
                (hs "0123456789abcdeffedcba9876543210")
                ( hs
                    "000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f"
                )
                ( hs
                    "06989c613da668ad2a8df782e1a8f96a 4b910651754b5553f10cfa0c8a09e9e5"
                )
            ]
        }
