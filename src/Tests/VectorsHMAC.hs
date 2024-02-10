{-# LANGUAGE OverloadedStrings, Safe #-}

module VectorsHMAC
	( hmacTestVectors
	, findHmacTestVectors
	) where

import HexUtils
import qualified Data.ByteString as B

hmacTestVectors :: [(String, [(B.ByteString, B.ByteString, String)])]
hmacTestVectors =
-- Wikipedia on HMAC
	[ ( "HMAC-MD5",
		[ ("", "", "74e6f7298a9c2d168935f58c001bad88")
		, ("key", "The quick brown fox jumps over the lazy dog", "80070713463e7749b90c2dc24911e275")
		])
	, ( "HMAC-SHA1",
		[ ("", "", "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d")
		, ("key", "The quick brown fox jumps over the lazy dog", "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")
		])
	, ( "HMAC-SHA256",
		[ ("", "", "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")
		, ("key", "The quick brown fox jumps over the lazy dog", "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
		])

	, ( "HMAC-MD5",
--  /* Test vectors for md5, from RFC-2202 */
		[ (hs "0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b", "Hi There", "9294727a3638bb1c 13f48ef8158bfc9d")
		, ("Jefe", "what do ya want for nothing?", "750c783e6ab0b503 eaa86e310a5db738")
		, (hs "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa", hs "dddddddddddddddd dddddddddddddddd dddddddddddddddd dddddddddddddddd dddddddddddddddd dddddddddddddddd dddd", "56be34521d144c88 dbb8c733f0e8b3f6")
		, (hs "0102030405060708 090a0b0c0d0e0f10 1112131415161718 19", hs "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcd", "697eaf0aca3a3aea 3a75164746ffaa79")
		, (hs "0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c", "Test With Truncation", "56461ef2342edc00 f9bab995")
		, (hs "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa", "Test Using Larger Than Block-Size Key - Hash Key First", "6b1ab7fe4bd7bf8f 0b62e6ce61b9d0cd")
		, (hs "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa", "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", "6f630fad67cda0ee 1fb1f562db3aa53e")
--  /* Additional test vectors, from Daniel Kahn Gillmor */
		, ("monkey monkey monkey monkey", "", "e84db42a188813f30a15e611d64c7869")
		, ("monkey monkey monkey monkey", "a", "123662062e67c2aab371cc49db0df134")
		, ("monkey monkey monkey monkey", "38", "0a46cc10a49d4b7025c040c597bf5d76")
		, ("monkey monkey monkey monkey", "abc", "d1f4d89f0e8b2b6ed0623c99ec298310")
		, ("monkey monkey monkey monkey", "message digest", "1627207b9bed5009a4f6e9ca8d2ca01e")
		, ("monkey monkey monkey monkey", "abcdefghijklmnopqrstuvwxyz", "922aae6ab3b3a29202e21ce5f916ae9a")
		, ("monkey monkey monkey monkey", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "ede9cb83679ba82d88fbeae865b3f8fc")
		, ("monkey monkey monkey monkey", "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "939dd45512ee3a594b6654f6b8de27f7")
		])
	, ( "HMAC-RIPEMD160",
--  /* Test vectors for ripemd160, from
--     http://homes.esat.kuleuven.be/~bosselae/ripemd160.html */
		[ (hs "00112233445566778899aabbccddeeff01234567", "", "cf387677bfda8483e63b57e06c3b5ecd8b7fc055")
		, (hs "00112233445566778899aabbccddeeff01234567", "a", "0d351d71b78e36dbb7391c810a0d2b6240ddbafc")
		, (hs "00112233445566778899aabbccddeeff01234567", "abc", "f7ef288cb1bbcc6160d76507e0a3bbf712fb67d6")
		, (hs "00112233445566778899aabbccddeeff01234567", "message digest", "f83662cc8d339c227e600fcd636c57d2571b1c34")
		, (hs "00112233445566778899aabbccddeeff01234567", "abcdefghijklmnopqrstuvwxyz", "843d1c4eb880ac8ac0c9c95696507957d0155ddb")
		, (hs "00112233445566778899aabbccddeeff01234567", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "60f5ef198a2dd5745545c1f0c47aa3fb5776f881")
		, (hs "00112233445566778899aabbccddeeff01234567", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "e49c136a9e5627e0681b808a3b97e6a6e661ae79")
--  /* Other key */
		, (hs "0123456789abcdeffedcba987654321000112233", "", "fe69a66c7423eea9c8fa2eff8d9dafb4f17a62f5")
		, (hs "0123456789abcdeffedcba987654321000112233", "a", "85743e899bc82dbfa36faaa7a25b7cfd372432cd")
		, (hs "0123456789abcdeffedcba987654321000112233", "abc", "6e4afd501fa6b4a1823ca3b10bd9aa0ba97ba182")
		, (hs "0123456789abcdeffedcba987654321000112233", "message digest", "2e066e624badb76a184c8f90fba053330e650e92")
		, (hs "0123456789abcdeffedcba987654321000112233", "abcdefghijklmnopqrstuvwxyz", "07e942aa4e3cd7c04dedc1d46e2e8cc4c741b3d9")
		, (hs "0123456789abcdeffedcba987654321000112233", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "b6582318ddcfb67a53a67d676b8ad869aded629a")
		, (hs "0123456789abcdeffedcba987654321000112233", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "f1be3ee877703140d34f97ea1ab3a07c141333e2")
		])
	, ( "HMAC-SHA1",
--  /* Test vectors for sha1, from RFC-2202 */
		[ (hs "0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b 0b0b0b0b", "Hi There", "b617318655057264 e28bc0b6fb378c8e f146be00")
		, ("Jefe", "what do ya want for nothing?", "effcdf6ae5eb2fa2 d27416d5f184df9c 259a7c79")
		, (hs "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaa", hs "dddddddddddddddd dddddddddddddddd dddddddddddddddd dddddddddddddddd dddddddddddddddd dddddddddddddddd dddd", "125d7342b9ac11cd 91a39af48aa17b4f 63f175d3")
		, (hs "0102030405060708 090a0b0c0d0e0f10 1112131415161718 19", hs "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcd", "4c9007f4026250c6 bc8414f9bf50c86c 2d7235da")
		, (hs "0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c 0c0c0c0c", "Test With Truncation", "4c1a03424b55e07f e7f27be1")
		, (hs "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa", "Test Using Larger Than Block-Size Key - Hash Key First", "aa4ae5e15272d00e 95705637ce8a3b55 ed402112")
		, (hs "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa", "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", "e8e99d0f45237d78 6d6bbaa7965c7808 bbff1a91")
		])
	, ( "HMAC-SHA224",
--  /* Test vectors for sha224, from RFC 4231 */
		[ (hs "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 0b0b0b0b", "Hi There", "896fb1128abbdf196832107cd49df33f 47b4b1169912ba4f53684b22")
		, ("Jefe", "what do ya want for nothing?", "a30e01098bc6dbbf45690f3a7e9e6d0f 8bbea2a39e6148008fd05e44")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaa", hs "dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddd", "7fb3cb3588c6c1f6ffa9694d7d6ad264 9365b0c1f65d69d1ec8333ea")
		, (hs "0102030405060708090a0b0c0d0e0f10 111213141516171819", hs "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcd", "6c11506874013cac6a2abc1bb382627c ec6a90d86efc012de7afec5a")
		, (hs "0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c 0c0c0c0c", "Test With Truncation", "0e2aea68a90c8d37c988bcdb9fca6fa8")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaa", "Test Using Larger Than Block-Size Key - Hash Key First", "95e9a0db962095adaebe9b2d6f0dbce2 d499f112f2d2b7273fa6870e")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaa", "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "3a854166ac5d9f023f54d517d0b39dbd 946770db9c2b95c9f6f565d1")
--  /* Additional test vectors, from Daniel Kahn Gillmor */
		, ("monkey monkey monkey monkey", "", "d12a49ae38177ffeaa548b2148bb5238 60849772d9391e675b103d89")
		, ("monkey monkey monkey monkey", "a", "b04ff8522f904f553970bfa8ad3f0086 bce1e8580affd8a12c94e31a")
		, ("monkey monkey monkey monkey", "38", "afcfb5511f710334f9350f57faec3c08 764b4bd126a6840f4347f116")
		, ("monkey monkey monkey monkey", "abc", "9df9907af127900c909376893565c6cf 2d7db244fdc4277da1e0b679")
		, ("monkey monkey monkey monkey", "message digest", "254ebf6b8ddd7a3271b3d9aca1699b0c 0bfb7df61e8a114922c88d27")
		, ("monkey monkey monkey monkey", "abcdefghijklmnopqrstuvwxyz", "6ec5bffba5880c3234a6cf257816e4d5 35ab178a7f12929769e378fb")
		, ("monkey monkey monkey monkey", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "5f768179dbb29ca722875d0f461a2e2f 597d0210340a84df1a8e9c63")
		, ("monkey monkey monkey monkey", "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "c7667b0d7e56b2b4f6fcc1d8da9e22da a1556f44c47132a87303c6a2")
		])
	, ( "HMAC-SHA256",
--  /* Test vectors for sha256, from RFC 4231 */
		[ (hs "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 0b0b0b0b", "Hi There", "b0344c61d8db38535ca8afceaf0bf12b 881dc200c9833da726e9376c2e32cff7")
		, ("Jefe", "what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c7 5a003f089d2739839dec58b964ec3843")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaa", hs "dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddd", "773ea91e36800e46854db8ebd09181a7 2959098b3ef8c122d9635514ced565fe")
		, (hs "0102030405060708090a0b0c0d0e0f10 111213141516171819", hs "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcd", "82558a389a443c0ea4cc819899f2083a 85f0faa3e578f8077a2e3ff46729665b")
		, (hs "0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c 0c0c0c0c", "Test With Truncation", "a3b6167473100ee06e0c796c2955552b")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaa", "Test Using Larger Than Block-Size Key - Hash Key First", "60e431591ee0b67f0d8a26aacbf5b77f 8e0bc6213728c5140546040f0ee37f54")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaa", "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "9b09ffa71b942fcb27635fbcd5b0e944 bfdc63644f0713938a7f51535c3a35e2")
--  /* Additional test vectors for sha256, from
--     draft-ietf-ipsec-ciph-sha-256-01.txt */
--  /* Test Case #1: HMAC-SHA-256 with 3-byte input and 32-byte key */
		, (hs "0102030405060708 090a0b0c0d0e0f10 1112131415161718 191a1b1c1d1e1f20", "abc", "a21b1f5d4cf4f73a 4dd939750f7a066a 7f98cc131cb16a66 92759021cfab8181")
--  /* Test Case #2: HMAC-SHA-256 with 56-byte input and 32-byte key */
		, (hs "0102030405060708 090a0b0c0d0e0f10 1112131415161718 191a1b1c1d1e1f20", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "104fdc1257328f08 184ba73131c53cae e698e36119421149 ea8c712456697d30")
--  /* Test Case #3: HMAC-SHA-256 with 112-byte (multi-block) input and 32-byte key */
		, (hs "0102030405060708 090a0b0c0d0e0f10 1112131415161718 191a1b1c1d1e1f20", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "470305fc7e40fe34 d3eeb3e773d95aab 73acf0fd060447a5 eb4595bf33a9d1a3")
--  /* Test Case #4:  HMAC-SHA-256 with 8-byte input and 32-byte key */
		, (hs "0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b", "Hi There", "198a607eb44bfbc6 9903a0f1cf2bbdc5 ba0aa3f3d9ae3c1c 7a3b1696a0b68cf7")
--  /* Test Case #6: HMAC-SHA-256 with 50-byte input and 32-byte key */
		, (hs "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa", hs "dddddddddddddddd dddddddddddddddd dddddddddddddddd dddddddddddddddd dddddddddddddddd dddddddddddddddd dddd", "cdcb1220d1ecccea 91e53aba3092f962 e549fe6ce9ed7fdc 43191fbde45c30b0")
--  /* Test Case #7: HMAC-SHA-256 with 50-byte input and 37-byte key */
		, (hs "0102030405060708 090a0b0c0d0e0f10 1112131415161718 191a1b1c1d1e1f20 2122232425", hs "cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcd cdcd", "d4633c17f6fb8d74 4c66dee0f8f07455 6ec4af55ef079985 41468eb49bd2e917")
--  /* Test Case #8: HMAC-SHA-256 with 20-byte input and 32-byte key */
		, (hs "0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c", "Test With Truncation", "7546af01841fc09b 1ab9c3749a5f1c17")
--  /* Test Case #9: HMAC-SHA-256 with 54-byte input and 80-byte key */
		, (hs "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa", "Test Using Larger Than Block-Size Key - Hash Key First", "6953025ed96f0c09 f80a96f78e6538db e2e7b820e3dd970e 7ddd39091b32352f")
--  /* Test Case #10: HMAC-SHA-256 with 73-byte (multi-block) input and 80-byte key */
		, (hs "aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa", "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", "6355ac22e890d0a3 c8481a5ca4825bc8 84d3e7a1ff98a2fc 2ac7d8e064c3b2e6")
--  /* Additional test vectors, from Daniel Kahn Gillmor */
		, ("monkey monkey monkey monkey", "", "5c780648c90d121c50091c3a0c3afc1f 4ab847528005d99d9821ad3f341b651a")
		, ("monkey monkey monkey monkey", "a", "6142364c0646b0cfe426866f21d613e0 55a136a7d9b45d85685e080a09cec463")
		, ("monkey monkey monkey monkey", "38", "e49aa7839977e130ad87b63da9d4eb7b 263cd5a27c54a7604b6044eb35901171")
		, ("monkey monkey monkey monkey", "abc", "e5ef49f545c7af933a9d18c7c562bc91 08583fd5cf00d9e0db351d6d8f8e41bc")
		, ("monkey monkey monkey monkey", "message digest", "373b04877180fea27a41a8fb8f88201c a6268411ee3c80b01a424483eb9156e1")
		, ("monkey monkey monkey monkey", "abcdefghijklmnopqrstuvwxyz", "eb5945d56eefbdb41602946ea6448d53 86b08d7d801a87f439fab52f8bb9736e")
		, ("monkey monkey monkey monkey", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "3798f363c57afa6edaffe39016ca7bad efd1e670afb0e3987194307dec3197db")
		, ("monkey monkey monkey monkey", "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "c89a7039a62985ff813fe4509b918a43 6d7b1ffd8778e2c24dec464849fb6128")
		])
	, ( "HMAC-SHA384",
--  /* Test vectors for sha384, from RFC 4231 */
		[ (hs "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 0b0b0b0b", "Hi There", "afd03944d84895626b0825f4ab46907f 15f9dadbe4101ec682aa034c7cebc59c faea9ea9076ede7f4af152e8b2fa9cb6")
		, ("Jefe", "what do ya want for nothing?", "af45d2e376484031617f78d2b58a6b1b 9c7ef464f5a01b47e42ec3736322445e 8e2240ca5e69e2c78b3239ecfab21649")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaa", hs "dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddd", "88062608d3e6ad8a0aa2ace014c8a86f 0aa635d947ac9febe83ef4e55966144b 2a5ab39dc13814b94e3ab6e101a34f27")
		, (hs "0102030405060708090a0b0c0d0e0f10 111213141516171819", hs "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcd", "3e8a69b7783c25851933ab6290af6ca7 7a9981480850009cc5577c6e1f573b4e 6801dd23c4a7d679ccf8a386c674cffb")
		, (hs "0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c 0c0c0c0c", "Test With Truncation", "3abf34c3503b2a23a46efc619baef897")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaa", "Test Using Larger Than Block-Size Key - Hash Key First", "4ece084485813e9088d2c63a041bc5b4 4f9ef1012a2b588f3cd11f05033ac4c6 0c2ef6ab4030fe8296248df163f44952")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaa", "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "6617178e941f020d351e2f254e8fd32c 602420feb0b8fb9adccebb82461e99c5 a678cc31e799176d3860e6110c46523e")
		])
	, ( "HMAC-SHA512",
--  /* Test vectors for sha512, from RFC 4231 */
		[ (hs "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 0b0b0b0b", "Hi There", "87aa7cdea5ef619d4ff0b4241a1d6cb0 2379f4e2ce4ec2787ad0b30545e17cde daa833b7d6b8a702038b274eaea3f4e4 be9d914eeb61f1702e696c203a126854")
		, ("Jefe", "what do ya want for nothing?", "164b7a7bfcf819e2e395fbe73b56e0a3 87bd64222e831fd610270cd7ea250554 9758bf75c05a994a6d034f65f8f0e6fd caeab1a34d4a6b4b636e070a38bce737")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaa", hs "dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddd", "fa73b0089d56a284efb0f0756c890be9 b1b5dbdd8ee81a3655f83e33b2279d39 bf3e848279a722c806b485a47e67c807 b946a337bee8942674278859e13292fb")
		, (hs "0102030405060708090a0b0c0d0e0f10 111213141516171819", hs "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd cdcd", "b0ba465637458c6990e5a8c5f61d4af7 e576d97ff94b872de76f8050361ee3db a91ca5c11aa25eb4d679275cc5788063 a5f19741120c4f2de2adebeb10a298dd")
		, (hs "0c0c0c0c0c0c0c0c 0c0c0c0c0c0c0c0c 0c0c0c0c", "Test With Truncation", "415fad6271580a531d4179bc891d87a6")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaa", "Test Using Larger Than Block-Size Key - Hash Key First", "80b24263c7c1a3ebb71493c1dd7be8b4 9b46d1f41b4aeec1121b013783f8f352 6b56d037e05f2598bd0fd2215d6a1e52 95e64f73f63f0aec8b915a985d786598")
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaa", "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "e37b6a775dc87dbaa4dfa9f96e5e3ffd debd71f8867289865df5a32d20cdc944 b6022cac3c4982b10d5eeb55c3e4de15 134676fb6de0446065c97440fa8c6a58")
--  /* Additional test vectors, from Daniel Kahn Gillmor */
		, ("monkey monkey monkey monkey", "", "34316413c2d6940572d0bbbf099d529d 148b424533cf562bc1b365f530e21a31 799fc51cef78060cc6f448a8e5d780c2 6cdf20d4c3e6f27fe5ef576bbd05e855")
		, ("monkey monkey monkey monkey", "a", "cf1948507378bc3ab58cb6ec87f4d456 b90d3298395c29873f1ded1e111b50fe c336ed24684bf19716efc309212f37aa 715cfb9ecccf3af13691ded167b4b336")
		, ("monkey monkey monkey monkey", "38", "b8201784216ce01b83cdd282616c6e89 644c6dfd1269ed8580bbc39b92add364 c2b2a2018cffb1915e8625e473b67d0f e54a50e475dfa0e2b1a97bac1383792c")
		, ("monkey monkey monkey monkey", "abc", "f097ee08b8c44e847a384f9fd645e35e 4816baa9791ba39d3dc611210500b044 873ee296bf1047dc06daa201a5767192 5b73b4ea59c60114881c8287d0699c83")
		, ("monkey monkey monkey monkey", "message digest", "921a441a884b83c76a8526da8e60d60d 17ded4eee5c29375e0d93717669a4c3e eba7473e95f7c1a2a85afc24a0adbc4d 6c2bdd6ca6cab8b18d19f82d4a6c51bc")
		, ("monkey monkey monkey monkey", "abcdefghijklmnopqrstuvwxyz", "640054c96f35815095617d0a8c956066 1a6ff46bfb39110333b2c52c8866abfb 59d9152c9b0948c1ed65c3fd72a8fb82 190acc8830770afe5b0c5b6414c75a77")
		, ("monkey monkey monkey monkey", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "835a4f5b3750b4c1fccfa88da2f746a4 900160c9f18964309bb736c13b59491b 8e32d37b724cc5aebb0f554c6338a3b5 94c4ba26862b2dadb59b7ede1d08d53e")
		, ("monkey monkey monkey monkey", "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "fdf83dc879e3476c8e8aceff2bf6fece 2e4f39c7e1a167845465bb549dfa5ffe 997e6c7cf3720eae51ed2b00ad2a8225 375092290edfa9d48ec7e4bc8e276088")
--  /* Additional test vectors, from draft-kelly-ipsec-ciph-sha2-01.txt */
--  /* Test case AUTH512-1: */
		, (hs "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "Hi There", "637edc6e01dce7e6742a99451aae82df 23da3e92439e590e43e761b33e910fb8 ac2878ebd5803f6f0b61dbce5e251ff8 789a4722c1be65aea45fd464e89f8f5b")
--  /* Test case AUTH512-2: */
		, ("JefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefe", "what do ya want for nothing?", "cb370917ae8a7ce28cfd1d8f4705d614 1c173b2a9362c15df235dfb251b15454 6aa334ae9fb9afc2184932d8695e397b fa0ffb93466cfcceaae38c833b7dba38")
--  /* Test case AUTH512-3: */
		, (hs "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", hs "dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddddddddddddddddddddddddddddddd dddd", "2ee7acd783624ca9398710f3ee05ae41 b9f9b0510c87e49e586cc9bf961733d8 623c7b55cebefccf02d5581acc1c9d5f b1ff68a1de45509fbe4da9a433922655")
--  /* Test case AUTH512-4 from same document seems broken. */
		])
	]

findHmacTestVectors :: Monad m => String -> m [(B.ByteString, B.ByteString, String)]
findHmacTestVectors key = case filter ((key == ) . fst) hmacTestVectors of
	[] -> error $ "unknown HMAC: " ++ key
	l -> return $ concatMap snd l
