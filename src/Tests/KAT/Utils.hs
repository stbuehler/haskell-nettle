
module KAT.Utils
	( KATs(..)
	, KAT_ECB(..)
	, KAT_Stream(..)
	, defaultKATs
	, defaultStreamKATs
	, concatKATs
	) where

import qualified Data.ByteString as B

-- source: crypto-cipher-tests
-- | all the KATs. use defaultKATs to prevent compilation error
-- from future expansion of this data structure
data KATs = KATs
    { kat_ECB  :: [KAT_ECB]
    } deriving (Show,Eq)

-- | ECB KAT
data KAT_ECB = KAT_ECB
    { ecbKey        :: B.ByteString -- ^ Key
    , ecbPlaintext  :: B.ByteString -- ^ Plaintext
    , ecbCiphertext :: B.ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | KAT for Stream cipher
data KAT_Stream = KAT_Stream
    { streamKey        :: B.ByteString
    , streamPlaintext  :: B.ByteString
    , streamCiphertext :: B.ByteString
    } deriving (Show,Eq)

-- | the empty KATs
defaultKATs :: KATs
defaultKATs = KATs
    { kat_ECB  = []
    }

-- | the empty KATs for stream
defaultStreamKATs :: [KAT_Stream]
defaultStreamKATs = []

concatKATs :: [KATs] -> KATs
concatKATs l = KATs (m kat_ECB)
	where
	m :: (KATs -> [x]) -> [x]
	m sel = concat $ map sel l
