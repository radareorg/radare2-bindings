{-#LANGUAGE ForeignFunctionInterface #-}
{-#LANGUAGE DeriveDataTypeable #-}

import Data.Typeable (Typeable)
import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable

#include <stdint.h>
#include <r_core.h>

type UInt8 = {#type uint8_t #}
type UInt16 = {#type uint16_t #}
type UInt32 = {#type uint32_t #}
type UInt64 = {#type uint64_t #}
{#typedef ut8 UInt8 #}
{#typedef ut16 UInt16 #}
{#typedef ut32 UInt32 #}
{#typedef ut64 UInt64 #}
{#default in `Ptr UInt8' [ut8 *] id#}
{#default in `Ptr UInt16' [ut16 *] id#}
{#default in `Ptr UInt32' [ut32 *] id#}
{#default in `Ptr UInt64' [ut64 *] id#}

{#enum RCoreVisualMode {underscoreToCase} deriving (Eq)#}

data RCoreUndo = RCoreUndo {action :: String, revert :: String, tstamp :: UInt64, offset :: UInt64}
{#pointer *RCoreUndo as RCoreUndoPtr -> RCoreUndo#}

{#fun pure r_core_get_theme as ^ {} -> `String' #}


