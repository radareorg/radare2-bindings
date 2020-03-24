
{-#LANGUAGE ForeignFunctionInterface #-}

import Foreign.C.Types
import Foreign.Ptr
import Foreign.Storable

#include <r_core.h>

{#enum RCoreVisualMode {underscoreToCase} deriving (Eq)#}

