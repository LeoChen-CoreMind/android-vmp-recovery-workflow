from .apk_ingest import ApkIngest
from .apk_unpack_repack import ApkUnpackRepack
from .dex_extract import DexExtract
from .dex_restore import DexRestore
from .ida_export import IdaExport
from .independent_validate import IndependentValidate
from .native_sim import NativeSim
from .so_dump import SoDump
from .so_repair import SoRepair
from .target_confirm import TargetConfirm
from .vm_static import VmStatic

PLUGINS = {plugin.id: plugin for plugin in [
    ApkIngest(), DexExtract(), TargetConfirm(), SoDump(), SoRepair(), IdaExport(),
    VmStatic(), NativeSim(), DexRestore(), IndependentValidate(),
    ApkUnpackRepack(),
]}

__all__ = ["PLUGINS"]
