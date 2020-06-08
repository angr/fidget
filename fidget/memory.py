# Register a new plugin preset fidget_preset with the special memory filler
from angr import SimState
from angr.storage.memory_mixins import (HexDumperMixin,
        RegionCategoryMixin,
        MemoryRegionMetaMixin,
        StaticFindMixin,
        AbstractMergerMixin,
        SmartFindMixin,
        UnwrapperMixin,
        NameResolutionMixin,
        DataNormalizationMixin,
        SimplificationMixin,
        InspectMixinHigh,
        ActionsMixinHigh,
        UnderconstrainedMixin,
        SizeConcretizationMixin,
        SizeNormalizationMixin,
        AddressConcretizationMixin,
        ActionsMixinLow,
        ConditionalMixin,
        ConvenientMappingsMixin,
        DirtyAddrsMixin,
        StackAllocationMixin,
        ClemoryBackerMixin,
        DictBackerMixin,
        PrivilegedPagingMixin,
        ListPagesMixin,
        SpecialFillerMixin,
        DefaultFillerMixin,
        SymbolicMergerMixin,
        PagedMemoryMixin,
)


class SpecialFillerMemory(
        HexDumperMixin,
        SmartFindMixin,
        UnwrapperMixin,
        NameResolutionMixin,
        DataNormalizationMixin,
        SimplificationMixin,
        InspectMixinHigh,
        ActionsMixinHigh,
        UnderconstrainedMixin,
        SizeConcretizationMixin,
        SizeNormalizationMixin,
        AddressConcretizationMixin,
        ActionsMixinLow,
        ConditionalMixin,
        ConvenientMappingsMixin,
        DirtyAddrsMixin,
        StackAllocationMixin,
        ClemoryBackerMixin,
        DictBackerMixin,
        PrivilegedPagingMixin,
        ListPagesMixin,
        SpecialFillerMixin,
        DefaultFillerMixin,
        SymbolicMergerMixin,
        PagedMemoryMixin,
):
    pass


class SpecialFillerRegionedMemory(
        RegionCategoryMixin,
        MemoryRegionMetaMixin,
        StaticFindMixin,
        UnwrapperMixin,
        NameResolutionMixin,
        DataNormalizationMixin,
        SimplificationMixin,
        SizeConcretizationMixin,
        SizeNormalizationMixin,
        AddressConcretizationMixin,
        ConvenientMappingsMixin,
        DirtyAddrsMixin,
        ClemoryBackerMixin,
        DictBackerMixin,
        ListPagesMixin,
        SpecialFillerMixin,
        DefaultFillerMixin,
        AbstractMergerMixin,
        PagedMemoryMixin,
):
    pass


def register_fidget_preset():
    if 'fidget_plugins' in SimState._presets:
        return
    fidget_preset = SimState._presets['default'].copy()
    fidget_preset.add_default_plugin('sym_memory', SpecialFillerMemory)
    SimState.register_preset("fidget_plugins", fidget_preset)

