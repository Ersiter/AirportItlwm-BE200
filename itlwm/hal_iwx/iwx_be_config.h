#pragma once

namespace IwxBE {
enum Family { None, GL, BZ };

inline Family pciFamily(unsigned device)
{
    switch (device) {
    case 0x272b: return GL;
    case 0xa840:
    case 0x7740:
    case 0x4d40: return BZ;
    default: return None;
    }
}

inline bool macMatches(Family family, unsigned mac)
{
    return family == GL ? mac == IWL_CFG_MAC_TYPE_GL :
        family == BZ && (mac == IWL_CFG_MAC_TYPE_BZ || mac == IWL_CFG_MAC_TYPE_BZ_W);
}

inline unsigned bzStep(unsigned mac, unsigned cnvi)
{
    unsigned step = (cnvi >> 24) & 0xf;
    if (mac == IWL_CFG_MAC_TYPE_BZ_W || ((cnvi & 0xfff) == 0x930 && step == 0))
        return 1;
    return step;
}

inline uint32_t mappedRF(unsigned crf, unsigned cnvi, unsigned otp)
{
    unsigned type;
    switch (crf & 0xfff) {
    case 0x910: type = IWL_CFG_RF_TYPE_FM; break;
    case 0x410: type = IWL_CFG_RF_TYPE_GF; break;
    default: return 0;
    }
    return (type << 12) | (((crf >> 24) & 0xf) << 8) |
        (((crf & (1U << 19)) || (otp & (1U << 4))) ? (1U << 28) : 0) |
        (((cnvi & (1U << 19)) || (otp & (1U << 5))) ? (1U << 29) : 0);
}

inline bool reducedCapability(uint32_t rfid, uint32_t sku)
{
    return CSR_HW_RFID_TYPE(rfid) == IWL_CFG_RF_TYPE_FM && (sku & (1U << 25));
}

inline bool supports320(uint32_t rfid, uint32_t sku, bool integrated, unsigned linkSpeed)
{
    return !reducedCapability(rfid, sku) && (integrated || linkSpeed >= 3);
}

struct Selection {
    Family family;
    unsigned max_api;
    unsigned selected_api;
    char prefix[40];
    char firmware[64];
    char pnvm[64];
};

inline bool makePrefix(Selection &selection, unsigned mac, unsigned step, uint32_t rfid)
{
    const char *rf;
    unsigned rfstep = CSR_HW_RFID_STEP(rfid);
    bool cdb = CSR_HW_RFID_IS_CDB(rfid);
    if (!macMatches(selection.family, mac) || step > 3 || rfstep > 3)
        return false;
    switch (CSR_HW_RFID_TYPE(rfid)) {
    case IWL_CFG_RF_TYPE_FM: rf = "fm"; break;
    case IWL_CFG_RF_TYPE_GF: rf = "gf"; break;
    default: return false;
    }
    if (selection.family == GL && (CSR_HW_RFID_TYPE(rfid) != IWL_CFG_RF_TYPE_FM || cdb))
        return false;
    int length = snprintf(selection.prefix, sizeof(selection.prefix), "iwlwifi-%s-%c0-%s%s-%c0",
        selection.family == GL ? "gl" : "bz", 'a' + step, rf, cdb ? "4" : "", 'a' + rfstep);
    return length > 0 && (unsigned)length < sizeof(selection.prefix);
}

inline unsigned apiAt(const Selection &selection, unsigned index)
{
    const unsigned adapted[] = {92, 86};
    unsigned limit = selection.max_api;
    if (!limit)
        limit = 92;
    for (unsigned api : adapted) {
        if (api > limit || (api == 86 && selection.family != GL))
            continue;
        if (index-- == 0)
            return api;
    }
    return 0;
}

inline bool candidate(Selection &selection, unsigned index)
{
    unsigned api = apiAt(selection, index);
    if (!api)
        return false;
    selection.selected_api = api;
    snprintf(selection.firmware, sizeof(selection.firmware), "%s-%u.ucode", selection.prefix, api);
    // GL86 retains its shipped calibration; GL92 uses the independently pinned resource.
    if (api == 92 && strcmp(selection.prefix, "iwlwifi-gl-c0-fm-c0") == 0)
        snprintf(selection.pnvm, sizeof(selection.pnvm), "%s-92.pnvm", selection.prefix);
    else
        snprintf(selection.pnvm, sizeof(selection.pnvm), "%s.pnvm", selection.prefix);
    return true;
}

template <typename Lookup>
inline bool compatible(unsigned api, bool mld, Lookup version)
{
    if ((api != 86 && api != 92) || !mld)
        return false;
    unsigned phy = version(1, 8), link = version(3, 9), sta = version(3, 0x0a);
    return phy >= 3 && phy <= 5 &&
        (link == 1 || link == 2 || (api == 86 && link == IWX_FW_CMD_VER_UNKNOWN)) &&
        version(3, 8) == 2 && (sta == 1 || sta == 2 || sta == IWX_FW_CMD_VER_UNKNOWN) &&
        version(5, 0x18) == 1 && version(5, 0x17) == 3 &&
        version(5, 0x16) == 2 && version(5, 8) == 2;
}
}
