#include "../AirportItlwm/WCL/WCL.hpp"
#include "../itl80211/openbsd/net80211/ieee80211_mbssid.h"
#include <assert.h>
#include <stdio.h>
#include <vector>

namespace {
using Bytes = std::vector<uint8_t>;
const uint8_t transmitted[6] = {2, 0, 0, 0, 1, 0x3a};

void element(Bytes &ies, uint8_t id, const Bytes &data)
{
    assert(data.size() <= 255);
    ies.push_back(id);
    ies.push_back(uint8_t(data.size()));
    ies.insert(ies.end(), data.begin(), data.end());
}

Bytes profile(const char *name, uint8_t index, const Bytes &extra = {})
{
    Bytes own = {83, 2, 0x11, 0x11};
    element(own, 0, Bytes(name, name + strlen(name)));
    element(own, 85, {index, 1, 0});
    own.insert(own.end(), extra.begin(), extra.end());
    return own;
}

void addSet(Bytes &ies, uint8_t bits, const Bytes &own)
{
    Bytes set = {bits};
    element(set, 0, own);
    element(ies, 71, set);
}

std::vector<IEEE80211Mbssid::Profile> decode(const Bytes &ies,
    const uint8_t *tx = transmitted)
{
    IEEE80211Mbssid::Cursor cursor = {};
    IEEE80211Mbssid::Profile p;
    std::vector<IEEE80211Mbssid::Profile> result;
    while (IEEE80211Mbssid::nextProfile(ies.data(), ies.size(), tx, cursor, p))
        result.push_back(p);
    return result;
}

Bytes merge(const Bytes &ies, const IEEE80211Mbssid::Profile &p)
{
    Bytes out(2048);
    size_t length;
    assert(IEEE80211Mbssid::mergeProfile(ies.data(), ies.size(), p,
        out.data(), out.size(), length));
    out.resize(length);
    return out;
}

const uint8_t *find(const Bytes &ies, unsigned id, int ext = -1)
{
    assert(IEEE80211Mbssid::validElements(ies.data(), ies.size()));
    for (size_t pos = 0; pos < ies.size(); pos += 2 + ies[pos + 1])
        if (ies[pos] == id && (ext < 0 || (ies[pos + 1] && ies[pos + 2] == ext)))
            return ies.data() + pos;
    return nullptr;
}

const Bytes owe = {1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4,
    1, 0, 0, 15, 172, 18, 192, 0};

void parserTests()
{
    Bytes ies = {0, 0};
    addSet(ies, 3, profile("1Joey_6", 1));
    auto profiles = decode(ies);
    assert(profiles.size() == 1 && profiles[0].bssid[5] == 0x3b);
    assert(profiles[0].capability == 0x1111 && profiles[0].hasDtim);
    auto child = merge(ies, profiles[0]);
    auto ssid = find(child, 0);
    assert(ssid && ssid[1] == 7 && memcmp(ssid + 2, "1Joey_6", 7) == 0);
    assert(!find(child, 71) && !find(child, 83) && !find(child, 85));

    // Screenshot 4 supplies this prefix; the unpictured remainder is synthetic.
    Bytes captured = {3, 0, 103, 83, 2, 17, 17, 0, 7, 49, 74, 111, 101,
        121, 95, 54, 85, 3, 1, 1, 0, 70, 5, 51, 0, 0, 0, 0};
    element(captured, 221, Bytes(76, 0));
    assert(captured.size() == 106);
    ies = {0, 0};
    element(ies, 71, captured);
    profiles = decode(ies);
    assert(profiles.size() == 1);
    child = merge(ies, profiles[0]);
    assert(memcmp(find(child, 0) + 2, "1Joey_6", 7) == 0);

    // Add the index modulo 2^n, including carry and wrap of nonzero low bits.
    for (unsigned bits = 1; bits <= 8; ++bits) {
        for (unsigned index = 1; index < (1U << bits); ++index) {
            uint8_t tx[6] = {2, 0, 0, 0, 1, 255};
            ies.clear(); addSet(ies, uint8_t(bits), profile("test", uint8_t(index)));
            profiles = decode(ies, tx);
            assert(profiles.size() == 1);
            const unsigned mask = (1U << bits) - 1;
            assert(profiles[0].bssid[5] == ((255U & ~mask) | ((255U + index) & mask)));
            assert(memcmp(profiles[0].bssid, tx, 5) == 0);
        }
    }
    // All profiles across several elements, including hidden children and duplicates.
    ies.clear();
    for (unsigned i = 1; i <= 12; ++i)
        addSet(ies, 4, profile(i == 2 ? "" : "test", uint8_t(i)));
    addSet(ies, 4, profile("duplicate", 1));
    assert(decode(ies).size() == 12);
    for (uint8_t badIndex : {uint8_t(0), uint8_t(8)}) {
        ies.clear(); addSet(ies, 3, profile("test", badIndex));
        assert(decode(ies).empty());
    }
    Bytes own = profile("test", 1);
    own.push_back(0); // A valid prefix followed by a truncated element is rejected.
    ies.clear(); addSet(ies, 3, own);
    assert(decode(ies).empty());
    ies.clear(); addSet(ies, 3, profile("test", 1));
    for (size_t len = 0; len < ies.size(); ++len)
        assert(decode(Bytes(ies.begin(), ies.begin() + len)).empty());
    std::puts("PASS MBSSID parser: Joey prefix, hidden parent, all indices, multiple elements, malformed and duplicate profiles");
}

void inheritanceTests()
{
    Bytes ies = {0, 0};
    Bytes parentRsn = owe;
    parentRsn[17] = 8; // Parent SAE, child OWE.
    element(ies, 48, parentRsn);
    element(ies, 255, {35, 10});
    element(ies, 255, {36, 20});
    element(ies, 255, {108, 30});
    element(ies, 255, {107, 0, 0});
    element(ies, 5, {2, 3, 0, 0});
    Bytes extra;
    element(extra, 48, owe);
    element(extra, 255, {108, 99});
    addSet(ies, 3, profile("1Joey_6", 1, extra));
    auto p = decode(ies)[0];
    auto child = merge(ies, p);
    assert(AirportWCL::rsnIsOWE(find(child, 48), owe.size() + 2));
    assert(find(child, 255, 35)[3] == 10 && find(child, 255, 36)[3] == 20);
    assert(find(child, 255, 108)[3] == 99 && !find(child, 255, 107));
    assert(find(child, 5)[2] == 0 && find(child, 5)[3] == 1);

    // The child can explicitly omit an ordinary IE and one extension ID.
    extra.clear();
    element(extra, 255, {56, 1, 48, 1, 35});
    ies.resize(p.offset - 5); // Remove the entire previous Multiple BSSID element.
    addSet(ies, 3, profile("open", 1, extra));
    child = merge(ies, decode(ies)[0]);
    assert(!find(child, 48) && !find(child, 255, 35));
    assert(find(child, 255, 36) && find(child, 255, 108));
    assert(!find(child, 255, 56));

    extra.clear(); element(extra, 255, {56, 2, 48}); // Invalid list lengths.
    ies.clear(); addSet(ies, 3, profile("invalid", 1, extra));
    p = decode(ies)[0];
    uint8_t out[256]; size_t outLength = 99;
    assert(!IEEE80211Mbssid::mergeProfile(ies.data(), ies.size(), p,
        out, sizeof(out), outLength) && outLength == 0);
    ies.clear(); addSet(ies, 3, profile("test", 1));
    p = decode(ies)[0];
    assert(!IEEE80211Mbssid::mergeProfile(ies.data(), ies.size(), p, out, 1, outLength));
    // Fragments of an excluded parent MLE travel with that element.
    ies.clear();
    Bytes parentMle(255, 0); parentMle[0] = 107;
    element(ies, 255, parentMle); element(ies, 242, {1, 2, 3});
    addSet(ies, 3, profile("test", 1));
    child = merge(ies, decode(ies)[0]);
    assert(!find(child, 255, 107) && !find(child, 242));
    ies.clear(); parentMle[0] = 35;
    element(ies, 255, parentMle); element(ies, 242, {1, 2, 3});
    addSet(ies, 3, profile("test", 1));
    child = merge(ies, decode(ies)[0]);
    assert(find(child, 255, 35) && find(child, 242));
    std::puts("PASS MBSSID inheritance: child OWE RSN, independent HE/EHT extensions, MLD identity, DTIM and Non-Inheritance");
}
}

#ifdef MBSSID_RX_WRAPPER
void rxTests();
#endif
int main()
{
    parserTests();
    inheritanceTests();
#ifdef MBSSID_RX_WRAPPER
    rxTests();
#endif
}
