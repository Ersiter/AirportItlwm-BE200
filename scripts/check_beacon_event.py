#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / "itl80211/openbsd/net80211/ieee80211_input.c").read_text(encoding="utf-8")
event = source.index("ic->ic_event_handler(ic, IEEE80211_EVT_BEACON, &event);")
start = source.rindex("    if (ic->ic_event_handler) {", 0, event)
end = source.index("\n#endif", start)
event_block = source[start:end]

probe = r'''
#include "AirportItlwm/WCL/WCL.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>

struct ieee80211_frame { uint8_t bytes[24]; };
struct ieee80211_node {};
struct ieee80211_beacon_event {
    ieee80211_node *node;
    const uint8_t *ies;
    size_t length;
    const uint8_t *frame;
    size_t frame_length;
};
struct ieee80211com { void (*ic_event_handler)(ieee80211com *, int, void *); };
constexpr int IEEE80211_EVT_BEACON = 1;
#define IEEE80211_CRC_LEN 4
using mbuf_t = std::vector<uint8_t> *;
size_t mbuf_len(mbuf_t m) { return m->size(); }
size_t ieee80211_get_hdrlen(const ieee80211_frame *) { return 24; }
ieee80211_beacon_event received{};
void capture(ieee80211com *, int, void *event) {
    received = *static_cast<ieee80211_beacon_event *>(event);
}
void emit(ieee80211com *ic, mbuf_t m, ieee80211_node *ni, const uint8_t *frm) {
    auto wh = reinterpret_cast<const ieee80211_frame *>(m->data());
    const uint8_t *tstamp = m->data() + 24;
    (void)tstamp;
    (void)wh;
    (void)m;
    (void)frm;
    /* PRODUCTION_EVENT */
}

int main(int argc, char **) {
    if (argc > 1) {
        auto oneByte = new uint8_t[1]{0};
        assert(AirportWCL::validIEPrefix(oneByte, 1, 0) == 0);
        delete[] oneByte;
        const uint8_t missingLength[] = {0, 0, 221};
        assert(AirportWCL::validIEPrefix(missingLength, sizeof(missingLength), 0) == 0);
        const uint8_t shortBody[] = {221, 2, 0};
        assert(AirportWCL::validIEPrefix(shortBody, sizeof(shortBody), 0) == 0);
        puts("one-byte IE header rejected without an out-of-bounds read");
        return 0;
    }
    ieee80211com ic{capture};
    ieee80211_node ni;
    for (unsigned tailSize : {0U, 1U, 2U, 5U}) {
        std::vector<uint8_t> ies = {0, 6, 'i', 'P', 'h', 'o', 'n', 'e', 1, 1, 0x82};
        ies.push_back(221);
        ies.push_back(uint8_t(tailSize));
        for (unsigned i = 0; i < tailSize; ++i) ies.push_back(uint8_t(0x40 + i));
        for (unsigned trailer : {0U, 1U, 4U, 8U}) {
            std::vector<uint8_t> frame(36, 0);
            frame[0] = 0x80;
            frame.insert(frame.end(), ies.begin(), ies.end());
            for (unsigned i = 0; i < trailer; ++i) frame.push_back(i ? 0xff : 0xde);
            // frm is the cursor left by net80211's bounded element walk.
            const uint8_t *frm = frame.data() + 36;
            const uint8_t *end = frame.data() + frame.size();
            while (end - frm >= 2) {
                if (size_t(frm[1]) + 2 > size_t(end - frm)) break;
                frm += 2 + frm[1];
            }
            received = {};
            emit(&ic, &frame, &ni, frm);
            assert(received.node == &ni);
            assert(received.length == ies.size());
            assert(received.frame_length == 36 + ies.size());
            assert(std::memcmp(received.ies, ies.data(), ies.size()) == 0);
            assert(AirportWCL::validIEPrefix(received.ies, received.length, 0) == ies.size());
            uint8_t ssid[32]{}, length = 0;
            assert(AirportWCL::parseSsid(received.ies, received.length, ssid, sizeof(ssid), length)
                == AirportWCL::SsidStatus::Ok);
            assert(length == 6 && std::memcmp(ssid, "iPhone", 6) == 0);
        }
    }
    puts("beacon event: complete last elements retained, unparsed trailers excluded (16 cases)");
}
'''.replace("    /* PRODUCTION_EVENT */", event_block)

with tempfile.TemporaryDirectory(prefix="beacon-event-") as temp:
    src = Path(temp) / "probe.cpp"
    binary = Path(temp) / "probe"
    src.write_text(probe, encoding="utf-8")
    subprocess.run([os.environ.get("CXX", "c++"), "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-I", str(root),
                    str(src), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    subprocess.run([str(binary), "short-header"], check=True)
