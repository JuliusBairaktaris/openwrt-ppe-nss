# wifi-8023 (M3/M4 host Wi-Fi fast path)

Done: seven mac80211/ath11k quilt patches plus the TSO pair, committed on wifi-8023.
 subsys 491 AQL refund of a freed 802.3 frame; 492 mesh_hdr_offload switch (default 0); 493 TSO/SG features, AQL fit, counters
 ath11k 988 a4 header misread; 989 RX SA tie to peer; 993 frame_mode=2 default; 994 mesh decap observer;
        997 TCL segments TCP batches (tso param); 998 offer SG/TSO to mac80211
Images (scratchpad/m3m4): wifi-8023-a.bin 0b98ae71... (patches up to 994 + 493 inert), wifi-8023.bin 91df5e29...
Commands: PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin make -j16 (log scratchpad/m3m4-build.log);
          make package/kernel/mac80211/compile V=s: clean, no warnings from the patches.
Copies/scripts: patches/wip/host-wifi-fastpath/m3m4/{patches,scripts}
Not run: flash, bench, any runtime test.

Image c: subsys 494 (rx_status->tid, mac80211 side) and 495 (frames with h_proto < 0x600 skip encap
offload) split out; 993 only fills status->tid. checkpatch --strict clean (only the missing-author
artifact of patch files). Image scratchpad/m3m4/wifi-8023-c.bin sha256 676d5cae...05c0. Not run: flash, bench,
tools/refreshcheck.sh (needs openwrt-ppe host zstd, missing).
