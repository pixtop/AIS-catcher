# Plan: forward CRC-valid but structurally invalid AIS frames (opt-in)

Status: **implemented on this branch (based on tag v0.70).** See "Implementation notes" at the end for deviations and test results.

**Target: git tag `v0.70`** (`8833c64`, "Bump version to v0.70", 2026-06-19). The tag is identical on `pixtop/AIS-catcher` and upstream `jvde-github/AIS-catcher`. The branch this file lives on is based on master `b6b4ae2`, which is **51 commits after v0.70** and differs substantially (§8). All file:line references below are **at v0.70** unless marked "HEAD".

This file is a working document. It is not meant to go upstream. Delete it when the feature lands.

---

## 0. Briefing facts, re-checked at v0.70

Every fact was checked in the source. The behaviour was also measured with a probe that drives `AIS::Decoder` with synthetic bit streams (appendix).

| Briefing says | At v0.70 | Verdict |
|---|---|---|
| `processData()`: validate fails → only `Debug()`, no `buildNMEA()`/`Send()`, returns true | `AIS.cpp:85-93` | ✔ |
| `Message::validate()` at `Message.cpp:396`: accepts length 0, rejects type ∉ 1..28 and length < `ml[]` | ✔ exactly. It has **no** MMSI check and **no** `< 38` check. MMSI 0 frames are sent as valid (**measured**). | ✔, with the note on MMSI 0 |
| `canStop()` aborts before CRC: type 0/>28, MMSI > 999999999, frame "24+ bits longer" | `AIS.cpp:111`, called at `AIS.cpp:222`. `END = 24` is the 16 FCS bits plus the closing flag. **Measured** trigger points, in payload bits: type check when payload ≥ 8, MMSI check when payload ≥ 40, size check at **standard + 2** (type 1: 169 bits passes, 170 is dropped). | ✔ rules; threshold wording corrected |
| `QuickReset` hard-coded true at `AIS.h:47`, no key | ✔ | ✔ |
| `TAG::error` (`uint32_t`): NONE=0, NOTOK=1 (unused), NMEA_CHECKSUM=2 (NMEA input only); no `quality` | `Common.h:225-227,255` ✔. The RF path **never touches `tag.error`**. `KEY_ERROR` has an index lookup table ("None", "Undefined Error", "NMEA Checksum Error", `Keys.cpp:175`). It is bounds-checked (`Writer.h:823`), so larger values simply get no `text` annotation. | ✔ |
| `tag.error` serialised only by JSONAIS; not by `getNMEAJSON()` | `JSONAIS.cpp:1111` ✔. `getNMEAJSON()` (`Message.cpp:91`) has no error key. BINARY_NMEA does not carry it either (flags 0x01/0x02 only). | ✔ |
| Statistics, Prometheus, DB skip types outside 1..28; `PostgreSQL.cpp:524` does an unguarded `1 << msg.type()` | `Statistics.h:81`, `Application/Prometheus.cpp:59`, `DB.cpp:1129` (also skips MMSI 0), `PostgreSQL.cpp:524` ✔. `DB.cpp:994` `1 << type` is behind the guard. | ✔ |
| Frames < 38 bits read stale bits as type/MMSI | ✔ **Measured.** At v0.70 the decoder never clears `msg`. Bits past `payload + 16 FCS + 7 flag bits` are left over from earlier frames. A 0-bit frame reports MMSI 2066240 after a type 1 frame and 2070824 after a type 5 frame. **`getNMEAJSON()` prints `mmsi`/`type` whenever length > 0** (`Message.cpp:171`), and so does JSONAIS (`:1138`). The same leftovers also appear in JSONAIS body fields of under-length frames. | ✔, and worse than stated |

Additional v0.70 facts that shape the design:

* `AIS::Filter::include(const Message&)` gets **no `TAG`** (`Message.cpp:1015`). About 20 call sites use it. The filter therefore cannot see `tag.error`.
* The `own_interval`, `position_interval` and `unique_interval` history blocks run **even with FILTER off** (`Message.cpp:1017-1048`).
* The type filter uses `msg.type() & 31` (`:1130`). Type 33 aliases to 1, and types 29-31 pass `allow == all`.
* The community feed (`-X`) is a plain `TCPClientStreamer` configured in `RunState.h:75-89` (FILTER on, REMOVE_EMPTY on). There is no dedicated class to hook.
* Models with decoders: `ModelBase`, `ModelStandard`, `ModelDefault` (v1 base, default), `ModelChallenger` (v1 high), and `ModelDiscriminator` (dev, derives `Model`). There is **no V2 engine** at v0.70.
* `ModelFrontend::Get()` prints all of its settings (`Model.cpp:403-416`), and that line appears in the `-v` log.
* `MaxBits = MAX_AIS_LENGTH = 1024`, so the maximum payload is 1001 bits.

---

## 1. Design summary

With the option on, a CRC-valid frame that fails structural checks is:

* converted to NMEA and sent to message outputs;
* flagged in `tag.error` with `INVALID` plus exactly one reason bit;
* marked on the `Message` object, so TAG-less consumers such as `Filter` can recognise it.

`quick_reset` gets its own key so that unknown types, out-of-range MMSIs and oversized frames reach the CRC check. With it off, frames the heuristic used to kill are flagged instead of passing as valid. State-keeping consumers (ship DB, web viewer, statistics, Prometheus, PostgreSQL, NMEA 2000) and the community feed never see flagged frames. Zeek sees everything and decides.

### R1: Opt-in configuration

Two model settings, handled in `ModelFrontend::SetKey` beside `FP_DS`, `DROOP` and similar, plus one filter setting:

| Key | Scope | Default | Meaning |
|---|---|---|---|
| `report_invalid` | model (`-go`) | `off` | Send CRC-valid frames that fail validation, flagged in `error`. Also clears the frame buffer per frame (R6). |
| `quick_reset` | model (`-go`) | `on` | Abort frames early when `canStop()` says they cannot be valid (upstream behaviour). |
| `remove_invalid` | output filter | `off` | With `FILTER on`, drop flagged frames on that output, like `REMOVE_EMPTY`. The community feed gets it `on`. |

Why model scope for the first two:

* Decoders live inside models, and `QuickReset` is a per-decoder member.
* The `-go` / `"model": {…}` pattern already exists for decoder knobs.
* It allows an A/B test in **one process**: two models on one device, one of them with `QUICK_RESET off` (T5).

Why two separate keys:

* `quick_reset off` alone is useful: oversized frames arrive flagged `OVERSIZED` without switching on invalid-frame output.
* `report_invalid on` alone still reports SHORT and LENGTH frames, and TYPE frames under 8 payload bits.
* For Zeek, set both.

Command line (`-go` applies to the last `-m` model, or to the default model it creates):

```
AIS-catcher -d 0 -go REPORT_INVALID on QUICK_RESET off -u 127.0.0.1 10110 MSGFORMAT JSON_NMEA
```

JSON config (v0.70 syntax, `Config.cpp:119`: settings sit directly in the `model` object):

```json
"model": { "active": true, "report_invalid": "on", "quick_reset": "off" }
```

Excluding flagged frames from one output: `-u host port FILTER on REMOVE_INVALID on`.

`ModelFrontend::Get()` appends ` report_invalid ON` / ` quick_reset OFF` **only when non-default**, so the default `-v` log line is byte-identical. `ModelDiscriminator` does not get the keys and throws the standard "not supported" error, which is acceptable for a dev model.

### R2: Error bits

`TAG::error` is a `uint32_t` with only bits 0-1 in use, so there is room for **independent bits**:

| Value | Constant | Set when |
|---|---|---|
| 4 | `MESSAGE_ERROR_INVALID` | Umbrella: CRC-valid, failed structural checks. Always set together with exactly one reason below. |
| 8 | `MESSAGE_ERROR_INVALID_SHORT` | 1-37 payload bits. The header is incomplete, so type and MMSI are **not reported**. |
| 16 | `MESSAGE_ERROR_INVALID_TYPE` | type 0 or 29-63 (≥ 38 bits) |
| 32 | `MESSAGE_ERROR_INVALID_LENGTH` | type 1..28 but below `ml[type-1]` |
| 64 | `MESSAGE_ERROR_INVALID_MMSI` | MMSI > 999 999 999. Only reachable with `quick_reset off`. |
| 128 | `MESSAGE_ERROR_OVERSIZED` | **Not** invalid. The frame passed `validate()` but ran past the `canStop()` size limit for its type. Only reachable with `quick_reset off`. |

Resulting `error` values: SHORT 12, TYPE 20, LENGTH 36, MMSI 68, OVERSIZED 128. Bit 1 (`NMEA_CHECKSUM`) never occurs on the RF path, so Zeek sees exactly these values.

Evaluation of the options:

* **A single bit** would make Zeek re-derive the reason. LENGTH needs a copy of AIS-catcher's `ml[]` table, and SHORT needs the fill bits. Sending the reason is cheap and avoids that drift.
* **A reason code** (2 bits) would also work, because reasons are mutually exclusive: `validate()` stops at the first failure. With 30 free bits, independent bits are simpler for Zeek (`error & 16`) and for any future filter vocabulary.
* **The umbrella bit** gives consumers one test (`& 4`) and leaves room for reasons added later.
* **The lookup table** (`LookupTable_message_error_types`) is index-based and was never right for bitmasks. Leave it alone: it is bounds-checked, and JSON_ANNOTATED just omits `text` for the new values.

**MMSI 0 is deliberately not flagged.** v0.70 already sends MMSI-0 frames as valid, and flagging them would change default output. Zeek can test `mmsi == 0` itself (Q6).

### R3: QuickReset: disable fully or partially?

What each `canStop()` rule blocks at v0.70 (measured; appendix):

| Rule | Fires at | Blocks frames that… | With it off, the frame is… |
|---|---|---|---|
| type 0 or > 28 | position 30 (payload ≥ 8) | …would fail `validate()` anyway | flagged TYPE |
| MMSI > 999 999 999 | position 62 (payload ≥ 40) | …**pass** `validate()`. **Measured: sent unflagged.** | flagged MMSI (new decoder check, §2.4) |
| per-type maximum | payload ≥ standard + 2 | …pass `validate()`. **Measured: a type 10 of 80 bits is sent unflagged.** | flagged OVERSIZED via the `overrun` latch (§2.3) |

**Recommendation: one on/off switch, no partial mode.**

* The type rule does most of the noise killing. It fires early and matches about 36/64 of random type values. It is exactly the rule that must go.
* The size and MMSI rules fire late and rarely in noise, so a partial mode that keeps them saves little and adds a tri-state setting to test and document.
* With `quick_reset off`, `canStop()` is still evaluated. It **latches `overrun`** instead of aborting, so no formerly-killed frame can leave unflagged.

### R4: Error field in JSON_NMEA: only when non-zero

Add `"error":N` to `getNMEAJSON()` **only when `tag.error != 0`**, right after `ipv4`.

* **Backward compatible.** Every line that is emitted today stays byte-identical, including valid frames in opt-in mode. Parsers keyed on exact output and dashboards are unaffected.
* **Consistent.** JSONAIS already emits `error` only when non-zero (`JSONAIS.cpp:1111`). Upstream later added `quality` to `getNMEAJSON()` with the same only-when-non-zero rule (HEAD `Message.cpp:153`), which confirms the convention and eases a future port.
* **Zeek rule:** absent means 0.

"Always" would add 10 bytes to every line and change all default JSON_NMEA output. That violates requirement 1.

Plain NMEA and NMEA_TAG cannot carry the flag, and neither can BINARY_NMEA at v0.70. **The Zeek feed must use `JSON_NMEA` (or `JSON_FULL`).**

### R5: Which consumers see flagged frames

**Recommendation: user-configured message outputs only.**

* Hard-skip in every consumer that builds per-MMSI or per-type state, and in NMEA 2000.
* The community feed skips flagged frames via `REMOVE_INVALID on`.
* Other outputs pass them, with `REMOVE_INVALID` available per output.

Why:

* The vessel table, tracks, coverage radar, per-type counters and Prometheus labels assume a trustworthy type and MMSI.
* A LENGTH-flagged type 1 with a real MMSI would move a real ship from zero padding.
* The ship DB (`Tracking/DB`) is the single entry point for the web viewer: histories, counters, SSE and Prometheus all hang off it (`WebViewer.cpp:642-647, 934, 950`). **One guard there covers all of them.**

Audit in §3.

### R6: Short frames and stale bits

1. **Clear the buffer per frame (opt-in only).** When `report_invalid` is on, call `msg.clear()` at the STARTFLAG→DATAFCS transition (`AIS.cpp:179`). Upstream made this unconditional after v0.70 (HEAD `AIS.h:131`), so the patch follows the upstream direction. It is gated here because doing it unconditionally would change default output: today, JSONAIS fields past the end of an under-length valid frame decode leftover bits from earlier frames. The cost is a 132-byte memset per start-flag candidate, a few per second per decoder.
2. **Clear the tail after CRC (opt-in only).** Zero bits `nBits … len+7` (the 16 FCS bits plus 7 flag bits) before building output. `type()`, `repeat()`, `mmsi()` and `getHash()` then read zeros. A 0-bit frame becomes type 0 / MMSI 0.
3. **Guard the serialisers for SHORT frames.** In `getNMEAJSON()` and JSONAIS, emit `mmsi`/`type` (and `repeat`, `country`) only when `length > 0 && !(error & SHORT)`.
4. **Skip the JSONAIS body decode for SHORT and LENGTH frames.** Those fields would come from zero padding and look like real data (e.g. `lat: 0`). MMSI-flagged frames are complete, so their body is decoded; TYPE frames have no `case` in the switch anyway.

Not chosen: **guarding the getters.** `type()` and `mmsi()` are hot inline getters used everywhere. Guarding them would change default behaviour and cost cycles on every message.

---

## 2. Changes by file (v0.70)

Estimated diff: about 130 lines of production code plus the new test file. The commit order is in §2.12.

### 2.1 `Source/Library/Common.h`
* After `MESSAGE_ERROR_NMEA_CHECKSUM` (`:227`), add the six constants from R2 (`const int`, matching the existing style).

### 2.2 `Source/Marine/Message.h`
* Add a member `bool invalid = false;` with `void setInvalid(bool b)` and `bool isInvalid() const`. It is the TAG-free marker used by `Filter` and the state consumers. The RF decoder sets it on every frame. Other producers (NMEA, N2K, …) never touch it, so it stays `false`.
* Add `bool remove_invalid = false;` to `class Filter` (`:344`).

### 2.3 `Source/Marine/AIS.h` / `AIS.cpp`: `Decoder`
* `AIS.h`: add `bool ReportInvalid = false; bool overrun = false;` beside `QuickReset` (`:47`), and a public `void setValidation(bool report_invalid, bool quick_reset)`.
* `AIS.cpp:179` (STARTFLAG→DATAFCS): add `overrun = false; if (ReportInvalid) msg.clear();`.
* `AIS.cpp:222`: replace `if (position == MaxBits || (QuickReset && canStop(position)))` with:

```cpp
if (position == MaxBits)
	NextState(State::TRAINING, 0);
else if (canStop(position))
{
	if (QuickReset)
		NextState(State::TRAINING, 0);
	else
		overrun = true;
}
```

This is equivalent to today when `QuickReset` is true.

### 2.4 `Source/Marine/AIS.cpp`: `processData()` (`:65-96`)

```cpp
tag.error &= ~(MESSAGE_ERROR_INVALID | MESSAGE_ERROR_INVALID_SHORT | MESSAGE_ERROR_INVALID_TYPE |
			   MESSAGE_ERROR_INVALID_LENGTH | MESSAGE_ERROR_INVALID_MMSI | MESSAGE_ERROR_OVERSIZED);
if (ReportInvalid)
	for (int i = nBits; i < len + 7; i++)
		msg.setBit(i, false); // FCS and flag bits must not read as type/MMSI

bool valid = msg.validate();
int reason = 0;
if (!valid)
	reason = nBits < 38 ? MESSAGE_ERROR_INVALID_SHORT
		   : (msg.type() < 1 || msg.type() > 28) ? MESSAGE_ERROR_INVALID_TYPE
		   : MESSAGE_ERROR_INVALID_LENGTH;
else if (nBits && msg.mmsi() > 999999999)
{
	reason = MESSAGE_ERROR_INVALID_MMSI;
	valid = false;
}
else if (overrun)
	tag.error |= MESSAGE_ERROR_OVERSIZED;

msg.setInvalid(!valid);
if (valid || ReportInvalid)
{
	if (!valid)
		tag.error |= MESSAGE_ERROR_INVALID | reason;
	msg.buildNMEA(tag);
	Send(&msg, 1, tag);
}
else
	Debug() << ...; // unchanged
return true;         // unchanged: resets sibling decoders
```

**Why the default output is identical.**
* With `QuickReset` on, `overrun` is never set.
* An MMSI above 999 999 999 cannot pass `validate()` there. Every payload of 40 bits or more is aborted at position 62, and payloads of 38-39 bits are below every `ml[]` entry (the minimum is 40).
* The `error &=` only clears bits the RF path never set before.
* `validate()` and the NMEA-input paths (`NMEA.cpp:112, 447, 756`) are **untouched**, so NMEA input keeps accepting MMSI > 999 999 999 exactly as today.

The reason is derived in the decoder rather than inside `validate()`. That keeps `validate()`'s signature and its three NMEA call sites unchanged.

### 2.5 `Source/Marine/Message.cpp`: `getNMEAJSON()` (`:91`)
* After the `ipv4` block (`:145-149`), add `if (tag.error) { ",\"error\":" N }`.
* `:171`: change `if (getLength() > 0)` to `if (getLength() > 0 && !(tag.error & MESSAGE_ERROR_INVALID_SHORT))`.

### 2.6 `Source/Marine/Message.cpp`: `Filter`
* `include()` (`:1015`): wrap the `own_interval`, `position_interval` and `unique_interval` blocks in `if (!msg.isInvalid())`.
  * `own_interval`: a frame whose junk MMSI equals the own MMSI would otherwise suppress real own-vessel output.
  * `position_interval`: a LENGTH-flagged type 1 with a real MMSI would otherwise suppress that ship's next genuine report. This matters because the check runs even with FILTER off.
* After the `remove_empty` check (`:1056`): add `if (remove_invalid && msg.isInvalid()) return false;`.
* `:1130` type aliasing: replace `(1U << (msg.type() & 31)) & allow` with `msg.type() < 32 ? ((1U << msg.type()) & allow) != 0 : allow == all`. This is identical for every frame reachable by default (type ≤ 28 or 0-bit type 0).
* `SetOptionKey`: add `case KEY_SETTING_REMOVE_INVALID` next to `REMOVE_EMPTY` (`:930`). `Get()`: print it when on.

### 2.7 `Source/DSP/Model.h` / `Model.cpp`
* `ModelFrontend` (`Model.h:132-145`): add `bool report_invalid = false, quick_reset = true;`.
* `SetKey` (`Model.cpp:357`): add two `Util::Parse::Switch` cases. `Get()` (`:403`): append each one only when non-default.
* Next to each `setOrigin` call, add `DEC.setValidation(report_invalid, quick_reset)`:
  * `ModelBase` (`:428-429`)
  * `ModelStandard` (`:458-459`)
  * `ModelDefault` (`:505-506`)
  * `ModelChallenger` (`:602-606`, four arrays)

### 2.8 `Source/JSON/KeyDefs.h`
* Add three X-lines: `KEY_SETTING_QUICK_RESET` ("quick_reset"), `KEY_SETTING_REPORT_INVALID` ("report_invalid") and `KEY_SETTING_REMOVE_INVALID` ("remove_invalid"). They **must** sit between `KEY_SETTING_ABOUT` (`:50`) and `KEY_SETTING_ZONE` (`:255`), because `lookupSettingKey()` iterates that range. Place them alphabetically next to `PS_EMA`/`REMOVE_EMPTY` (`:171-175`).
* Also give `KEY_ERROR` (`:29`) a description string listing the values.
* Before merging, check that no persisted file stores numeric `Keys` values; the enum shifts. PostgreSQL's `db_keys` mapping is by name at startup, but verify.

### 2.9 `Source/JSON/JSONAIS.cpp`: `ProcessMsg()`
* `:1138`: same SHORT guard as §2.5.
* Before `switch (msg.type())` (`:1150`): `if (tag.error & (MESSAGE_ERROR_INVALID_SHORT | MESSAGE_ERROR_INVALID_LENGTH)) return;`. Nothing after the switch needs to run.

### 2.10 Hard skips (one line each, `if (msg.isInvalid()) return;`)
* `Tracking/DB.cpp:1119` `DB::Receive()`, **before** `filter.include()`. This covers ships, histories, counters, SSE, Prometheus and viewer plugins.
* `DBMS/PostgreSQL.cpp:478` `Receive()`, before `filter.include()`. This also makes the `1 << msg.type()` at `:524` unreachable for type ≥ 31.
* `IO/N2KStream.cpp:777` `N2KStreamer::Receive()`. Otherwise LENGTH-flagged type 1/5/… frames would become PGNs built from zeros.

### 2.11 Community feed and CLI
* `Application/RunState.h:75-89` `createCommunityFeed()`: add `.SetKey(AIS::KEY_SETTING_REMOVE_INVALID, "on")`.
* `Application/Main.cpp:147` usage line: add `REPORT_INVALID [on/off] QUICK_RESET [on/off]`. Also list `REMOVE_INVALID` with the output filter options.

### 2.12 Commit sequence
1. Add the constants and the `Message::invalid` marker, plus the T1 harness running column D. No behaviour change.
2. Add the decoder options, keys and model plumbing. Behaviour is gated.
3. Add the consumer guards: Filter, `getNMEAJSON`, JSONAIS, DB, PostgreSQL, N2K, community feed.
4. Update the usage text and key descriptions.

Optional, not included: add an `INVALID` marker to the human-readable FULL screen format (`IO/Screen.cpp:97`). After the tail clear it prints `MSG: 0, MMSI: 0` for SHORT frames.

---

## 3. Downstream consumer audit (v0.70)

Paths from the decoder:

* **Message stream:** `Model::output` goes to message outputs (NMEA, NMEA_TAG, FULL, JSON_NMEA, BINARY_NMEA, COMMUNITY_HUB), `Screen` and `StreamCounter`, and to `JSONAIS`.
* **JSON stream:** `JSONAIS` goes to JSON-format outputs, `PostgreSQL`, `N2KStreamer` and `DB` (web viewer). `DB` then feeds `History ×4`, `Counter ×2`, `SSEStreamer`, `PrometheusCounter` and plugins.

| Consumer | Location | Verdict | Notes |
|---|---|---|---|
| `AIS::Filter::include()` | `Marine/Message.cpp:1015` | **Needs a guard** | History blocks and type aliasing (§2.6). No TAG, hence the `Message::invalid` marker. |
| UDP / TCP client / TCP listener / MQTT / HTTP outputs | `IO/Network.cpp` (`:77,391,409,546,565,722,734,808,823`) | **Safe, passes** | Flag visible in JSON_NMEA and JSON_* only. `REMOVE_INVALID on` excludes it per output. HTTP uploads to third parties (APRS etc.) should set it (Q5). |
| Community feed (`-X`, TCPClientStreamer, COMMUNITY_HUB) | `Application/RunState.h:75` | **Must skip** | `REMOVE_INVALID on` (§2.11). |
| File output | `IO/File.h:66-126` | **Safe, passes** | — |
| Screen (`-o N`) | `IO/Screen.cpp:85,142` | **Safe** | FULL format shows type/MMSI without a flag (zeros for SHORT after the tail clear); JSON formats show `error`. |
| `getNMEAJSON()` (JSON_NMEA) | `Marine/Message.cpp:91` | **Needs a guard** | §2.5 (error key, SHORT guard). |
| `getBinaryNMEA()` / NMEA / NMEA_TAG | `Marine/Message.cpp` | **Safe, but flag lost** | Do not use these for Zeek. |
| `JSONAIS` | `JSON/JSONAIS.cpp:1090` | **Needs a guard** | §2.9. `getUint()` is bounds-checked, so crafted frames cannot read out of bounds. |
| `N2KStreamer` | `IO/N2KStream.cpp:773` | **Must skip** | §2.10. |
| `PostgreSQL` | `DBMS/PostgreSQL.cpp:478` | **Must skip** (default, Q3) | Message row, `ais_vessel` upsert keyed by MMSI, `1 << type` UB for type ≥ 31. |
| `Tracking/DB` (ship table) | `Tracking/DB.cpp:1119` | **Must skip** | The existing guard (type 1..28, MMSI ≠ 0) lets LENGTH-flagged and MMSI > 1e9 frames through. |
| `History` / `Counter` / `MessageStatistics` | `Tracking/History.h`, `Tracking/Statistics.h:81` | **Safe** (behind DB) | Own 1..28 guard too. |
| `SSEStreamer`, `PrometheusCounter`, viewer plugins | `Application/WebViewer.cpp:934,950`, `Application/Prometheus.cpp:59` | **Safe** (behind DB) | — |
| `StreamCounter` (`-v` stats) | `IO/StreamCounter.h:27` | **Safe** | The count includes flagged frames in opt-in mode. Document it. |
| Downstream AIS-catcher reading our output | `Marine/NMEA.cpp` | **Safe, one caveat** | SHORT, TYPE and LENGTH frames fail `validate()` downstream and are dropped. **MMSI-flagged frames pass downstream validation** and would enter that instance's ship DB, because NMEA loses the flag. Don't chain the flagged feed into another AIS-catcher, or set `REMOVE_INVALID on` on that output. |

---

## 4. Test plan

`processData()` is reachable only from the RF path. Test on three levels.

### T1: Unit harness driving `AIS::Decoder` directly (primary)
New `scripts/test-invalid-frames.cpp`, standalone with `assert`. HEAD has this kind of script (`scripts/test-binary-badges.cpp`); v0.70 does not, so this adds the pattern.

A generator builds the payload, computes the FCS exactly like `Decoder::CRC16`, bit-stuffs, adds training bits and flags, NRZI-encodes to ±1 floats, and calls `Decoder::Receive()`. A `StreamIn<AIS::Message>` sink records `type`, `mmsi`, `length`, `tag.error`, `getNMEAJSON()` and JSONAIS output.

**It already compiles and runs against v0.70** (appendix). Build line:

```
c++ -std=c++11 $(find Source -type d | sed 's/^/-I/') scripts/test-invalid-frames.cpp \
    Source/Marine/AIS.cpp Source/Marine/Message.cpp Source/JSON/Keys.cpp \
    Source/Utilities/Convert.cpp Source/Utilities/Parse.cpp Source/Utilities/Helper.cpp \
    Source/Library/Logger.cpp -lpthread -o /tmp/test-invalid-frames
```

The JSONAIS check also needs `JSON/JSONAIS.cpp` and `JSON/JSON.cpp`.

Columns: **D** = defaults, **R** = `report_invalid on, quick_reset off`, **R+Q** = `report_invalid on, quick_reset on`. The D column was measured on v0.70.

| # | Frame | D (measured) | R expected | R+Q expected |
|---|---|---|---|---|
| 1 | type 1, MMSI 244123456, 168 bits | sent, error 0 | **byte-identical to D** | same |
| 2 | type 0, 72 bits | dropped | error 20, `type:0` + mmsi in JSON, no body | dropped (canStop) |
| 3 | types 29, 45, 63, 72 bits | dropped | error 20 | dropped |
| 4 | type 0, 7 bits (below the canStop threshold) | dropped (validate) | error 12, no type/mmsi keys | error 12 |
| 5 | type 1, 100 bits (< 149) | dropped | error 36, no JSONAIS body | error 36 |
| 6 | 20-bit frame, after a valid frame | dropped | error 12; no type/mmsi; NMEA payload 4 chars | error 12 |
| 7 | 37 / 38 bits (boundary) | dropped | 12 / 36 (or 20) | same |
| 8 | 0-bit frame after type 1, and after type 5 | sent, error 0, **MMSI 2066240 / 2070824 (stale)**; JSON has no mmsi | sent, error 0, **MMSI 0 in both cases** | same as R |
| 9 | type 1, MMSI 0 | **sent, error 0** (v0.70 behaviour) | unchanged (not flagged, Q6) | unchanged |
| 10 | type 1, MMSI 1073741823 | dropped | error 68, body decoded | dropped |
| 11 | type 1, 169 bits | sent, error 0 | error 0 (below the canStop limit) | error 0 |
| 12 | type 1, 170 bits | dropped | error 128 (OVERSIZED, not INVALID) | dropped |
| 13 | type 10, 80 bits | dropped | error 128 | dropped |
| 14 | `quick_reset off` only (`report_invalid off`): #10 and #13 | — | #10 **dropped** (not emitted as valid); #13 error 128 | — |
| 15 | Invalid frame, then a valid frame on the same `TAG` and decoder | — | second frame error 0, `isInvalid()` false | — |
| 16 | 1001-bit type 26 / 8 with long runs of ones (stuffing) | sent | identical to D | identical |

Also run the harness under `-fsanitize=undefined,address` and with `-m32` if multilib is available.

### T2: Consumers (extend T1)
* **Filter:**
  * `ALLOW_TYPE 1` must reject type 33;
  * `POSITION_INTERVAL 60`: a LENGTH-flagged type 1 with a real MMSI must not suppress the next valid report;
  * `FILTER on REMOVE_INVALID on` must drop flagged frames.
* **DB:** the ship count must be unchanged after flagged frames.
* **JSONAIS:** SHORT/LENGTH frames have no body keys.

### T3: Default-output regression (the "identical to v0.70" gate)
Build the **baseline** (tag) and the **patched** binary. Run each on the same inputs with **no new options**:

1. A real IQ recording (busy channel), e.g. `-r cu8 rec.raw -s 1536K`, with `-o 3` (JSON_NMEA), `-o 5` (JSON_FULL) and `-n`. Repeat for `-m 2` (default), `-m 4` and `-m 0`.
2. The synthetic IQ file from T4.
3. NMEA text input (`-r txt file.nmea -o 5`), as a sanity check. The NMEA path is untouched, but `Filter` changed.

Strip `rxtime`/`rxuxtime` and `diff`. **Zero differences required.** Also diff the `-v` startup lines.

### T4: Synthetic IQ end-to-end (`-r`)
A numpy script:

* GMSK-modulates the T1 bit streams (BT 0.4, 9600 Bd) on the channel A/B offsets at about 20 dB SNR;
* writes CF32 or CU8 at a supported rate (e.g. 288 kS/s).

Run `AIS-catcher -r cf32 syn.raw -s 288K -go REPORT_INVALID on QUICK_RESET off -o 3`. Each crafted frame must appear **once** with the expected `error`. This exercises the DSP chain, the sibling-decoder reset (no duplicates) and the serialisers.

The same generator with **noise only** is the **junk-rate test**: replay hours of signal time faster than real time and count flagged lines per hour, by reason, with `quick_reset` on and off.

### T5: Sensitivity A/B for `quick_reset off`
On a real recording, run two models in one process (`-m 2 -m 2 -go QUICK_RESET off`; outputs are separated by group) or two runs. Compare valid (`!(error & 4)`) message counts and unique MMSIs. The acceptance threshold is to be agreed (Q7); I suggest a loss of at most 0.5 %.

### T6: Builds
Linux x64, Raspberry Pi OS 32-bit (armhf), Windows MSVC. Also compile the T1 harness on MSVC if feasible.

---

## 5. Risks

* **Junk from noise.** Order-of-magnitude estimate, to be measured in T4:
  * In noise, each decoder sees a false training-plus-start-flag roughly every 10³ bits, so about 5 candidate frames per second per decoder.
  * Each candidate ends at the first run of six ones, about 126 bits on average.
  * v1 base has about 10 decoders per model and v1 high about 20. That gives about 50-100 candidates per second, and at 1 in 65536 about **one CRC pass every 10-20 minutes per receiver**.
  * v0.70 drops nearly all of these (canStop plus `validate`). With the option on, they are emitted.
  * About half end before 38 payload bits, so SHORT (error 12) will dominate. Expect **a few flagged junk frames per hour**, usually at low `signalpower`.
  * Zeek should down-weight isolated SHORT or low-level frames, and alert on repeated TYPE/LENGTH/MMSI frames at a good level.
* **Sensitivity with `quick_reset off`.** CPU cost is negligible: one branch per bit, plus a CRC of about 100 iterations per candidate, plus a memset when `report_invalid` is on. The real cost is that a decoder stays on a noise candidate for about 126 bits instead of 30 or 62. A real preamble in that window is lost **for that decoder**. The parallel phase decoders mitigate this. Measure with T5.
* **Spurious sibling resets.** Every CRC pass resets the sibling decoders (`processData` returns true). That already happens at v0.70; it becomes a little more frequent. Keep `return true`: returning false would let siblings decode the same invalid transmission again, producing duplicates.
* **Crafted frames.** Adversarial invalid frames are the point of this feature. AIS-catcher-side safety:
  * buffers are bounded (`MaxBits`, bounds-checked `getUint`/`setBit`);
  * flagged frames cannot touch ship state (DB skip);
  * they cannot suppress real reports (Filter guard);
  * they cannot reach the community feed.
* **32-bit builds** (Raspberry Pi OS armhf, Windows where `long` is 32-bit):
  * the new constants are small `int`s;
  * `tag.error` is `uint32_t`;
  * shifts by `type` are bounded (< 32) by the Filter fix and the PostgreSQL skip;
  * no new `long` or `time_t` arithmetic.
  * **Pre-existing, not introduced here:** `Decoder::start_idx`/`end_idx` and `Message::start_idx` are `long`. On 32-bit targets `ssc`/`sl` wrap after 2³¹ samples (about 2 hours at 288 kS/s). This only affects JSON_NMEA `ssc`/`sl` with `INCLUDE_SAMPLE_START`. Upstream later changed them to `long long`.
* **Rebase and upgrade.** HEAD reworked this area (§8), so the v0.70 patch will **not** rebase mechanically. The plan keeps it small and in four commits so it can be re-applied by hand. Re-implement it against HEAD's `quality` field rather than rebasing.
* **Default drift.** Guarded by T3 (zero-diff gate) and T1 column D, whose values were measured on v0.70.

---

## 6. Open questions

1. **Upgrade path.** Will you stay on v0.70 or move to a newer upstream soon? If you move, implement directly on HEAD (§8); the design carries over, but the bit and field names change.
2. **Error bits.** Are the independent bits 4/8/16/32/64 plus 128 for OVERSIZED OK? Any preference to align values with the later HEAD `quality` bits (4096…)?
3. **PostgreSQL.** Skip flagged frames (recommended), or store them for forensics? Storing them needs a `type_bit` guard and a check that the `msg_type` column accepts 0-63, and must not upsert `ais_vessel`.
4. **Web viewer.** Should it show an "invalid frames" counter? Proposed: no, Zeek owns this. If yes, add a bucket to `MessageStatistics` and bump its save-format version.
5. **Third-party HTTP uploads** (APRS, …). Rely on the user setting `REMOVE_INVALID on`, or force it?
6. **MMSI 0.** v0.70 sends these unflagged. Keep that (proposed, preserves default output), or flag them as INVALID_MMSI in opt-in mode only?
7. **Sensitivity acceptance** for `quick_reset off` in T5: what loss is acceptable?
8. **Zeek input format.** JSON_NMEA (proposed, compact, has `nmea` + `error`) or JSON_FULL?
9. **Coupling.** Should `report_invalid on` imply `quick_reset off`? Proposed: no, keep them independent and document the pair.
10. **OVERSIZED.** Should overrun frames stay out of the ship DB too (treat as INVALID), or keep flowing like v0.70's standard+1 oversized frames (proposed)?

---

## 7. Measured baseline (v0.70 probe)

The probe drove `AIS::Decoder` (v0.70 sources from `git archive v0.70`). `QuickReset` was flipped only in a scratch copy of `AIS.h`.

```
                              QuickReset on (v0.70)                          QuickReset off (scratch copy)
valid type 1          P=168   SENT mmsi=244123456 err=0                      same
0-bit after type 1    P=  0   SENT mmsi=2066240 (stale)  JSON: no mmsi/type  same
valid type 5          P=424   SENT                                           same
0-bit after type 5    P=  0   SENT mmsi=2070824 (stale)                      same
type 1 oversize +1    P=169   SENT err=0                                     SENT err=0
type 1 oversize +2    P=170   dropped                                        SENT err=0   <- unflagged: overrun latch
type 1 below min      P=100   dropped                                        dropped (validate)
type 0 / 45 / 63      P= 72   dropped                                        dropped (validate)
type 0                P=  7   dropped                                        dropped (validate)
mmsi 0 type 1         P=168   SENT mmsi=0 err=0                              same
mmsi 1073741823       P=168   dropped                                        SENT err=0   <- unflagged: MMSI check
20-bit frame          P= 20   dropped                                        dropped (validate)
type 10 oversize      P= 80   dropped                                        SENT err=0   <- unflagged: overrun latch
```

Frame generator (verified):

```cpp
// payload bits in decoder storage order: bit k = byte[k>>3] bit (k&7);
// AIS fields are MSB-first, so field bit i is stored at (offset+i)^7
static std::vector<float> frame(const std::vector<uint8_t> &bytes, int P) {
	std::vector<int> bits;
	for (int k = 0; k < P; k++) bits.push_back((bytes[k >> 3] >> (k & 7)) & 1);
	uint16_t crc = 0xFFFF;                               // as Decoder::CRC16
	for (int b : bits) crc = ((b ^ crc) & 1) ? (crc >> 1) ^ 0x8408 : crc >> 1;
	uint16_t fcs = ~crc;
	for (int i = 0; i < 16; i++) bits.push_back((fcs >> i) & 1);
	std::vector<int> s; int ones = 0;                    // bit stuffing
	for (int b : bits) { s.push_back(b); ones = b ? ones + 1 : 0; if (ones == 5) { s.push_back(0); ones = 0; } }
	std::vector<int> all;
	for (int i = 0; i < 24; i++) all.push_back(i & 1);   // training
	int flag[8] = {0,1,1,1,1,1,1,0};
	for (int b : flag) all.push_back(b);
	all.insert(all.end(), s.begin(), s.end());
	for (int b : flag) all.push_back(b);
	for (int i = 0; i < 24; i++) all.push_back(i & 1);
	std::vector<float> out; int lvl = 1;                 // NRZI: 0 = transition
	for (int b : all) { if (!b) lvl = -lvl; out.push_back((float)lvl); }
	return out;
}
```

---

## 8. Porting notes: v0.70 → master HEAD (`b6b4ae2`)

HEAD changed this area. If the feature is ported to HEAD, the design stays but the mechanics differ:

* **Error carrier.** `TAG::error` is gone. It was replaced by `uint16_t TAG::quality` with `CHECKSUM` = 512, `UNDERSIZED` = 1024 and `OVERSIZED` = 2048; bits 12-15 are free. Use bit 12 = INVALID plus a 2-bit reason in bits 13-14, and leave bit 15 for the CRC-failure feature. Reuse the existing `OVERSIZED` for the overrun latch.
* **Serialisers.** `getNMEAJSON()` and BINARY_NMEA already emit `quality` when non-zero, so R4 is done on HEAD.
* **Validation.** `validate(TAG&)` also rejects `len < 38` and **MMSI 0**, which adds an MMSI reason, and it sets UNDERSIZED/OVERSIZED. The reasons can be set inside `validate()`; its return value must not change.
* **Stale bits.** The decoder already calls `msg.clear()` per frame (`AIS.h:131`). Only the FCS-tail clear is still needed.
* **Filter.** `Filter::include(msg, tag)` takes the TAG and has `EXCLUDE_ERRORS`/`ONLY_ERRORS`/`IncludedWithError`. Add `invalid` to that vocabulary instead of `REMOVE_INVALID`. The `Message::invalid` marker is unnecessary.
* **Decoder layout.** The decoder kernel moved to `Run()` in `AIS.h`, and `canStop()` was renamed `cannotBeValid()`. There is a V2 engine (`ModelEngineV2`, 6 decoders per channel) to plumb as well.
* **Consumers.** The unguarded shift moved to `DBMS/DatabaseOutput.cpp:714` (shared by PostgreSQL, SQLite and CSV). The community feed is a dedicated `HubStreamer`. The ship DB is `Tracking/DB.cpp:1536`.

---

## 9. Implementation notes

Implemented in four commits on top of `v0.70`, following §2 and using the proposed answer wherever §6 left a question open:
- PostgreSQL skips flagged frames.
- There is no viewer counter.
- HTTP uploads rely on `REMOVE_INVALID`.
- MMSI 0 is not flagged.
- `OVERSIZED` frames still flow to the DB.
- The two keys are independent.

Deviations from §2:

* `Filter::Get()` does not print `remove_invalid`, matching `remove_empty`. Printing it would change the community feed's startup log line under `-X`.
* The T1 harness landed with the decoder commit rather than the first one, because it needs `Decoder::setValidation()`.
* The harness also checks the `Filter` (T2): type aliasing, the `POSITION_INTERVAL` history guard, and `REMOVE_INVALID`.

Test results (Linux x64, GCC 13):

* **T1/T2** `scripts/test-invalid-frames.cpp`: all checks pass, also under `-fsanitize=undefined,address` and as a 32-bit (`-m32`) build. Mutation checks confirmed the tests catch these guards being removed: buffer clear, tail clear, JSONAIS body skip, Filter history guard, type aliasing.
* **T3** default-output gate: the v0.70 binary and the patched binary decoded a synthetic GMSK recording (288 kS/s CF32, channel A, 16 crafted frames). Output was **identical for every combination** of `-m 0/1/2/4` and `-o 1..6` (NMEA, FULL, JSON_NMEA, JSON_SPARSE, JSON_FULL, JSON_ANNOTATED), once timestamps were stripped. NMEA text input (`-r txt`, including the flagged sentences) was also identical.
* **T4** end-to-end with `-go REPORT_INVALID on QUICK_RESET off -o 3`: all 16 frames came out once each with the expected `error` (0, 12, 20, 36, 68, 128).
* **Junk rate (T4, white noise only).** Configurations tested: v0.70, patched defaults, opt-in with `-m 2`, and opt-in with `-m 4`. Each got 6 h of Gaussian noise streamed on stdin; together with one extra hour of opt-in noise (different seed), that is **1 flagged frame in about 13 opt-in noise-hours**. It was type 30 (`error` 20) at **−36 dB `signalpower`**, against about −1 dB for real frames at 20 dB SNR, so its low signal level stands out. The rate is roughly 0.1 per hour per receiver, lower than the §5 estimate. Real RF, with interference and partial collisions, will differ; measure on site. Defaults and v0.70 produced nothing.
* **Web viewer**, looping the same recording with `-N`: baseline and patched builds show the same 3 ships. The patched build's counters additionally include only the two `OVERSIZED` frames. The frames flagged invalid never reach them.
* **Builds:** the full CMake build passes with PostgreSQL (libpq 16) and NMEA2000 enabled. `Model.cpp`, `DB.cpp`, `PostgreSQL.cpp`, `N2KStream.cpp` and `Main.cpp` also pass a `-m32` syntax check. **Not tested here:** MSVC/Windows, real armhf hardware, a real RF recording (T5 sensitivity A/B).

Caution for manual testing: at v0.70, `-N` switches the aiscatcher.org community feed on unless `-X off` is given.
