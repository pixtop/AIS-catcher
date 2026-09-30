# Plan: forward CRC-valid but structurally invalid AIS frames (opt-in)

Status: **plan only, no code changed.** Target tree: this checkout (HEAD `b6b4ae2`, `VERSION "v0.70"`, no git tags in the clone).

This file is a working document. It is not meant to go upstream. Delete it when the feature lands.

---

## 0. Read first: the checkout differs from the briefing

I re-checked every "verified fact" against the code. Several do not hold in this tree, and two of them change the design. Please confirm the baseline (see Open question Q1) before implementation starts.

| Briefing says | Code actually says | Impact |
|---|---|---|
| `processData()` only logs `Debug()` on validation failure; it does not call `buildNMEA()` | `Marine/AIS.cpp:86-98`: it **does** call `msg.buildNMEA(tag)`, then Debug-logs type, length and each sentence. There is no `Send()`. It still returns `true` (which resets sibling decoders). | Small. The NMEA build cost already exists on this path. |
| `Message::validate()` at `Message.cpp:396`, `ml[]` table | `Marine/Message.cpp:423`, signature `validate(TAG &tag)`. Length 0 returns true. It rejects `len < 38 \|\| len > 1064`, `type ∉ 1..28`, `len < minimum[type-1]`, and **`mmsi() == 0`**. On success it also sets `UNDERSIZED`/`OVERSIZED` in `tag.quality`. | The reason set gains "MMSI 0". Upstream already forwards 0-bit frames. |
| `Decoder::canStop()` | Called `cannotBeValid(int)` (`AIS.cpp:117`), invoked per bit from `Run()` at `AIS.h:172`. | Naming only. |
| Oversized frames are aborted at "24+ bits longer" than standard | `END = 24` covers the 16 FCS bits plus the closing flag. A frame is aborted once its payload reaches **standard + 2 bits**. **Measured:** a 169-bit type 1 frame passes (flag `OVERSIZED`), a 170-bit one is dropped. The type check fires for payloads of 8 bits or more. The MMSI check fires for payloads of 40 bits or more. | Changes the threshold wording in tests and docs. |
| `QuickReset` hard-coded `true` at `AIS.h:47`, no key | ✔ Correct. | — |
| `TAG` has `uint32_t error` (NONE/NOTOK/NMEA_CHECKSUM); no `quality` field | **No `error` field.** `TAG::quality` is a `uint16_t` (`Library/Common.h:278`). Bits 0-6 are reception marks (plausible, confirmed, suspect, duplicate, echo, late, dense). Bits 7-8 are "reserved" upstream. Bit 9 is `CHECKSUM` (512), bit 10 `UNDERSIZED` (1024), bit 11 `OVERSIZED` (2048). The mask `MESSAGE_QUALITY_ERRORS` covers bits 9-11. **Free: bits 12-15.** | The new flag goes into `quality`, not into a new field. |
| Error only serialised by JSONAIS; `getNMEAJSON()` omits it | `quality` is emitted when non-zero by **JSONAIS** (`JSONAIS.cpp:1260`), **`getNMEAJSON()`** (`Message.cpp:153`, the JSON_NMEA format), and **BINARY_NMEA** (flag `0x10`, `Message.cpp:368/398`). NMEA, NMEA_TAG and FULL do not carry it. | **Requirement 4 is already met upstream.** |
| Unguarded `1 << msg.type()` at `DBMS/PostgreSQL.cpp:524` | It is at `DBMS/DatabaseOutput.cpp:714` (`entry.type_bit`), shared by the PostgreSQL, SQLite and CSV backends. The guards in `Statistics.h:92`, `Prometheus.cpp:59` and `DB.cpp:1541` exist as described. | Different file. |
| Frames under 38 bits expose **stale** bits from earlier frames | `msg.clear()` zeroes the buffer at every start flag (`AIS.h:131`). Bits past `nBits` are **this frame's** 16 FCS bits plus the first 7 bits of the closing flag (`0111111`), then zeros. The garbage is deterministic, not stale. For a 0-bit frame the FCS is `0x0000`, so `type()=0` and `mmsi()=2064384` (`0x7E<<14`). **Measured.** Upstream already emits these as "empty" messages. | Requirement 6 is still needed, but the cause is different. |

Relevant infrastructure the briefing did not mention (reused by this plan):

* `AIS::Filter` (`Message.cpp:861-1265`) already has `EXCLUDE_ERRORS` (undersized, oversized, checksum, all, none), `ONLY_ERRORS`, and a three-way result: `Included`, `IncludedWithError`, `NotIncluded`. Message outputs only pass `Included`. The ship DB treats `IncludedWithError` as "count it but do not touch vessel state".
* `validate()` is also called from the NMEA text, multipart and binary input paths (`NMEA.cpp:119, 462, 827`). Any change to its **return value** changes NMEA-input behaviour. This plan changes only its side effects on `tag.quality`, never its return value.

---

## 1. Design summary

With the option on, a frame that passes CRC-16 but fails structural checks is converted to NMEA and sent to the message outputs like any other frame. It carries `quality` bit 12 (`INVALID`) plus a 2-bit reason code. The decoder's early-abort heuristic (`QuickReset`) gets its own key so that unknown types, out-of-range MMSIs and oversized frames get as far as the CRC check. State-keeping consumers (ship DB, web viewer, statistics, Prometheus, database backends, NMEA 2000 output, the community feed) skip flagged frames. Zeek sees everything and decides.

### R1: Opt-in configuration

Two **engine (model) settings**, handled in `ModelFrontend::SetKey` beside `FP_DS`, `DROOP` and similar:

| Key | Default | Meaning |
|---|---|---|
| `report_invalid` | `off` | Send CRC-valid frames that fail validation, flagged in `quality`. |
| `quick_reset` | `on` | Abort frames early when `cannotBeValid()` says they cannot be valid AIS (upstream behaviour). |

Why engine-level, not global:

* Decoders live inside models, and `QuickReset` is a per-decoder member.
* This matches the existing `-go` and `"engines": [{ "settings": {…} }]` pattern.
* It allows an A/B test in **one process**: two models on the same device, one with `quick_reset off` (see T5).

Why two keys and not one:

* `quick_reset off` alone is useful. Oversized frames then arrive flagged `OVERSIZED` without switching on invalid-frame output.
* `report_invalid on` alone still reports short, below-minimum-length and MMSI-0 frames.
* For Zeek, set **both**.

Command line (`-go` applies to the last `-m` model, or to the default model it creates):

```
AIS-catcher -d 0 -go REPORT_INVALID on QUICK_RESET off -u 127.0.0.1 10110 MSGFORMAT JSON_NMEA
```

JSON config (receiver block):

```json
"engines": [ { "type": "v1_base", "settings": { "report_invalid": "on", "quick_reset": "off" } } ]
```

`ModelFrontend::Get()` appends `report_invalid ON` / `quick_reset OFF` only when non-default, so the default `Model #…` log line stays byte-identical. `ModelDiscriminator` (development model `-m 3`, derives from `Model`) does not get the keys and throws the standard "setting not supported" error. That is acceptable.

### R2: Error bits

Layout, chosen to keep one spare bit for the later CRC-failure feature:

| Bits | Name | Value(s) |
|---|---|---|
| 12 | `MESSAGE_QUALITY_INVALID` | 4096. The frame passed CRC-16 but failed structural validation. |
| 13-14 | reason code (valid only when bit 12 is set) | `0` **SHORT**: 1-37 bits, header incomplete (also the unreachable `> 1064`) · `1` **TYPE**: type 0 or 29-63 · `2` **LENGTH**: below the per-type minimum (`minimum[]` table) · `3` **MMSI**: MMSI 0, or MMSI > 999 999 999 (RF path only, see §2.4) |
| 15 | *left free* | Keep it for the CRC-failure feature. |

Resulting `quality` values (other bits permitting): SHORT 4096, TYPE 12288, LENGTH 20480, MMSI 28672. In Zeek: `if (q & 4096) reason = (q >> 13) & 3;`

Evaluation of the alternatives:

* **Bit 12 only.** Zeek can recompute SHORT, TYPE and MMSI from the NMEA payload. LENGTH, however, depends on AIS-catcher's private `minimum[]` table, which Zeek would have to copy and keep in sync. That makes the reason worth carrying.
* **Four independent bits (12-15).** Reasons are **mutually exclusive by construction**, because `validate()` returns at the first failed check. Independent bits gain nothing and leave no bit for the CRC feature.
* **Widening `quality` to 32 bits.** Rejected. It breaks the 2-byte field in the BINARY_NMEA wire format (flag `0x10`), which dAISy-catcher and aiscatcher.org also parse.
* **Bits 7-8.** Upstream marks them reserved, which is a rebase hazard.

`MESSAGE_QUALITY_INVALID` is added to `MESSAGE_QUALITY_ERRORS`, so `ONLY_ERRORS` and `EXCLUDE_ERRORS all` include it. `EXCLUDE_ERRORS` gains the name `invalid`, so an operator can remove flagged frames from one output with `FILTER on EXCLUDE_ERRORS invalid`.

### R3: QuickReset: disable fully or partially?

What each `cannotBeValid()` rule blocks (measured with the probe in the appendix):

| Rule | Fires when | Blocks frames that… | What we need |
|---|---|---|---|
| type 0 or > 28 | position 30 (payload ≥ 8 bits) | …would be flagged TYPE | **off** |
| MMSI > 999 999 999 | position 62 (payload ≥ 40) | …**pass `validate()`**. They would be emitted unflagged; the probe shows `quality=0`. | **off**, plus a new MMSI check (§2.4) |
| per-type maximum | payload ≥ max + 2 (types 1-5, 7, 9-11, 15, 16, 18-25, 27, 28) | …pass `validate()`. `OVERSIZED` is only set for types 1-5, 9, 11, 18, 19, 23, 27, 28. Types 7, 10, 15, 16, 20, 21, 22, 24 and 25 would be emitted unflagged; the probe shows a type 10 frame of 80 bits with `quality=0`. | **off**, plus an `overrun` latch that sets `OVERSIZED` |

**Recommendation: one on/off switch.** Do not add a partial mode.

* The type rule is the one that kills most noise candidates. It fires early, on about 56 % of random type values, and it is exactly the rule we must switch off.
* The remaining rules fire late and rarely in noise, so keeping only them buys little sensitivity while adding a tri-state setting to test and document.

With `quick_reset off`, `cannotBeValid()` is still evaluated. When it fires, it latches `overrun` instead of aborting. If the frame then passes CRC and `validate()`, the decoder sets `OVERSIZED`. That turns every frame the heuristic would have killed into either `INVALID` or `OVERSIZED`, and none of them leaves unflagged.

### R4: Error field in JSON_NMEA

**Already implemented upstream** (`Message.cpp:153-157`): `"quality":N` is added only when non-zero. **Keep "only when non-zero".**

* **Backward compatible.** Output for valid, unflagged frames stays byte-identical, including in opt-in mode.
* **Consistent.** JSONAIS (JSON_FULL, JSON_SPARSE, JSON_ANNOTATED), BINARY_NMEA and the NMEA/JSON input parser (`NMEA.cpp:575`) all treat an absent key as 0.
* **Cheap.** It adds nothing to about 99.9 % of lines.
* **Zeek rule:** absent means 0.

Remaining work is documentation only: update the `KEY_QUALITY` description in `KeyDefs.h`.

Plain NMEA and NMEA_TAG **cannot** carry the flag, so the Zeek feed must use `JSON_NMEA` (or `JSON_FULL`).

### R5: Which consumers see flagged frames

**Recommendation: message outputs only.**

* **Hard-skip:** every consumer that builds state keyed on type or MMSI, anything that publishes to third parties, and NMEA 2000.
* **Pass:** user-configured message outputs. They can still exclude flagged frames per output with the existing filter.

The full audit is in §3.

Rationale:

* The briefing's goal is "Zeek decides". Vessel tables, tracks, coverage radar, the per-type counters and the Prometheus labels all assume a trustworthy type and MMSI. Feeding them junk corrupts the operator display. With MMSI-reason frames, a crafted frame could also move a real ship.
* The ship DB (`Tracking/DB`) is the single entry point for the whole web viewer: ships, paths, histories, counters, SSE and Prometheus all hang off it (`ReceiverTracker::wireStreams`, `ViewerSettings.cpp:145-149`). **One guard there covers all of them.**

### R6: Short frames

* **Clear the tail.** When `report_invalid` is on, `processData()` zeroes the bits from `nBits` to `len + 7` (the FCS and closing-flag bits, at most 23 iterations) after the CRC check and before `validate()`. `type()`, `repeat()`, `mmsi()` and `getHash()` then read zeros instead of FCS or flag bits. A 0-bit frame becomes type 0 / MMSI 0 rather than MMSI 2064384. This is gated on the option: doing it unconditionally would change default JSON for valid-but-undersized frames, whose fields past `length` currently decode FCS bits.
* **Guard JSONAIS.** For flagged frames, emit `type`, `repeat` and `mmsi` only when `length >= 38`, and skip the per-type body decode unless the reason is MMSI. The body fields would otherwise be decoded from zero padding and look like real data (for example `lat: 0`). For MMSI-reason frames the payload is complete, so the body is decoded; Zeek may want the position of an MMSI-0 transmitter.
* **Not chosen: guarding the getters.** `type()` and `mmsi()` are hot inline getters used everywhere. Guarding them would change default behaviour and cost cycles on every message.

---

## 2. Changes by file

Estimated diff: about 150 lines of production code plus the new test file. Split into four commits (§2.12) to ease rebasing.

### 2.1 `Source/Library/Common.h`
* After `MESSAGE_QUALITY_OVERSIZED`, add `MESSAGE_QUALITY_INVALID = 1 << 12`, `MESSAGE_INVALID_MASK = 3 << 13`, and the codes `MESSAGE_INVALID_SHORT/TYPE/LENGTH/MMSI = 0/1/2/3 << 13`.
* Add `MESSAGE_QUALITY_INVALID` to `MESSAGE_QUALITY_ERRORS`.
* Update the bit comment: "bits 7-8 reserved, 12 invalid, 13-14 invalid reason, 15 free".

### 2.2 `Source/Marine/Message.cpp`: `Message::validate(TAG&)`
* On entry, clear `INVALID | MESSAGE_INVALID_MASK` along with `UNDERSIZED | OVERSIZED`.
* Replace each `return false;` with a local helper that sets `INVALID | reason` and returns false. Order and conditions stay unchanged. **The return value is unchanged on every path, so NMEA-input behaviour is unchanged.** NMEA paths drop failed messages and `tag.clear()` per line (`NMEA.cpp:503/683/988/1050`), so the bits never leak.

### 2.3 `Source/Marine/Message.cpp`: `AIS::Filter`
* `SetOptionKey(EXCLUDE_ERRORS)`: accept `invalid` and update the error text. `Get()`: print `invalid`.
* `include()`: compute `bool invalid = tag.quality & MESSAGE_QUALITY_INVALID` once.
  * Skip the `own_interval`, `position_interval` and `unique_interval` history updates for flagged frames. These blocks run **even with FILTER off**. Without the guard, a junk or crafted frame carrying a real MMSI would suppress that ship's genuine position reports, and one carrying the own MMSI would suppress own-vessel output.
  * Fix type aliasing: `unsigned type = msg.type() & 31` maps type 33 to 1 and lets it through `ALLOW_TYPE 1`. Replace it with `type < 32 ? ((1U << type) & allow) : allow == all`. Default behaviour is identical, because no reachable default frame has type ≥ 32.

### 2.4 `Source/Marine/AIS.h`: `Decoder`
* Add members `bool ReportInvalid = false; bool overrun = false;`.
* Add a setter `void setValidation(bool report_invalid, bool quick_reset)`.
* In `Run()`, set `overrun = false;` next to `msg.clear()` (STARTFLAG to DATAFCS).
* Replace `if (position == MaxBits || (QuickReset && cannotBeValid(position)))` with:

```cpp
if (position == MaxBits)
	NextState(State::TRAINING, 0);
else if (cannotBeValid(position))
{
	if (QuickReset)
		NextState(State::TRAINING, 0);
	else
		overrun = true;
}
```

With `QuickReset == true` this is equivalent to today. It costs one extra branch per bit only when the option is off.

### 2.5 `Source/Marine/AIS.cpp`: `Decoder::processData()`

```cpp
tag.quality &= ~MESSAGE_QUALITY_CHECKSUM;
if (ReportInvalid)
	for (int i = nBits; i < len + 7; i++)
		msg.setBit(i, false); // FCS and flag bits must not read as type/MMSI

bool valid = msg.validate(tag);
if (valid && msg.getLength() && msg.mmsi() > 999999999)
{
	tag.quality |= MESSAGE_QUALITY_INVALID | MESSAGE_INVALID_MMSI;
	valid = false;
}
else if (valid && overrun)
	tag.quality |= MESSAGE_QUALITY_OVERSIZED;

if (valid || ReportInvalid)
{
	msg.buildNMEA(tag);
	Send(&msg, 1, tag);
}
else
{ /* unchanged Debug() logging */ }
return true; // unchanged: still resets sibling decoders
```

Default-identity argument:

* With `QuickReset` on, `overrun` is never set.
* An MMSI above 999 999 999 cannot pass `validate()`. Every frame with a payload of 40 bits or more is aborted at position 62, and payloads of 38-39 bits fail the minimum length (the smallest is 40).
* The MMSI range check lives here and not in `validate()`, so NMEA input keeps accepting such MMSIs as it does today.

### 2.6 `Source/DSP/Model.h` / `Model.cpp`
* `ModelFrontend`: add protected `bool report_invalid = false, quick_reset = true;`. Add `SetKey` cases for `KEY_SETTING_REPORT_INVALID` and `KEY_SETTING_QUICK_RESET` (`Util::Parse::Switch`). Extend `Get()`, non-default values only.
* In each `buildModel`, beside the existing `setOrigin` calls, add `DEC.setValidation(report_invalid, quick_reset)`:
  * `ModelBase` (`Model.cpp:428`)
  * `ModelStandard` (`:501`)
  * `ModelDefault` (`:547`)
  * `ModelChallenger` (`:643-647`, four decoder arrays)
  * `ModelEngineV2`: inside the existing `getDecoder(i)` loop (`:455-459`). No change to `V2Engine` is needed.

### 2.7 `Source/JSON/KeyDefs.h`
* Add `X(KEY_SETTING_QUICK_RESET, …, "quick_reset", …)` and `X(KEY_SETTING_REPORT_INVALID, …, "report_invalid", …)`. They **must** sit between `KEY_SETTING_ABOUT` and `KEY_SETTING_ZONE`, because `lookupSettingKey()` iterates that range (`Keys.cpp:39`). Put them alphabetically near `PS_EMA` and `REMOVE_EMPTY`.
* Update the `KEY_QUALITY` and `KEY_SETTING_EXCLUDE_ERRORS` descriptions.
* Check that no persisted file stores numeric `Keys` values; the enum shifts. Upstream adds keys routinely, so this is expected to be fine, but verify the backup and `DatabaseOutput` column mapping.

### 2.8 `Source/JSON/JSONAIS.cpp`: `ProcessMsg()`
* Header block (`:1287`): change `if (msg.getLength() > 0)` to `if (msg.getLength() > 0 && (!invalid || msg.getLength() >= 38))`.
* Before `switch (msg.type())`: `if (invalid && (tag.quality & MESSAGE_INVALID_MASK) != MESSAGE_INVALID_MMSI) return;`. Nothing after the switch needs to run; `Receive()` sends right after.

### 2.9 `Source/Tracking/DB.cpp`: `DB::Receive()` (`:1536`)
* First statement after `msg` is set: `if (tag.quality & MESSAGE_QUALITY_INVALID) return;`. This covers ships, paths, the binary store, places, visits, histories, counters, SSE and Prometheus.

### 2.10 Other hard skips (one line each)
* `DBMS/DatabaseOutput.cpp` `Receive()` (`:655`): skip flagged frames. This makes the `1 << msg.type()` at `:714` unreachable for type ≥ 31. Also change that line to `msg.type() < 32 ? 1u << msg.type() : 0` as belt and braces; it is outside the default path.
* `IO/N2KStream.cpp` `N2KStreamer::Receive()` (`:773`): skip flagged frames. Otherwise below-minimum-length type 1/2/3/5/… frames would be encoded as PGNs from zero padding.
* `IO/Network.h` `HubStreamer::sendFormatted()` (`:213`): skip flagged frames. The community feed (auto-enabled by `-X`) must never receive them. It sets `FILTER on` but no `EXCLUDE_ERRORS`, and a user config could override a filter-based exclusion, so a hard skip is safer.

### 2.11 `Source/Application/CommandLine.cpp`
* Usage line `:120`: add `REPORT_INVALID [on/off] QUICK_RESET [on/off]` to the `-go` list.

### 2.12 Commit sequence
1. Add the constants and reason bits in `validate()`, plus the test harness. No behaviour change; the harness proves it.
2. Add the decoder options, keys and model plumbing. Behaviour is gated.
3. Add the consumer guards: Filter, JSONAIS, DB, DatabaseOutput, N2K, Hub.
4. Update the usage text and key descriptions.

Optional, not included: add a `, INVALID` marker to the human-readable `FULL` screen format (`IO/MsgOut.h:71-107`), which currently cannot show `quality`.

---

## 3. Downstream consumer audit

Paths from the decoder:

* **Message stream:** `Model::output` goes to message outputs (NMEA, NMEA_TAG, FULL, JSON_NMEA, BINARY_NMEA, COMMUNITY_HUB), `ScreenOutput`, `StreamCounter`, `ChannelActivity` and `JSONAIS`.
* **JSON stream:** `JSONAIS` goes to JSON-format outputs, `DatabaseOutput`, `N2KStreamer`, `HTTPStreamer` and `DB`. `DB` then feeds `History ×4`, `Counter ×2`, `SSEStreamer` and `PrometheusCounter`.

| Consumer | Where | Verdict | Notes |
|---|---|---|---|
| `AIS::Filter::include()` (all outputs, DB) | `Message.cpp:1129` | **Needs a guard** | History blocks (own, position, unique) and type aliasing (§2.3). The error, quality and only_errors logic already fits. |
| UDP / TCP client / TCP listener / MQTT / file outputs (`OutputMessage::Receive`) | `IO/MsgOut.h:177-207` | **Safe, passes** | Flag visible only in JSON_NMEA, JSON_*, BINARY_NMEA. Per-output opt-out: `FILTER on EXCLUDE_ERRORS invalid`. |
| `HTTPStreamer` (AISCATCHER / APRS / LIST / AIRFRAMES / NMEA upload) | `IO/Network.cpp:77` | **Safe, but document** | User-configured. Uploads to third parties (APRS, Airframes) should set `EXCLUDE_ERRORS invalid` (Q5). |
| `HubStreamer` (community feed, `-X`) | `IO/Network.h:213` | **Must skip** | Hard skip (§2.10). |
| `ScreenOutput` (`-o N`) | `IO/Screen.h` | **Safe** | FULL format prints type and MMSI (zeros after tail clear) with no flag; optional marker. JSON formats carry `quality`. |
| `JSONAIS` (JSON decoder) | `JSON/JSONAIS.cpp:1238` | **Needs a guard** | §2.8. `getUint()` is bounds-checked to `MAX_AIS_LENGTH`, so there is no out-of-bounds read even for crafted frames. |
| `N2KStreamer` | `IO/N2KStream.cpp:769` | **Must skip** | §2.10. |
| `DatabaseOutput` (PostgreSQL / SQLite / CSV) | `DBMS/DatabaseOutput.cpp:650` | **Must skip** (default; see Q3) | Writes a message row and a per-MMSI state row; `1 << type` is UB for type ≥ 31; `accumulateStats` inserts the junk MMSI into hourly vessel counts. |
| `Tracking/DB` (ship table, web viewer) | `Tracking/DB.cpp:1536` | **Must skip** | Existing `type` 1..28 guard misses LENGTH, SHORT and MMSI reasons with a valid type. MMSI-0 or partial type 1/5 frames would create or move ships. |
| `History` / `Counter` / `MessageStatistics` | `Tracking/History.h:66`, `Statistics.h:88,296` | **Safe** (behind DB) | Own 1..28 guard, too. |
| `SSEStreamer` (live NMEA/signal feed) | `Web/WebViewer.cpp:36` | **Safe** (behind DB) | — |
| `PrometheusCounter` | `Web/Prometheus.cpp:56` | **Safe** (behind DB) | Own 1..28 guard, too. |
| `StreamCounter` (`-v` stats) | `IO/StreamCounter.h:49` | **Safe** | The count includes flagged frames in opt-in mode. Document it. |
| `ChannelActivity` (control UI) | `Control/ControlCore.h:42` | **Safe** | Counts RF activity per channel; including flagged frames is arguably correct. |
| NMEA / JSON / binary **input** of another AIS-catcher | `Marine/NMEA.cpp:119,462,575,827` | **Safe** | A downstream instance clears the INVALID bits in `validate()` and then drops the frame, as today. |
| `buildNMEA()` AIVDM/AIVDO | `Message.cpp` | **Safe** | A flagged frame whose MMSI equals the own MMSI is rendered `!AIVDO`. Cosmetic. |
| `V2::Engine` slot-phase learning | `V2Engine.cpp:371` | **Unchanged** | Already fed by CRC-valid invalid frames upstream (`processData` returns true). |

---

## 4. Test plan

`processData()` is reachable only from the RF path. Test on three levels.

### T1: Unit harness driving `AIS::Decoder` directly (primary)
New `scripts/test-invalid-frames.cpp`, following the precedent of `scripts/test-binary-badges.cpp` (standalone, no test framework, `assert`). A generator builds the payload, computes the FCS exactly like `Decoder::CRC16`, bit-stuffs, adds training bits and flags, NRZI-encodes to ±1 floats, and calls `Decoder::Receive()`. A `StreamIn<AIS::Message>` sink records `type`, `mmsi`, `length`, `tag.quality`, the NMEA text, and the JSONAIS JSON.

**This generator already works against the unmodified tree** (appendix). Build line, verified:

```
c++ -std=c++11 $(find Source -type d | sed 's/^/-I/') scripts/test-invalid-frames.cpp \
    Source/Marine/AIS.cpp Source/Marine/Message.cpp Source/JSON/Keys.cpp \
    Source/Utilities/Convert.cpp Source/Utilities/Parse.cpp Source/Utilities/Helper.cpp \
    Source/Library/Logger.cpp -lpthread -o /tmp/test-invalid-frames
```

Adding the JSONAIS check needs `JSON/JSONAIS.cpp` and `JSON/JSON.cpp` as well.

Cases. Columns: **D** = default, **R** = `report_invalid on, quick_reset off`, **R+Q** = `report_invalid on, quick_reset on`. The D column was measured on the current code.

| # | Frame | D (measured) | R expected | R+Q expected |
|---|---|---|---|---|
| 1 | type 1, MMSI 244123456, 168 bits | sent, q=0 | sent, q=0, **NMEA byte-identical to D** | same |
| 2 | type 0, 72 bits | dropped (QuickReset) | q=12288 (TYPE), JSON has type/repeat/mmsi, no body | dropped |
| 3 | types 29, 45, 63, 72 bits | dropped | q=12288 | dropped |
| 4 | type 0, 7 bits (below the QuickReset threshold) | dropped (`validate`) | q=4096 (SHORT) | q=4096 |
| 5 | type 1, 100 bits (< 149) | dropped | q=20480 (LENGTH), JSON without body | q=20480 |
| 6 | 20-bit frame | dropped | q=4096, JSON has **no** type/mmsi, NMEA payload 4 chars | q=4096 |
| 7 | 37 and 38 bits (boundary) | dropped | 4096 / 20480 | same |
| 8 | 0-bit frame | sent, q=0, type 0, **mmsi 2064384** | sent, q=0, **mmsi 0** | same as R |
| 9 | type 1, MMSI 0, 168 bits | dropped | q=28672 (MMSI), body decoded | q=28672 |
| 10 | type 1, MMSI 1073741823 | dropped | q=28672 | dropped |
| 11 | type 1, 169 bits | sent, q=2048 | q=2048 | q=2048 |
| 12 | type 1, 170 bits | dropped | q=2048 (OVERSIZED, not INVALID) | dropped |
| 13 | type 10, 80 bits (validate has no OVERSIZED for type 10) | dropped | q=2048 via `overrun` | dropped |
| 14 | `quick_reset off`, `report_invalid off`: cases 10 and 13 | — | #10 **dropped** (not emitted as valid), #13 q=2048 | — |
| 15 | Tag reuse: invalid frame, then a valid frame on the same `TAG` | — | second frame q=0 (no bit leakage) | — |
| 16 | Payload with long runs of ones (stuffing), 1064-bit type 26 | sent | identical to D | identical |

Also run the harness under `-fsanitize=undefined,address` and with `-m32` (if multilib is available). These catch shift-width UB and 32-bit truncation.

### T2: Filter and consumer units (extend T1)
Feed the flagged messages through:

* `AIS::Filter` with `ALLOW_TYPE 1`: type 33 must not pass.
* `POSITION_INTERVAL 60`: a flagged type 1 with a real MMSI must not suppress the next valid report.
* `EXCLUDE_ERRORS invalid` and `ONLY_ERRORS`.
* A `Tracking::DB` instance: the ship count must stay unchanged after flagged frames.

### T3: Default-output regression (the "identical to upstream" gate)
Build **baseline** (this HEAD) and **patched** binaries. Run each on the same inputs with no new options:

1. A real IQ recording (ideally a busy one), e.g. `-r cu8 rec.raw -s 1536K -o 5` and `-o 3`, plus `-go` with each engine: `-m 2`, `-m 4`, v2.
2. The synthetic IQ file from T4.
3. NMEA text, JSON and BINARY_NMEA input files (`-r txt …`), because `validate()` changed.

Strip `rxtime` and `rxuxtime` (for example `jq -c 'del(.rxtime,.rxuxtime)'`) and `diff`. **The acceptance criterion is zero differences.** Also diff the `-v` startup log lines.

### T4: Synthetic IQ end-to-end (`-r`)
A Python script (numpy):

* Encodes the T1 bit streams as GMSK (BT 0.4, 9600 Bd) on channel A/B offsets.
* Sets the SNR to about 20 dB.
* Writes CU8 or CF32 at a supported rate (e.g. 288 kS/s).

Run `AIS-catcher -r cf32 syn.raw -s 288K -go REPORT_INVALID on QUICK_RESET off -o 3`. Check that each crafted frame appears once, with the expected `quality`. This exercises the full DSP chain, the sibling-decoder reset (no duplicates), JSONAIS and the outputs. The same file with only Gaussian noise serves as the **junk-rate test**: run the equivalent of hours of signal faster than real time and count INVALID lines per hour of signal time, by reason, for `quick_reset` on and off.

### T5: Sensitivity A/B for `quick_reset off`
On a real recording, run two models in one process (or two runs): upstream settings versus `QUICK_RESET off`. Compare:

* the count of valid (`!(q & 4096)`) messages;
* the count of unique MMSIs.

The acceptance threshold is to be agreed (Q7); I suggest a loss of at most 0.5 %.

### T6: Builds
Run the existing CI matrix: Debian/Ubuntu/Fedora x64, the armv6 (Raspberry Pi OS 32-bit) job, and Windows MSVC. Also compile the T1 harness on MSVC if feasible.

---

## 5. Risks

* **Junk from noise.** Order-of-magnitude estimate, to be measured in T4:
  * In noise, each decoder sees a false training-plus-start-flag roughly every 10³ bits, so about 5 candidate frames per second per decoder.
  * Candidates end at the first run of six ones, about 126 bits on average.
  * Decoders per model: about 10 (v1 base), 20 (v1 high), 12 (v2). That gives about 50-100 candidates per second per receiver, and at 1 in 65536 about **one CRC pass every 10-20 minutes**.
  * Upstream drops nearly all of these (QuickReset plus `validate`). With the option on, they are emitted.
  * About half end before 38 payload bits, so SHORT will dominate. Expect **a few flagged junk frames per hour per receiver**, usually at low `signalpower`.
  * Zeek should weight SHORT and isolated low-level INVALID frames accordingly, and should correlate: repeated TYPE/LENGTH/MMSI frames at good signal level are the interesting ones.
* **Sensitivity with `quick_reset off`.** CPU cost is negligible: one branch per bit, plus a CRC of about 100 iterations per candidate. The real cost is that a decoder stays busy on a noise candidate for about 126 bits instead of being aborted at 30 or 62 bits. A real preamble arriving during that window is lost **for that decoder**. The parallel decoders (5 phases per channel) mitigate this. Measure with T5.
* **Spurious sibling resets.** Every CRC pass, invalid or not, resets the sibling decoders (`processData` returns true). A junk CRC pass in the middle of a real frame on another decoder can lose that frame. This already happens upstream; with QuickReset off it happens slightly more often (a few times per hour). Keep `return true`: returning false would make the siblings decode the same real invalid transmission again, producing duplicates.
* **Crafted frames.** An adversary can transmit invalid frames on purpose; that is the point. AIS-catcher-side safety:
  * buffers are bounded (`MaxBits`, bounds-checked `getUint`/`setBit`);
  * flagged frames cannot touch ship state (DB skip);
  * they cannot suppress real reports (Filter history guard);
  * they cannot reach the community feed.
* **32-bit builds** (Raspberry Pi OS armhf, Windows where `long` is 32-bit):
  * the new constants are `uint16_t` literals ≤ `3 << 13`;
  * no new `long` or `time_t` arithmetic;
  * shifts by `type` are bounded (< 32) by the Filter fix and the `DatabaseOutput` guard;
  * `mmsi()` is 30 bits in `unsigned`.
  * T1 under `-m32`/UBSan plus the armv6 CI job cover this.
* **Rebase.** Upstream may later claim bits 12-15 or reorganise `Filter`/`validate()`. The changes are small and grouped into four commits. The key X-lines sit in the alphabetical block, so conflicts will be local.
* **Default drift.** Guarded by T3 (zero-diff gate) and T1 column D, whose values were measured on the current code.

---

## 6. Open questions

1. **Baseline.** Your fact list matches an older tree (`TAG::error`, `canStop()`), not this checkout (`TAG::quality`, `cannotBeValid()`). Which tree is deployed? This plan targets the checkout. On the older tree the bit would go into `error`, and `getNMEAJSON()` would need the change R4 describes.
2. **Bit layout.** Is bit 12 plus a 2-bit reason code (bit 15 left for the CRC-failure feature) acceptable, or do you prefer independent bits?
3. **Database backends.** Skip flagged frames (recommended), or store them for forensics? Storing them needs the `type_bit` guard and a check that `msg_type` accepts 0-63, and must not update the per-MMSI state table.
4. **Web viewer.** Should it show an "invalid frames" counter? Proposed: no; Zeek owns this. If yes, add one bucket to `MessageStatistics` and bump its `_VERSION`, which invalidates saved backups.
5. **Third-party uploads.** Hub gets a hard skip. For HTTP uploads (APRS, Airframes), rely on `EXCLUDE_ERRORS invalid`, or hard-skip them too?
6. **Oversize overrun.** Reuse `OVERSIZED` (proposed), or add a separate flag? Reusing it keeps bit 15 free.
7. **Sensitivity acceptance** for `quick_reset off` in T5: what loss is acceptable?
8. **Zeek input format.** JSON_NMEA (proposed) or JSON_FULL? Plain NMEA cannot carry the flag.
9. **Coupling.** Should `report_invalid on` imply `quick_reset off`? Proposed: no, keep them independent and just document the pair.
10. **Upstreaming.** Is this meant to go upstream eventually? If so, agree the bit allocation with the maintainer first.

---

## Appendix: verified frame generator and measured baseline

The core of the probe that produced the "D" column. It was run against the unmodified tree; `QuickReset` was flipped only in a scratch copy of `AIS.h`.

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

Measured output:

```
                              QuickReset on (upstream)            QuickReset off (scratch copy)
valid type 1          P=168   SENT q=0                            SENT q=0
type 1 oversize +1    P=169   SENT q=2048                         SENT q=2048
type 1 oversize +2    P=170   dropped                             SENT q=2048
type 1 undersized     P=160   SENT q=1024                         SENT q=1024
type 1 below min      P=100   dropped                             dropped (validate)
type 0                P= 72   dropped                             dropped (validate)
type 45               P= 72   dropped                             dropped (validate)
type 0                P=  7   dropped                             dropped (validate)
mmsi 0 type 1         P=168   dropped                             dropped (validate)
mmsi 1073741823       P=168   dropped                             SENT q=0   <-- unflagged, fixed by §2.5
20-bit frame          P= 20   dropped                             dropped (validate)
0-bit frame           P=  0   SENT q=0 type=0 mmsi=2064384        same
type 10 oversize      P= 80   dropped                             SENT q=0   <-- unflagged, fixed by overrun latch
```
