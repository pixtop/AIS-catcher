// Standalone regression test for the RF decoder's handling of CRC-valid frames. From the
// repository root (one command):
//
//   c++ -std=c++11 $(find Source -type d | sed 's/^/-I/') scripts/test-invalid-frames.cpp
//       Source/Marine/AIS.cpp Source/Marine/Message.cpp Source/JSON/JSONAIS.cpp Source/JSON/JSON.cpp
//       Source/JSON/Keys.cpp Source/Utilities/Convert.cpp Source/Utilities/Parse.cpp
//       Source/Utilities/Helper.cpp Source/Library/Logger.cpp -lpthread -o /tmp/test-invalid-frames
//   /tmp/test-invalid-frames
//
// Frames are built bit-exact (payload, FCS, bit stuffing, flags, NRZI) and fed to AIS::Decoder
// as one sample per bit, so every path in Decoder::processData() can be reached without IQ data.
#include "AIS.h"
#include "JSONAIS.h"
#include "Writer.h"

#include <cstdio>
#include <string>
#include <vector>

static int failures = 0;

#define CHECK(cond)                                                                   \
	do                                                                                \
	{                                                                                 \
		if (!(cond))                                                                  \
		{                                                                             \
			std::printf("FAIL %s:%d: %s [%s]\n", __FILE__, __LINE__, #cond, current); \
			failures++;                                                               \
		}                                                                             \
	} while (0)

static const char *current = "";

struct Out
{
	bool sent = false;
	unsigned type = 0, mmsi = 0;
	int length = -1;
	int error = 0;
	bool invalid = false;
	std::string nmea_json, full_json;

	bool has(const std::string &s) const { return full_json.find(s) != std::string::npos; }
	bool nmea_has(const std::string &s) const { return nmea_json.find(s) != std::string::npos; }
};

struct MessageSink : public StreamIn<AIS::Message>
{
	Out *out = nullptr;
	void Receive(const AIS::Message *d, int len, TAG &tag) override
	{
		out->sent = true;
		out->type = d->type();
		out->mmsi = d->mmsi();
		out->length = d->getLength();
		out->error = (int)tag.error;
		out->invalid = d->isInvalid();
		out->nmea_json.clear();
		d->getNMEAJSON(out->nmea_json, tag);
	}
};

struct JSONSink : public StreamIn<JSON::JSON>
{
	Out *out = nullptr;
	JSON::Serializer builder{JSON_DICT_FULL};
	void Receive(const JSON::JSON *d, int len, TAG &tag) override
	{
		out->full_json.clear();
		builder.stringify(d[0], out->full_json);
	}
};

// AIS fields are MSB-first; the decoder stores stream bit k at bit (k & 7) of byte k >> 3
static void put(std::vector<uint8_t> &b, int off, int len, uint32_t v)
{
	for (int i = 0; i < len; i++)
	{
		int k = (off + i) ^ 7;
		if ((v >> (len - 1 - i)) & 1)
			b[k >> 3] |= 1 << (k & 7);
	}
}

static std::vector<float> modulate(const std::vector<uint8_t> &bytes, int P)
{
	std::vector<int> bits;
	for (int k = 0; k < P; k++)
		bits.push_back((bytes[k >> 3] >> (k & 7)) & 1);

	uint16_t crc = 0xFFFF; // as Decoder::CRC16
	for (int b : bits)
		crc = ((b ^ crc) & 1) ? (crc >> 1) ^ 0x8408 : crc >> 1;
	uint16_t fcs = ~crc;
	for (int i = 0; i < 16; i++)
		bits.push_back((fcs >> i) & 1);

	std::vector<int> stuffed;
	int ones = 0;
	for (int b : bits)
	{
		stuffed.push_back(b);
		ones = b ? ones + 1 : 0;
		if (ones == 5)
		{
			stuffed.push_back(0);
			ones = 0;
		}
	}

	const int flag[8] = {0, 1, 1, 1, 1, 1, 1, 0};
	std::vector<int> all;
	for (int i = 0; i < 24; i++)
		all.push_back(i & 1);
	all.insert(all.end(), flag, flag + 8);
	all.insert(all.end(), stuffed.begin(), stuffed.end());
	all.insert(all.end(), flag, flag + 8);
	for (int i = 0; i < 24; i++)
		all.push_back(i & 1);

	std::vector<float> out;
	int level = 1;
	for (int b : all) // NRZI: a zero is a transition
	{
		if (!b)
			level = -level;
		out.push_back((float)level);
	}
	return out;
}

class Receiver
{
	AIS::Decoder dec;
	AIS::JSONAIS jsonais;
	MessageSink msink;
	JSONSink jsink;
	TAG tag;

public:
	Receiver(bool report_invalid = false, bool quick_reset = true)
	{
		dec.setOrigin('A', 0, -1);
		dec.setValidation(report_invalid, quick_reset);
		dec >> msink;
		dec >> jsonais;
		jsonais >> jsink;
		tag.mode = 0;
	}

	// P payload bits; a filler pattern follows the header so bit stuffing is exercised
	Out send(unsigned type, unsigned mmsi, int P, uint8_t filler = 0x5A)
	{
		std::vector<uint8_t> bytes(160, 0);
		if (P >= 6)
			put(bytes, 0, 6, type);
		if (P >= 38)
			put(bytes, 8, 30, mmsi);
		for (int k = 38; k + 8 <= P; k += 8)
			put(bytes, k, 8, filler);

		Out out;
		msink.out = &out;
		jsink.out = &out;
		std::vector<float> f = modulate(bytes, P);
		dec.Receive(f.data(), (int)f.size(), tag);
		return out;
	}
};

static void defaults()
{
	Receiver rx;
	Out o;

	current = "D1 valid type 1";
	o = rx.send(1, 244123456, 168);
	CHECK(o.sent && o.type == 1 && o.mmsi == 244123456 && o.error == 0 && !o.invalid);
	CHECK(o.nmea_json.find("\"error\"") == std::string::npos);
	CHECK(o.nmea_has("\"mmsi\":244123456,\"type\":1"));

	current = "D8 0-bit frames expose bits left by the previous frame";
	o = rx.send(0, 0, 0);
	CHECK(o.sent && o.length == 0 && o.error == 0 && o.mmsi == 2066240);
	rx.send(5, 227006760, 424);
	o = rx.send(0, 0, 0);
	CHECK(o.sent && o.mmsi == 2070824);

	current = "D11 one bit oversized passes";
	o = rx.send(1, 244123456, 169);
	CHECK(o.sent && o.error == 0);

	current = "D9 MMSI 0 is sent unflagged";
	o = rx.send(1, 0, 168);
	CHECK(o.sent && o.mmsi == 0 && o.error == 0);

	const struct
	{
		const char *name;
		unsigned type, mmsi;
		int P;
	} dropped[] = {
		{"D12 two bits oversized", 1, 244123456, 170},
		{"D5 below minimum length", 1, 244123456, 100},
		{"D2 type 0", 0, 244123456, 72},
		{"D3 type 29", 29, 244123456, 72},
		{"D3 type 45", 45, 244123456, 72},
		{"D3 type 63", 63, 244123456, 72},
		{"D4 type 0, 7 bits", 0, 0, 7},
		{"D10 MMSI above 999999999", 1, 1073741823, 168},
		{"D6 20-bit frame", 3, 0, 20},
		{"D7 37-bit frame", 3, 0, 37},
		{"D7 38-bit frame", 3, 244123456, 38},
		{"D13 type 10 oversized", 10, 244123456, 80},
	};
	for (const auto &d : dropped)
	{
		current = d.name;
		o = rx.send(d.type, d.mmsi, d.P);
		CHECK(!o.sent);
	}

	current = "D16 long frame with stuffing";
	o = rx.send(8, 244123456, 1000, 0xFF);
	CHECK(o.sent && o.length == 1000 && o.error == 0);
}

// REPORT_INVALID on, QUICK_RESET off: every CRC-valid frame reaches the outputs
static void report_invalid()
{
	Receiver rx(true, false);
	Out o;

	current = "R1 valid frame unchanged";
	o = rx.send(1, 244123456, 168);
	CHECK(o.sent && o.type == 1 && o.mmsi == 244123456 && o.error == 0 && !o.invalid);

	current = "R2/R3 unknown types";
	const unsigned types[] = {0, 29, 45, 63};
	for (unsigned t : types)
	{
		o = rx.send(t, 244123456, 72);
		CHECK(o.sent && o.type == t && o.mmsi == 244123456 && o.invalid);
		CHECK(o.error == (MESSAGE_ERROR_INVALID | MESSAGE_ERROR_INVALID_TYPE));
	}

	current = "R4 type 0, 7 bits";
	o = rx.send(0, 0, 7);
	CHECK(o.sent && o.length == 7 && o.error == (MESSAGE_ERROR_INVALID | MESSAGE_ERROR_INVALID_SHORT));

	current = "R5 below minimum length";
	o = rx.send(1, 244123456, 100);
	CHECK(o.sent && o.invalid && o.error == (MESSAGE_ERROR_INVALID | MESSAGE_ERROR_INVALID_LENGTH));

	current = "R6 20-bit frame after a long frame: no stale bits";
	rx.send(5, 227006760, 424);
	o = rx.send(3, 0, 20);
	CHECK(o.sent && o.length == 20 && o.type == 3 && o.mmsi == 0);
	CHECK(o.error == (MESSAGE_ERROR_INVALID | MESSAGE_ERROR_INVALID_SHORT));

	current = "R7 37/38-bit boundary";
	o = rx.send(3, 0, 37);
	CHECK(o.error == (MESSAGE_ERROR_INVALID | MESSAGE_ERROR_INVALID_SHORT));
	o = rx.send(3, 244123456, 38);
	CHECK(o.mmsi == 244123456 && o.error == (MESSAGE_ERROR_INVALID | MESSAGE_ERROR_INVALID_LENGTH));
	o = rx.send(45, 244123456, 38);
	CHECK(o.error == (MESSAGE_ERROR_INVALID | MESSAGE_ERROR_INVALID_TYPE));

	current = "R8 0-bit frames read zeros";
	rx.send(1, 244123456, 168);
	o = rx.send(0, 0, 0);
	CHECK(o.sent && o.length == 0 && o.type == 0 && o.mmsi == 0 && o.error == 0 && !o.invalid);

	current = "R9 MMSI 0 stays unflagged";
	o = rx.send(1, 0, 168);
	CHECK(o.sent && o.error == 0 && !o.invalid);

	current = "R10 MMSI above 999999999";
	o = rx.send(1, 1073741823, 168);
	CHECK(o.sent && o.invalid && o.mmsi == 1073741823);
	CHECK(o.error == (MESSAGE_ERROR_INVALID | MESSAGE_ERROR_INVALID_MMSI));

	current = "R11 one bit oversized is below the QuickReset limit";
	o = rx.send(1, 244123456, 169);
	CHECK(o.sent && o.error == 0);

	current = "R12/R13 oversized";
	o = rx.send(1, 244123456, 170);
	CHECK(o.sent && !o.invalid && o.error == MESSAGE_ERROR_OVERSIZED);
	o = rx.send(10, 244123456, 80);
	CHECK(o.sent && !o.invalid && o.error == MESSAGE_ERROR_OVERSIZED);

	current = "R15 flags do not leak into the next frame";
	rx.send(45, 244123456, 72);
	o = rx.send(1, 244123456, 168);
	CHECK(o.error == 0 && !o.invalid);
	rx.send(10, 244123456, 80);
	o = rx.send(1, 244123456, 168);
	CHECK(o.error == 0);

	current = "R16 long frame with stuffing";
	o = rx.send(8, 244123456, 1000, 0xFF);
	CHECK(o.sent && o.length == 1000 && o.error == 0);
}

// REPORT_INVALID on, QUICK_RESET on: frames stopped before the CRC stay dropped
static void report_invalid_quick_reset()
{
	Receiver rx(true, true);
	Out o;

	current = "R+Q type 45 stopped early";
	o = rx.send(45, 244123456, 72);
	CHECK(!o.sent);

	current = "R+Q below minimum length";
	o = rx.send(1, 244123456, 100);
	CHECK(o.sent && o.error == (MESSAGE_ERROR_INVALID | MESSAGE_ERROR_INVALID_LENGTH));

	current = "R+Q MMSI and oversize stopped early";
	CHECK(!rx.send(1, 1073741823, 168).sent);
	CHECK(!rx.send(1, 244123456, 170).sent);
	CHECK(!rx.send(10, 244123456, 80).sent);
}

// QUICK_RESET off alone: formerly stopped frames are flagged or dropped, never passed as valid
static void quick_reset_off()
{
	Receiver rx(false, false);
	Out o;

	current = "Q14 MMSI above 999999999 is dropped";
	o = rx.send(1, 1073741823, 168);
	CHECK(!o.sent);

	current = "Q14 oversized is flagged";
	o = rx.send(10, 244123456, 80);
	CHECK(o.sent && o.error == MESSAGE_ERROR_OVERSIZED && !o.invalid);

	current = "Q14 unknown type is dropped";
	CHECK(!rx.send(45, 244123456, 72).sent);
}

int main()
{
	defaults();
	report_invalid();
	report_invalid_quick_reset();
	quick_reset_off();

	if (failures)
	{
		std::printf("%d check(s) failed\n", failures);
		return 1;
	}
	std::printf("all checks passed\n");
	return 0;
}
