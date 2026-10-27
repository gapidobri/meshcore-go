// Golden vector generator: links the upstream C++ MeshCore sources and prints
// JSON test vectors (crypto, encodings, and a two-node mesh scenario) for the
// Go implementation to assert byte equality against.
//
// Built and run by gen.sh. Keep the scenario in sync with golden_test.go.

#include <Mesh.h>
#include <Utils.h>
#include <helpers/AdvertDataHelpers.h>
#include <helpers/SimpleMeshTables.h>
#include <helpers/StaticPoolPacketManager.h>
#include <helpers/TxtDataHelpers.h>
#include <SHA256.h>

#include <cstdarg>
#include <functional>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace mesh;

typedef std::vector<uint8_t> Bytes;

static std::string hex(const uint8_t* b, size_t n) {
  std::string s(n * 2 + 1, '\0');
  Utils::toHex(&s[0], b, n);
  s.resize(n * 2);
  return s;
}
static std::string hex(const Bytes& b) { return hex(b.data(), b.size()); }

static std::string fmt(const char* f, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, f);
  vsnprintf(buf, sizeof(buf), f, ap);
  va_end(ap);
  return buf;
}

static Bytes pattern(int n, int a, int b) {
  Bytes v(n);
  for (int i = 0; i < n; i++) v[i] = (uint8_t)(a + i * b);
  return v;
}

static Bytes str(const char* s) { return Bytes(s, s + strlen(s)); }

// timestamp (LE) + flags byte + text, like the chat payloads
static Bytes msg(uint32_t ts, uint8_t flags, const char* text) {
  Bytes v(5);
  memcpy(v.data(), &ts, 4);
  v[4] = flags;
  v.insert(v.end(), text, text + strlen(text));
  return v;
}

// ---------------------------------------------------------------- JSON output

static bool first_item;
static void begin_array(const char* name, bool first = false) {
  printf("%s\"%s\": [\n", first ? "" : ",\n", name);
  first_item = true;
}
static void item(const std::string& s) {
  printf("%s    %s", first_item ? "" : ",\n", s.c_str());
  first_item = false;
}
static void end_array() { printf("\n  ]"); }

static std::string jstr(const std::string& s) {
  std::string o = "\"";
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') { o += '\\'; o += (char)c; }
    else if (c < 0x20) o += fmt("\\u%04x", c);
    else o += (char)c;
  }
  return o + "\"";
}

// ------------------------------------------------------------- test doubles

struct XorShiftRNG : public RNG {
  uint32_t s;
  explicit XorShiftRNG(uint32_t seed) : s(seed) {}
  void random(uint8_t* dest, size_t sz) override {
    for (size_t i = 0; i < sz; i++) {
      s ^= s << 13;
      s ^= s >> 17;
      s ^= s << 5;
      dest[i] = s & 0xFF;
    }
  }
};

struct FakeMillis : public MillisecondClock {
  unsigned long t = 1000;
  unsigned long getMillis() override { return t; }
};

struct FakeRTC : public RTCClock {
  uint32_t t = 1700000000;
  uint32_t getCurrentTime() override { return t; }
  void setCurrentTime(uint32_t x) override { t = x; }
};

static std::vector<std::string>* g_log;

struct FakeRadio : public Radio {
  std::string tag;
  std::vector<Bytes> rxq;
  FakeRadio* peer = nullptr;
  bool sending = false;

  int recvRaw(uint8_t* bytes, int sz) override {
    if (rxq.empty()) return 0;
    Bytes b = rxq.front();
    rxq.erase(rxq.begin());
    int n = (int)b.size() < sz ? (int)b.size() : sz;
    memcpy(bytes, b.data(), n);
    return n;
  }
  uint32_t getEstAirtimeFor(int len_bytes) override { return len_bytes * 2; }
  float packetScore(float snr, int packet_len) override { return 0.3f; }
  bool startSendRaw(const uint8_t* bytes, int len) override {
    Bytes b(bytes, bytes + len);
    g_log->push_back(tag + ":TX " + hex(b));
    if (peer) peer->rxq.push_back(b);
    sending = true;
    return true;
  }
  bool isSendComplete() override {
    if (sending) { sending = false; return true; }
    return false;
  }
  void onSendFinished() override {}
  bool isInRecvMode() const override { return !sending; }
  float getLastRSSI() const override { return -80.0f; }
  float getLastSNR() const override { return 5.25f; }
};

class TestMesh : public Mesh {
public:
  std::string tag;
  std::vector<Identity> contacts;
  std::vector<GroupChannel> channels;
  int matches[8];

  TestMesh(Radio& radio, MillisecondClock& ms, RNG& rng, RTCClock& rtc, PacketManager& mgr, MeshTables& tables)
    : Mesh(radio, ms, rng, rtc, mgr, tables) {}

  void ev(const std::string& s) { g_log->push_back(tag + ":" + s); }

protected:
  bool allowPacketForward(const Packet* packet) override { return true; }
  uint8_t getExtraAckTransmitCount() const override { return 1; }

  int searchPeersByHash(const uint8_t* hash) override {
    int n = 0;
    for (size_t i = 0; i < contacts.size() && n < 8; i++) {
      if (contacts[i].isHashMatch(hash)) matches[n++] = (int)i;
    }
    return n;
  }
  void getPeerSharedSecret(uint8_t* dest_secret, int peer_idx) override {
    self_id.calcSharedSecret(dest_secret, contacts[matches[peer_idx]]);
  }
  int searchChannelsByHash(const uint8_t* hash, GroupChannel dest[], int max_matches) override {
    int n = 0;
    for (size_t i = 0; i < channels.size() && n < max_matches; i++) {
      if (channels[i].hash[0] == hash[0]) dest[n++] = channels[i];
    }
    return n;
  }

  void onPeerDataRecv(Packet* packet, uint8_t type, int sender_idx, const uint8_t* secret, uint8_t* data, size_t len) override {
    ev(fmt("PEERDATA type=%d idx=%d data=%s", type, sender_idx, hex(data, len).c_str()));
  }
  void onTraceRecv(Packet* packet, uint32_t tag, uint32_t auth_code, uint8_t flags, const uint8_t* path_snrs, const uint8_t* path_hashes, uint8_t path_len) override {
    ev(fmt("TRACE tag=%u auth=%u flags=%d snrs=%s hashes=%s", tag, auth_code, flags,
           hex(path_snrs, packet->path_len).c_str(), hex(path_hashes, path_len).c_str()));
  }
  bool onPeerPathRecv(Packet* packet, int sender_idx, const uint8_t* secret, uint8_t* path, uint8_t path_len, uint8_t extra_type, uint8_t* extra, uint8_t extra_len) override {
    int pb = (path_len & 63) * ((path_len >> 6) + 1);
    ev(fmt("PATHRECV idx=%d path_len=%d path=%s extra_type=%d extra=%s", sender_idx, path_len,
           hex(path, pb).c_str(), extra_type, hex(extra, extra_len).c_str()));
    return true;
  }
  void onAdvertRecv(Packet* packet, const Identity& id, uint32_t timestamp, const uint8_t* app_data, size_t app_data_len) override {
    ev(fmt("ADVERT pub=%s ts=%u app=%s", hex(id.pub_key, PUB_KEY_SIZE).c_str(), timestamp, hex(app_data, app_data_len).c_str()));
  }
  void onAnonDataRecv(Packet* packet, const uint8_t* secret, const Identity& sender, uint8_t* data, size_t len) override {
    ev(fmt("ANON sender=%s data=%s", hex(sender.pub_key, PUB_KEY_SIZE).c_str(), hex(data, len).c_str()));
  }
  void onControlDataRecv(Packet* packet) override {
    ev(fmt("CONTROL payload=%s", hex(packet->payload, packet->payload_len).c_str()));
  }
  void onRawDataRecv(Packet* packet) override {
    ev(fmt("RAW payload=%s", hex(packet->payload, packet->payload_len).c_str()));
  }
  void onGroupDataRecv(Packet* packet, uint8_t type, const GroupChannel& channel, uint8_t* data, size_t len) override {
    ev(fmt("GROUP type=%d ch=%s data=%s", type, hex(channel.hash, PATH_HASH_SIZE).c_str(), hex(data, len).c_str()));
  }
  void onAckRecv(Packet* packet, uint32_t ack_crc) override {
    ev(fmt("ACK crc=%08X", ack_crc));
  }
};

struct Node {
  FakeRadio radio;
  FakeMillis ms;
  XorShiftRNG rng;
  FakeRTC rtc;
  StaticPoolPacketManager mgr;
  SimpleMeshTables tables;
  TestMesh mesh;

  Node(const char* tag, uint32_t rng_seed, const Bytes& id_seed)
    : rng(rng_seed), mgr(16), mesh(radio, ms, rng, rtc, mgr, tables) {
    radio.tag = tag;
    mesh.tag = tag;
    // LocalIdentity has no seed constructor; feed the seed through an RNG
    struct SeedRNG : public RNG {
      const Bytes& s;
      explicit SeedRNG(const Bytes& s) : s(s) {}
      void random(uint8_t* d, size_t n) override { memcpy(d, s.data(), n); }
    } seeder(id_seed);
    mesh.self_id = LocalIdentity(&seeder);
  }
};

static GroupChannel makeChannel(const Bytes& secret16) {
  GroupChannel ch;
  memset(ch.secret, 0, sizeof(ch.secret));
  memcpy(ch.secret, secret16.data(), 16);
  Utils::sha256(ch.hash, PATH_HASH_SIZE, ch.secret, 16);
  return ch;
}

static void run(Node& a, Node& b, int iterations) {
  for (int i = 0; i < iterations; i++) {
    a.ms.t += 10;
    b.ms.t += 10;
    a.mesh.loop();
    b.mesh.loop();
  }
}

static Bytes rawOf(const Packet* p) {
  uint8_t buf[MAX_TRANS_UNIT + 8];
  int n = p->writeTo(buf);
  return Bytes(buf, buf + n);
}

static void inject(Node& n, const Bytes& raw) {
  g_log->push_back(n.mesh.tag + ":INJECT " + hex(raw));
  n.radio.rxq.push_back(raw);
}

// ------------------------------------------------------------------ vectors

static void emitCrypto() {
  std::vector<LocalIdentity> keys;
  begin_array("keys", true);
  for (int i = 0; i < 8; i++) {
    Bytes seed = pattern(32, i * 31 + 1, 7);
    struct SeedRNG : public RNG {
      const Bytes& s;
      explicit SeedRNG(const Bytes& s) : s(s) {}
      void random(uint8_t* d, size_t n) override { memcpy(d, s.data(), n); }
    } seeder(seed);
    LocalIdentity id(&seeder);
    uint8_t blob[PRV_KEY_SIZE + PUB_KEY_SIZE];
    id.writeTo(blob, sizeof(blob));
    keys.push_back(id);
    item(fmt("{\"seed\": \"%s\", \"pub\": \"%s\", \"prv\": \"%s\", \"valid\": %s}", hex(seed).c_str(),
             hex(id.pub_key, PUB_KEY_SIZE).c_str(), hex(blob, PRV_KEY_SIZE).c_str(),
             LocalIdentity::validatePrivateKey(blob) ? "true" : "false"));
  }
  end_array();

  begin_array("signs");
  int lens[] = {0, 1, 31, 68, 200};
  for (int i = 0; i < 8; i++) {
    for (int l : lens) {
      Bytes msg = pattern(l, i + l, 3);
      uint8_t sig[SIGNATURE_SIZE];
      keys[i].sign(sig, msg.data(), (int)msg.size());
      bool ok = keys[i].verify(sig, msg.data(), (int)msg.size());
      sig[5] ^= 1;
      bool bad = keys[i].verify(sig, msg.data(), (int)msg.size());
      sig[5] ^= 1;
      item(fmt("{\"key\": %d, \"msg\": \"%s\", \"sig\": \"%s\", \"ok\": %s, \"tampered_ok\": %s}", i, hex(msg).c_str(),
               hex(sig, SIGNATURE_SIZE).c_str(), ok ? "true" : "false", bad ? "true" : "false"));
    }
  }
  end_array();

  begin_array("ecdh");
  std::vector<Bytes> odd_pubs = {
    Bytes(32, 0x00),
    [] { Bytes b(32, 0); b[0] = 1; return b; }(),            // y = 1, so 1-y = 0
    [] { Bytes b(32, 0xFF); return b; }(),                    // non-canonical y, sign bit set
    [] { Bytes b(32, 0xFF); b[0] = 0xEE; b[31] = 0x7F; return b; }(),  // y = p+... non-canonical
  };
  for (int i = 0; i < 8; i++) {
    uint8_t blob[PRV_KEY_SIZE];
    keys[i].writeTo(blob, PRV_KEY_SIZE);
    std::vector<Bytes> pubs;
    pubs.push_back(Bytes(keys[(i + 1) % 8].pub_key, keys[(i + 1) % 8].pub_key + PUB_KEY_SIZE));
    if (i < (int)odd_pubs.size()) pubs.push_back(odd_pubs[i]);
    for (auto& pub : pubs) {
      uint8_t secret[PUB_KEY_SIZE];
      keys[i].calcSharedSecret(secret, pub.data());
      item(fmt("{\"prv\": \"%s\", \"pub\": \"%s\", \"secret\": \"%s\"}", hex(blob, PRV_KEY_SIZE).c_str(), hex(pub).c_str(),
               hex(secret, PUB_KEY_SIZE).c_str()));
    }
  }
  end_array();

  begin_array("validate");
  std::vector<Bytes> prvs = {Bytes(64, 0x00), Bytes(64, 0xFF), pattern(64, 9, 13), pattern(64, 200, 1)};
  for (auto& p : prvs) {
    item(fmt("{\"prv\": \"%s\", \"valid\": %s}", hex(p).c_str(), LocalIdentity::validatePrivateKey(p.data()) ? "true" : "false"));
  }
  end_array();

  begin_array("cipher");
  for (int l = 0; l <= 40; l += 3) {
    Bytes key = pattern(32, l * 5 + 3, 11);
    Bytes plain = pattern(l, l, 17);
    uint8_t enc[64], etm[80], dec[80];
    int enc_len = Utils::encrypt(key.data(), enc, plain.data(), (int)plain.size());
    int etm_len = Utils::encryptThenMAC(key.data(), etm, plain.data(), (int)plain.size());
    int dec_len = Utils::MACThenDecrypt(key.data(), dec, etm, etm_len);
    etm[etm_len - 1] ^= 0x80;
    int bad_len = Utils::MACThenDecrypt(key.data(), dec + 40, etm, etm_len);
    etm[etm_len - 1] ^= 0x80;
    item(fmt("{\"key\": \"%s\", \"plain\": \"%s\", \"enc\": \"%s\", \"etm\": \"%s\", \"dec\": \"%s\", \"bad_len\": %d}",
             hex(key).c_str(), hex(plain).c_str(), hex(enc, enc_len).c_str(), hex(etm, etm_len).c_str(),
             hex(dec, dec_len).c_str(), bad_len));
  }
  end_array();

  begin_array("sha");
  for (int l = 0; l <= 130; l += 13) {
    Bytes msg = pattern(l, l, 29);
    Bytes frag = pattern(l / 2, 7, 1);
    uint8_t h1[32], h2[32];
    Utils::sha256(h1, 32, msg.data(), (int)msg.size());
    Utils::sha256(h2, 8, msg.data(), (int)msg.size(), frag.data(), (int)frag.size());
    item(fmt("{\"msg\": \"%s\", \"frag\": \"%s\", \"hash\": \"%s\", \"hash2_8\": \"%s\"}", hex(msg).c_str(),
             hex(frag).c_str(), hex(h1, 32).c_str(), hex(h2, 8).c_str()));
  }
  end_array();
}

static void emitPackets() {
  begin_array("packets");
  std::vector<Bytes> raws = {
    {0x11, 0x00, 0xAA, 0xBB, 0xCC},                         // flood ADVERT, no path
    {0x0A, 0x02, 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF},       // direct TXT_MSG, path 2
    {0x24, 0x03, 0x11, 0x22, 0x33, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00},  // direct TRACE
    {0x26, 0x01, 0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00},              // TRACE path_len 1
    {0x14, 0x34, 0x12, 0xCD, 0xAB, 0x41, 0x01, 0x02, 0x03, 0x04, 0x55},  // transport flood GRP_TXT, 2-byte hashes
    {0x0F, 0x00, 0x01},                                     // transport direct ACK
    {0x15, 0xC1, 0x01, 0x02},                               // path mode 3 (invalid)
    {0x55, 0x00, 0x01},                                     // version 1 header
    {0x15, 0x05, 0x01, 0x02},                               // path longer than packet
    {0x15, 0x00},                                           // no payload
  };
  for (auto& r : raws) {
    Packet p;
    bool ok = p.readFrom(r.data(), (uint8_t)r.size());
    uint8_t h[MAX_HASH_SIZE] = {0};
    uint8_t back[MAX_TRANS_UNIT];
    int back_len = 0;
    if (ok) {
      p.calculatePacketHash(h);
      back_len = p.writeTo(back);
    }
    item(fmt("{\"raw\": \"%s\", \"ok\": %s, \"hash\": \"%s\", \"encoded\": \"%s\", \"raw_len\": %d}", hex(r).c_str(),
             ok ? "true" : "false", ok ? hex(h, MAX_HASH_SIZE).c_str() : "", hex(back, back_len).c_str(),
             ok ? p.getRawLength() : 0));
  }
  end_array();
}

static void emitAdverts() {
  begin_array("adverts");
  struct Case { uint8_t type; const char* name; bool loc; double lat, lon; uint16_t f1, f2; };
  Case cases[] = {
    {ADV_TYPE_CHAT, "Alice", false, 0, 0, 0, 0},
    {ADV_TYPE_REPEATER, "Ljubljana RPT", true, 46.056946, 14.505751, 0, 0},
    {ADV_TYPE_ROOM, nullptr, true, -33.8688, 151.2093, 0x1234, 0},
    {ADV_TYPE_SENSOR, "S", false, 0, 0, 0x0102, 0xA0B0},
    {ADV_TYPE_CHAT, "A very long name that will be truncated!", true, 1.5, -2.5, 7, 9},
    {ADV_TYPE_CHAT, "\xC5\xBDiga \xF0\x9F\x98\x80\xF0\x9F\x98\x80\xF0\x9F\x98\x80\xF0\x9F\x98\x80\xF0\x9F\x98\x80", false, 0, 0, 0, 0},
    {ADV_TYPE_CHAT, "bad\xC3", false, 0, 0, 0, 0},
    {ADV_TYPE_NONE, "", false, 0, 0, 0, 0},
  };
  for (auto& c : cases) {
    AdvertDataBuilder b = c.loc ? AdvertDataBuilder(c.type, c.name, c.lat, c.lon) : AdvertDataBuilder(c.type, c.name);
    b.setFeat1(c.f1);
    b.setFeat2(c.f2);
    uint8_t app[MAX_ADVERT_DATA_SIZE];
    uint8_t n = b.encodeTo(app);
    AdvertDataParser p(app, n);
    item(fmt("{\"type\": %d, \"name\": \"%s\", \"loc\": %s, \"lat\": %.9f, \"lon\": %.9f, \"f1\": %d, \"f2\": %d, "
             "\"enc\": \"%s\", \"p_valid\": %s, \"p_type\": %d, \"p_name\": \"%s\", \"p_lat\": %d, \"p_lon\": %d, \"p_f1\": %d, \"p_f2\": %d}",
             c.type, c.name ? hex((const uint8_t*)c.name, strlen(c.name)).c_str() : "", c.loc ? "true" : "false", c.lat,
             c.lon, c.f1, c.f2, hex(app, n).c_str(), p.isValid() ? "true" : "false", p.getType(),
             hex((const uint8_t*)p.getName(), strlen(p.getName())).c_str(), p.getIntLat(), p.getIntLon(), p.getFeat1(),
             p.getFeat2()));
  }
  end_array();

  begin_array("reltime");
  int32_t secs[] = {0, 5, -5, 59, 60, -125, 3599, 3600, -7200, 86399, 86400, -864000};
  for (int32_t s : secs) {
    for (int sh = 0; sh < 2; sh++) {
      char buf[64];
      AdvertTimeHelper::formatRelativeTimeDiff(buf, s, sh);
      item(fmt("{\"secs\": %d, \"short\": %s, \"s\": %s}", s, sh ? "true" : "false", jstr(buf).c_str()));
    }
  }
  end_array();

  begin_array("ftoa");
  float fs[] = {0.0f, 1.0f, -1.0f, 0.5f, 3.14159265f, -2.71828f, 123456.789f, 0.0001234f, 1e-9f, 3e9f, 869.618f, 62.5f, -0.4996f, 0.0005f, 12.3456f};
  for (float f : fs) {
    uint32_t bits;
    memcpy(&bits, &f, 4);
    std::string s1 = StrHelper::ftoa(f);
    std::string s3 = StrHelper::ftoa3(f);
    item(fmt("{\"bits\": %u, \"ftoa\": %s, \"ftoa3\": %s}", bits, jstr(s1).c_str(), jstr(s3).c_str()));
  }
  end_array();
}

// ----------------------------------------------------------------- scenario

static void emitScenario() {
  Bytes seedA = pattern(32, 0xA0, 3), seedB = pattern(32, 0xB0, 5), seedC = pattern(32, 0xC0, 7);
  Node a("A", 0x12345678, seedA);
  Node b("B", 0x9ABCDEF0, seedB);
  a.radio.peer = &b.radio;
  b.radio.peer = &a.radio;
  a.mesh.contacts.push_back(b.mesh.self_id);
  b.mesh.contacts.push_back(a.mesh.self_id);
  GroupChannel chan = makeChannel(pattern(16, 0x42, 9));
  a.mesh.channels.push_back(chan);
  b.mesh.channels.push_back(chan);

  LocalIdentity c;
  {
    struct SeedRNG : public RNG {
      const Bytes& s;
      explicit SeedRNG(const Bytes& s) : s(s) {}
      void random(uint8_t* d, size_t n) override { memcpy(d, s.data(), n); }
    } seeder(seedC);
    c = LocalIdentity(&seeder);
  }

  uint8_t secretAB[PUB_KEY_SIZE];
  a.mesh.self_id.calcSharedSecret(secretAB, b.mesh.self_id);
  uint8_t bHash = b.mesh.self_id.pub_key[0];
  uint8_t aHash = a.mesh.self_id.pub_key[0];

  a.mesh.begin();
  b.mesh.begin();

  struct Step { const char* name; std::vector<std::string> log; };
  std::vector<Step> steps;
  std::vector<std::string> log;
  g_log = &log;

  auto step = [&](const char* name, std::function<void()> fn) {
    log.clear();
    fn();
    run(a, b, 300);
    steps.push_back({name, log});
  };

  auto appData = [](AdvertDataBuilder b) {
    Bytes v(MAX_ADVERT_DATA_SIZE);
    v.resize(b.encodeTo(v.data()));
    return v;
  };

  step("advert", [&] {
    Bytes app = appData(AdvertDataBuilder(ADV_TYPE_CHAT, "Alice", 46.05, 14.5));
    a.mesh.sendFlood(a.mesh.createAdvert(a.mesh.self_id, app.data(), app.size()));
  });
  step("advert_hash2", [&] {
    a.rtc.t += 10;
    Bytes app = appData(AdvertDataBuilder(ADV_TYPE_REPEATER, "Alice2"));
    a.mesh.sendFlood(a.mesh.createAdvert(a.mesh.self_id, app.data(), app.size()), (uint32_t)0, 2);
  });
  step("advert_from_c", [&] {
    Bytes app = appData(AdvertDataBuilder(ADV_TYPE_SENSOR, "Carol"));
    a.mesh.sendFlood(a.mesh.createAdvert(c, app.data(), app.size()), 100);
  });
  step("txt_flood", [&] {
    Bytes d = msg(0x04030201, 0, "hello B");
    a.mesh.sendFlood(a.mesh.createDatagram(PAYLOAD_TYPE_TXT_MSG, b.mesh.self_id, secretAB, d.data(), d.size()));
  });
  step("req_zero_hop_direct", [&] {
    Bytes d = pattern(20, 1, 1);
    a.mesh.sendDirect(a.mesh.createDatagram(PAYLOAD_TYPE_REQ, b.mesh.self_id, secretAB, d.data(), d.size()), NULL, 0);
  });
  step("response_flood", [&] {
    Bytes d = pattern(150, 9, 2);
    a.mesh.sendFlood(a.mesh.createDatagram(PAYLOAD_TYPE_RESPONSE, b.mesh.self_id, secretAB, d.data(), d.size()));
  });
  step("anon", [&] {
    Bytes d = str("login:password");
    a.mesh.sendFlood(a.mesh.createAnonDatagram(PAYLOAD_TYPE_ANON_REQ, a.mesh.self_id, b.mesh.self_id, secretAB, d.data(), d.size()));
  });
  step("group", [&] {
    Bytes d = msg(0x40302010, 0, "Alice: hi all");
    a.mesh.sendFlood(a.mesh.createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, chan, d.data(), d.size()));
  });
  step("path_return_extra", [&] {
    uint8_t path[] = {0x33, 0x44};
    Bytes extra = str("xyz");
    a.mesh.sendFlood(a.mesh.createPathReturn(b.mesh.self_id, secretAB, path, 2, 3, extra.data(), extra.size()));
  });
  step("path_return_plain", [&] {
    uint8_t path[] = {0x55};
    a.mesh.sendFlood(a.mesh.createPathReturn(b.mesh.self_id, secretAB, path, 1, 0, NULL, 0));
  });
  step("ack_flood", [&] { a.mesh.sendFlood(a.mesh.createAck(0xDEADBEEF)); });
  step("trace", [&] {
    uint8_t path[] = {bHash, aHash};
    a.mesh.sendDirect(a.mesh.createTrace(0x01020304, 0x0A0B0C0D, 0), path, 2);
  });
  step("control_zero_hop", [&] {
    uint8_t d[] = {0x81, 1, 2, 3};
    a.mesh.sendZeroHop(a.mesh.createControlData(d, sizeof(d)));
  });
  step("raw_direct", [&] {
    uint8_t d[] = {0xCA, 0xFE, 0x00, 0x01};
    a.mesh.sendDirect(a.mesh.createRawData(d, sizeof(d)), NULL, 0);
  });
  step("transport_flood", [&] {
    Bytes d = msg(0x41302010, 0, "Alice: transport");
    uint16_t codes[2] = {0x1234, 0xABCD};
    a.mesh.sendFlood(a.mesh.createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, chan, d.data(), d.size()), codes);
  });
  step("transport_zero_hop", [&] {
    uint16_t codes[2] = {0x0102, 0x0304};
    a.mesh.sendZeroHop(a.mesh.createAck(0x01020304), codes);
  });
  step("multiack_direct", [&] {
    uint8_t path[] = {bHash};
    a.mesh.sendDirect(a.mesh.createMultiAck(0xCAFEBABE, 1), path, 1);
  });
  step("ack_direct_hop", [&] {
    uint8_t path[] = {bHash, 0x99};
    a.mesh.sendDirect(a.mesh.createAck(0x11223344), path, 2);
  });
  step("txt_direct_hop", [&] {
    uint8_t path[] = {bHash, 0x98, 0x97};
    Bytes d = str("relay me");
    a.mesh.sendDirect(a.mesh.createDatagram(PAYLOAD_TYPE_TXT_MSG, b.mesh.self_id, secretAB, d.data(), d.size()), path, 3);
  });
  step("dup", [&] {
    Bytes d = msg(0x44332211, 0, "dup");
    Packet* p = a.mesh.createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, chan, d.data(), d.size());
    p->header = (p->header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD;
    p->path_len = 0;
    Bytes raw = rawOf(p);
    a.mesh.releasePacket(p);
    inject(b, raw);
    inject(b, raw);
  });
  step("bad_sig_advert", [&] {
    Bytes app = appData(AdvertDataBuilder(ADV_TYPE_CHAT, "Mallory"));
    Packet* p = a.mesh.createAdvert(c, app.data(), app.size());
    p->header = (p->header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD;
    p->path_len = 0;
    p->payload[40] ^= 0x01;
    Bytes raw = rawOf(p);
    a.mesh.releasePacket(p);
    inject(b, raw);
  });
  step("invalid", [&] {
    inject(b, Bytes{0x55, 0x00, 0x01, 0x02});        // version 1
    inject(b, Bytes{0x15, 0xC1, 0x01, 0x02, 0x03});  // path mode 3
    inject(b, Bytes{0x15});                          // truncated
    inject(b, Bytes{0x15, 0x05, 0x01});              // path longer than packet
    inject(b, Bytes{0x0D, 0x00, 0x01, 0x02});        // short ACK
    inject(b, Bytes{0x09, 0x00, 0x00, 0x01, 0x02});  // short datagram
    inject(b, Bytes{0x11, 0x00, 0x01});              // short advert
  });
  step("full_path_flood", [&] {
    Bytes d = str("full");
    Packet* p = a.mesh.createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, chan, d.data(), d.size());
    p->header = (p->header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD;
    p->setPathHashSizeAndCount(1, 64);
    for (int i = 0; i < 64; i++) p->path[i] = (uint8_t)(0x60 + i);
    Bytes raw = rawOf(p);
    a.mesh.releasePacket(p);
    inject(b, raw);
  });
  step("flood_hash3", [&] {
    Bytes d = str("three");
    Packet* p = a.mesh.createGroupDatagram(PAYLOAD_TYPE_GRP_DATA, chan, d.data(), d.size());
    p->header = (p->header & ~PH_ROUTE_MASK) | ROUTE_TYPE_FLOOD;
    p->setPathHashSizeAndCount(3, 2);
    for (int i = 0; i < 6; i++) p->path[i] = (uint8_t)(0x70 + i);
    Bytes raw = rawOf(p);
    a.mesh.releasePacket(p);
    inject(b, raw);
  });
  step("trace_hash2_end", [&] {
    // TRACE with 2-byte path hashes that has already reached its end
    Packet* p = a.mesh.createTrace(77, 88, 1);
    uint8_t path[] = {0x01, 0x02, bHash, 0x04};
    memcpy(&p->payload[p->payload_len], path, 4);
    p->payload_len += 4;
    p->header = (p->header & ~PH_ROUTE_MASK) | ROUTE_TYPE_DIRECT;
    p->path_len = 2;
    p->path[0] = 0x10;
    p->path[1] = 0x20;
    Bytes raw = rawOf(p);
    a.mesh.releasePacket(p);
    inject(b, raw);
  });
  step("rtc_change_advert", [&] {
    a.rtc.t = 1700000500;
    a.mesh.sendFlood(a.mesh.createAdvert(a.mesh.self_id, NULL, 0));
  });

  begin_array("scenario");
  for (auto& s : steps) {
    std::string lines;
    for (size_t i = 0; i < s.log.size(); i++) lines += (i ? ", " : "") + jstr(s.log[i]);
    item(fmt("{\"name\": \"%s\", \"log\": [", s.name) + lines + "]}");
  }
  end_array();

  printf(",\n\"scenario_meta\": {\"seedA\": \"%s\", \"seedB\": \"%s\", \"seedC\": \"%s\", \"pubA\": \"%s\", \"pubB\": \"%s\", \"secretAB\": \"%s\"}",
         hex(seedA).c_str(), hex(seedB).c_str(), hex(seedC).c_str(), hex(a.mesh.self_id.pub_key, PUB_KEY_SIZE).c_str(),
         hex(b.mesh.self_id.pub_key, PUB_KEY_SIZE).c_str(), hex(secretAB, PUB_KEY_SIZE).c_str());
}

int main() {
  printf("{\n");
  emitCrypto();
  emitPackets();
  emitAdverts();
  emitScenario();
  printf("\n}\n");
  return 0;
}
