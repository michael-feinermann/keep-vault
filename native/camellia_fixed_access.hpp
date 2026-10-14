// Camellia key schedule and Feistel structure adapted from the pinned Crypto++
// camellia.cpp (Kevin Springle 2003, Wei Dai 2007), public domain; distribution
// license external/cryptopp/License.txt. No vendor source is modified.
//
// The original secret-indexed S/SP accesses are replaced for BOTH the key
// schedule and rounds. ARM64 loads all 256 S-box bytes at public addresses and
// selects only inside NEON registers. The portable path reads every entry via
// volatile and branchless masks. This addresses the table-cache mechanism;
// it is not a claim of universal microarchitectural constant-time behavior.
#ifndef KEEPVAULT_CAMELLIA_FIXED_ACCESS_HPP
#define KEEPVAULT_CAMELLIA_FIXED_ACCESS_HPP
#include "camellia.h"
#include "misc.h"
#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#endif
namespace CryptoPP {
// Stack-only ownership for derived key/state words. Destruction is non-throwing
// and runs on both successful returns and exception unwinding.
template<class T, size_t N> struct KeepVaultCamelliaScopedWords {
    T values[N]{};
    ~KeepVaultCamelliaScopedWords() noexcept { SecureWipeBuffer(values, N); }
};
class CamelliaFixedAccess final : public Camellia::Encryption {
public:
    void UncheckedSetKey(const byte*, unsigned int, const NameValuePairs&) override;
    void ProcessAndXorBlock(const byte*, const byte*, byte*) const override;
};
inline void keepvault_camellia_sbox8(const byte* table, byte indices[8]) {
#if defined(__aarch64__) || defined(_M_ARM64)
    const uint8x16_t input = vcombine_u8(vld1_u8(indices), vdup_n_u8(0));
    const uint8x16_t low = vandq_u8(input, vdupq_n_u8(63));
    const uint8x16_t high = vandq_u8(input, vdupq_n_u8(192));
    uint8x16_t result = vdupq_n_u8(0);
    for (unsigned part = 0; part < 4; ++part) {
        uint8x16x4_t registers;
        for (unsigned vector = 0; vector < 4; ++vector)
            registers.val[vector] = vld1q_u8(table + part * 64 + vector * 16);
        const uint8x16_t selected = vqtbl4q_u8(registers, low);
        result = vorrq_u8(result, vandq_u8(selected, vceqq_u8(high, vdupq_n_u8(static_cast<byte>(part * 64)))));
    }
    vst1_u8(indices, vget_low_u8(result));
#else
    byte result[8] = {};
    const volatile byte* fixed_table = table;
    for (unsigned i = 0; i < 256; ++i) {
        const unsigned value = fixed_table[i];
        for (unsigned lane = 0; lane < 8; ++lane) {
            const unsigned difference = i ^ indices[lane];
            const unsigned mask = ((difference - 1u) >> 8) & 255u;
            result[lane] |= static_cast<byte>(value & mask);
        }
    }
    std::memcpy(indices, result, sizeof(result));
    SecureWipeBuffer(result, sizeof(result));
#endif
}
#define SLOW_ROUND(lh, ll, rh, rl, kh, kl) { \
    KeepVaultCamelliaScopedWords<word32, 2> roundWords; \
    word32 &zr = roundWords.values[0], &zl = roundWords.values[1]; \
    zr = ll ^ kl; zl = lh ^ kh; \
    KeepVaultCamelliaScopedWords<byte, 8> substitutions{{byte(zr >> 24), byte(zr >> 16), rotlConstant<1>(byte(zr >> 8)), byte(zr), \
                 byte(zl >> 24), byte(zl >> 16), byte(zl >> 8), rotlConstant<1>(byte(zl))}}; \
    byte *s = substitutions.values; \
    keepvault_camellia_sbox8(s1, s); \
    zr = word32(rotlConstant<1>(s[0])) | (word32(rotrConstant<1>(s[1])) << 24) | (word32(s[2]) << 16) | (word32(s[3]) << 8); \
    zl = (word32(s[4]) << 24) | (word32(rotlConstant<1>(s[5])) << 16) | (word32(rotrConstant<1>(s[6])) << 8) | s[7]; \
    zl ^= zr; zr = zl ^ rotlConstant<8>(zr); zl = zr ^ rotrConstant<8>(zl); \
    rh ^= rotlConstant<16>(zr); rh ^= zl; rl ^= rotlConstant<8>(zl); \
}
#define ROUND SLOW_ROUND
#define DOUBLE_ROUND(lh, ll, rh, rl, k0, k1, k2, k3) \
    ROUND(lh, ll, rh, rl, k0, k1) \
    ROUND(rh, rl, lh, ll, k2, k3)
#if CRYPTOPP_LITTLE_ENDIAN
#define EFI(i) (1-(i))
#else
#define EFI(i) (i)
#endif
inline void CamelliaFixedAccess::UncheckedSetKey(const byte *key, unsigned int keylen, const NameValuePairs &)
{
	m_rounds = (keylen >= 24) ? 4 : 3;
	unsigned int kslen = (8 * m_rounds + 2);
	m_key.New(kslen*2);
	word32 *ks32 = m_key.data();
	int m=0, a=0;
	if (!IsForwardTransformation())
		m = -1, a = kslen-1;

    KeepVaultCamelliaScopedWords<word32, 12> scheduleWords;
    word32 &kl0 = scheduleWords.values[0], &kl1 = scheduleWords.values[1];
    word32 &kl2 = scheduleWords.values[2], &kl3 = scheduleWords.values[3];
    word32 &k0 = scheduleWords.values[4], &k1 = scheduleWords.values[5];
    word32 &k2 = scheduleWords.values[6], &k3 = scheduleWords.values[7];
    word32 &kr0 = scheduleWords.values[8], &kr1 = scheduleWords.values[9];
    word32 &kr2 = scheduleWords.values[10], &kr3 = scheduleWords.values[11];
	GetBlock<word32, BigEndian> getBlock(key);
	getBlock(kl0)(kl1)(kl2)(kl3);
	k0=kl0, k1=kl1, k2=kl2, k3=kl3;

#define CALC_ADDR2(base, i, j)	((byte *)(base)+8*(i)+4*(j)+((-16*(i))&m))
#define CALC_ADDR(base, i)	CALC_ADDR2(base, i, 0)

    KeepVaultCamelliaScopedWords<word64, 2> rotatedWords;
    word64 &kwl = rotatedWords.values[0], &kwr = rotatedWords.values[1];
	ks32 += 2*a;
#define PREPARE_KS_ROUNDS			\
	kwl = (word64(k0) << 32) | k1;	\
	kwr = (word64(k2) << 32) | k3
#define KS_ROUND_0(i)							\
	CRYPTOPP_ASSERT(IsAlignedOn(CALC_ADDR(ks32, i+EFI(0)),GetAlignmentOf<word64>()));	\
	CRYPTOPP_ASSERT(IsAlignedOn(CALC_ADDR(ks32, i+EFI(1)),GetAlignmentOf<word64>()));	\
	*(word64*)(void*)CALC_ADDR(ks32, i+EFI(0)) = kwl;	\
	*(word64*)(void*)CALC_ADDR(ks32, i+EFI(1)) = kwr
#define KS_ROUND(i, r, which)																						\
	CRYPTOPP_ASSERT(IsAlignedOn(CALC_ADDR(ks32, i+EFI(r<64)),GetAlignmentOf<word64>()));	\
	CRYPTOPP_ASSERT(IsAlignedOn(CALC_ADDR(ks32, i+EFI(r>64)),GetAlignmentOf<word64>()));	\
	if (which & (1<<int(r<64))) *(word64*)(void*)CALC_ADDR(ks32, i+EFI(r<64)) = (kwr << (r%64)) | (kwl >> (64 - (r%64)));	\
	if (which & (1<<int(r>64))) *(word64*)(void*)CALC_ADDR(ks32, i+EFI(r>64)) = (kwl << (r%64)) | (kwr >> (64 - (r%64)))


	if (keylen == 16)
	{
		// KL
		PREPARE_KS_ROUNDS;
		KS_ROUND_0(0);
		KS_ROUND(4, 15, 3);
		KS_ROUND(10, 45, 3);
		KS_ROUND(12, 60, 2);
		KS_ROUND(16, 77, 3);
		KS_ROUND(18, 94, 3);
		KS_ROUND(22, 111, 3);

		// KA
		k0=kl0, k1=kl1, k2=kl2, k3=kl3;
		DOUBLE_ROUND(k0, k1, k2, k3, 0xA09E667Ful, 0x3BCC908Bul, 0xB67AE858ul, 0x4CAA73B2ul);
		k0^=kl0, k1^=kl1, k2^=kl2, k3^=kl3;
		DOUBLE_ROUND(k0, k1, k2, k3, 0xC6EF372Ful, 0xE94F82BEul, 0x54FF53A5ul, 0xF1D36F1Cul);

		PREPARE_KS_ROUNDS;
		KS_ROUND_0(2);
		KS_ROUND(6, 15, 3);
		KS_ROUND(8, 30, 3);
		KS_ROUND(12, 45, 1);
		KS_ROUND(14, 60, 3);
		KS_ROUND(20, 94, 3);
		KS_ROUND(24, 47, 3);
	}
	else
	{
		// KL
		PREPARE_KS_ROUNDS;
		KS_ROUND_0(0);
		KS_ROUND(12, 45, 3);
		KS_ROUND(16, 60, 3);
		KS_ROUND(22, 77, 3);
		KS_ROUND(30, 111, 3);

		// KR
		GetBlock<word32, BigEndian>(key+16)(kr0)(kr1);
		if (keylen == 24)
			kr2 = ~kr0, kr3 = ~kr1;
		else
			GetBlock<word32, BigEndian>(key+24)(kr2)(kr3);
		k0=kr0, k1=kr1, k2=kr2, k3=kr3;

		PREPARE_KS_ROUNDS;
		KS_ROUND(4, 15, 3);
		KS_ROUND(8, 30, 3);
		KS_ROUND(18, 60, 3);
		KS_ROUND(26, 94, 3);

		// KA
		k0^=kl0, k1^=kl1, k2^=kl2, k3^=kl3;
		DOUBLE_ROUND(k0, k1, k2, k3, 0xA09E667Ful, 0x3BCC908Bul, 0xB67AE858ul, 0x4CAA73B2ul);
		k0^=kl0, k1^=kl1, k2^=kl2, k3^=kl3;
		DOUBLE_ROUND(k0, k1, k2, k3, 0xC6EF372Ful, 0xE94F82BEul, 0x54FF53A5ul, 0xF1D36F1Cul);

		PREPARE_KS_ROUNDS;
		KS_ROUND(6, 15, 3);
		KS_ROUND(14, 45, 3);
		KS_ROUND(24, 77, 3);
		KS_ROUND(28, 94, 3);

		// KB
		k0^=kr0, k1^=kr1, k2^=kr2, k3^=kr3;
		DOUBLE_ROUND(k0, k1, k2, k3, 0x10E527FAul, 0xDE682D1Dul, 0xB05688C2ul, 0xB3E6C1FDul);

		PREPARE_KS_ROUNDS;
		KS_ROUND_0(2);
		KS_ROUND(10, 30, 3);
		KS_ROUND(20, 60, 3);
		KS_ROUND(32, 47, 3);
	}
}

inline void CamelliaFixedAccess::ProcessAndXorBlock(const byte *inBlock, const byte *xorBlock, byte *outBlock) const
{
#define KS(i, j) ks[i*4 + EFI(j/2)*2 + EFI(j%2)]

#define FL(klh, kll, krh, krl)		\
	ll ^= rotlConstant<1>(lh & klh);\
	lh ^= (ll | kll);				\
	rh ^= (rl | krl);				\
	rl ^= rotlConstant<1>(rh & krh);

    KeepVaultCamelliaScopedWords<word32, 4> blockWords;
    word32 &lh = blockWords.values[0], &ll = blockWords.values[1];
    word32 &rh = blockWords.values[2], &rl = blockWords.values[3];
	typedef BlockGetAndPut<word32, BigEndian> Block;
	Block::Get(inBlock)(lh)(ll)(rh)(rl);
	const word32 *ks = m_key.data();
	lh ^= KS(0,0);
	ll ^= KS(0,1);
	rh ^= KS(0,2);
	rl ^= KS(0,3);

	unsigned int i;

	SLOW_ROUND(lh, ll, rh, rl, KS(1,0), KS(1,1))
	SLOW_ROUND(rh, rl, lh, ll, KS(1,2), KS(1,3))
	for (i = m_rounds-1; i > 0; --i)
	{
		DOUBLE_ROUND(lh, ll, rh, rl, KS(2,0), KS(2,1), KS(2,2), KS(2,3))
		DOUBLE_ROUND(lh, ll, rh, rl, KS(3,0), KS(3,1), KS(3,2), KS(3,3))
		FL(KS(4,0), KS(4,1), KS(4,2), KS(4,3));
		DOUBLE_ROUND(lh, ll, rh, rl, KS(5,0), KS(5,1), KS(5,2), KS(5,3))
		ks += 16;
	}
	DOUBLE_ROUND(lh, ll, rh, rl, KS(2,0), KS(2,1), KS(2,2), KS(2,3))
	ROUND(lh, ll, rh, rl, KS(3,0), KS(3,1))
	SLOW_ROUND(rh, rl, lh, ll, KS(3,2), KS(3,3))
	lh ^= KS(4,0);
	ll ^= KS(4,1);
	rh ^= KS(4,2);
	rl ^= KS(4,3);
	Block::Put(xorBlock, outBlock)(rh)(rl)(lh)(ll);
}


#undef SLOW_ROUND
#undef ROUND
#undef DOUBLE_ROUND
#undef EFI
#undef CALC_ADDR2
#undef CALC_ADDR
#undef PREPARE_KS_ROUNDS
#undef KS_ROUND_0
#undef KS_ROUND
#undef KS
#undef FL
} // namespace CryptoPP
#endif
