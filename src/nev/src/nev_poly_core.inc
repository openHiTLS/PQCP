/* Copyright (c) 2025 LiuRuikang
 * School Of Cyber Engineering, Xidian University
 *
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

/*
 * Per-modulus template for the hot code of the NEV generic C backend
 * (NTT, NTT-CRT arithmetic, packing codecs).
 *
 * This file is #included exactly once from each of nev_poly_q769.c,
 * nev_poly_q1409.c and nev_poly_q3329.c, which define:
 *   NEV_TQ              modulus q: 769, 1409 or 3329
 *   NEV_TQINV_S16       q^-1 mod 2^16 as its signed 16-bit representative
 *   NEV_TBARRETT_V      Barrett multiplier (nev.c parameter table)
 *   NEV_TBARRETT_SHIFT  Barrett shift
 *   NEV_TDIM            per-block NTT size: 64 (q = 1409) or 128 (769/3329)
 *   NEV_TFN(name)       pastes the per-q suffix onto the entry-point names
 *
 * Why a template: the reference implementation compiles one binary per
 * parameter set with q, qinv, the Barrett constants and the NTT dimension as
 * compile-time literals. Loading them from the CRYPT_NevInfo record on every
 * reduction is measurably slower, because the library builds with
 * -fno-strict-aliasing: every int16 coefficient store may alias the info
 * fields, so the compiler must reload q/qinv/barrettV inside the hot loops.
 * All twelve parameter sets share just three moduli, and nttDim is a function
 * of q, so instantiating the hot code once per modulus recovers the
 * reference's constant-folded code generation while keeping runtime parameter
 * set selection: nev_ntt.c / nev_poly.c / nev_pack.c dispatch once per
 * operation on info->q. n (and thus t = n / nttDim) stays a runtime value;
 * the slot-product and inverse towers already dispatch on t, and inside each
 * t branch n = t * NEV_TDIM is again a compile-time constant.
 *
 * The bodies below are the former nev_ntt.c / nev_poly.c / nev_pack.c bodies
 * with the info-> loads replaced by the template constants; the arithmetic,
 * evaluation order and loop structure are unchanged, so the bit-exactness,
 * congruence and range arguments (kept with the functions, see especially the
 * range-verifier script) apply verbatim, and the outputs are BIT-IDENTICAL to
 * the previous runtime-parameter code for every input.
 *
 * t values by modulus (parameter table in nev.c): q = 1409 (nttDim 64) is
 * used with n = 512/1024/2048, i.e. t in {8, 16, 32}; q = 769 and q = 3329
 * (nttDim 128) with t in {4, 8, 16}. The t = 4 path is therefore only
 * instantiated for q != 1409 and the t = 32 tower only for q = 1409.
 */

#if !defined(NEV_TQ) || !defined(NEV_TQINV_S16) || !defined(NEV_TBARRETT_V) || \
    !defined(NEV_TBARRETT_SHIFT) || !defined(NEV_TDIM) || !defined(NEV_TFN)
#error "nev_poly_core.inc requires the NEV_T* template macros (see nev_poly_q769.c)"
#endif

/* ------------------------------------------------------------------ */
/* Modular arithmetic helpers: the nev_local.h inline helpers with the
 * CRYPT_NevInfo loads replaced by the per-q compile-time constants.  */

/* (a * q^-1 mod 2^16) Montgomery reduction: returns a * 2^-16 mod q, in (-q, q). */
static inline int16_t MontReduceQ(int32_t a)
{
    int16_t t = (int16_t)((int32_t)(int16_t)a * (int32_t)NEV_TQINV_S16);
    t = (int16_t)((a - (int32_t)t * NEV_TQ) >> 16);
    return t;
}

static inline int16_t FqMulQ(int16_t a, int16_t b)
{
    return MontReduceQ((int32_t)a * b);
}

/* Centered Barrett reduction; the per-q (v, shift) pair returns the unique
 * centered representative for every int16 input (verified exhaustively). */
static inline int16_t BarrettReduceQ(int16_t a)
{
    int16_t t = (int16_t)(((int32_t)NEV_TBARRETT_V * a +
        (1 << (NEV_TBARRETT_SHIFT - 1))) >> NEV_TBARRETT_SHIFT);
    return (int16_t)(a - (int32_t)t * NEV_TQ);
}

/* Conditionally add q so that a negative representative becomes non-negative. */
static inline int16_t CaddqQ(int16_t x)
{
    return (int16_t)(x + ((x >> 15) & (int16_t)NEV_TQ));
}

/*
 * Plantard multiplication of a variable by a Plantard-domain constant
 * (eprint 2022/956, Algorithm 8 with L = 16, alpha = 3): returns a value
 * === a * z_plain (mod q) with |result| <= (q - 1) / 2, valid for
 * |a| <= 2^(L + alpha) = 2^19. (t + 8) * q <= (2^15 + 7) * 4095 stays far
 * below 2^31, so no intermediate overflows.
 */
static inline int16_t PlantardMulQ(int16_t a, int32_t zetaP)
{
    int32_t t = (int32_t)((uint32_t)a * (uint32_t)zetaP);
    t >>= 16;
    t = (t + (1 << 3)) * NEV_TQ; // 1 << 3: rounding term 2^alpha, alpha = 3
    t >>= 16;
    return (int16_t)t;
}

/* ------------------------------------------------------------------ */
/*
 * NTT zeta tables (Plantard domain) and fused inverse-NTT constants.
 *
 * NTT butterflies use Plantard modular multiplication by a constant
 * (Huang et al., https://eprint.iacr.org/2022/956.pdf, Section 4.1, L = 16,
 * alpha = 3), exactly as the openHiTLS ML-KEM C backend does. All three NEV
 * moduli satisfy the scheme's requirement q < 2^(L - alpha - 1) = 4096.
 *
 * The tables are the reference Montgomery-form tables of ntt.c converted to
 * the Plantard domain. Generation (Python, for each q):
 *
 *   TWO32 = 1 << 32
 *   def to_plantard(z_plain, q):     # z_plain = z_mont * 2^-16 mod q
 *       x = ((z_plain * (-TWO32)) % q) * pow(q, -1, TWO32) % TWO32
 *       return x - TWO32 if x >= TWO32 // 2 else x
 *   table[k]   = to_plantard(z_mont[k] * pow(2, -16, q) % q, q)
 *   F_PLANTARD = to_plantard(pow(dim, -1, q) * (1 << 16) % q, q)
 *   FZETA_PLANTARD = to_plantard(pow(dim, -1, q) * (1 << 16) *
 *                                (z_mont[1] * pow(2, -16, q)) % q, q)
 *
 * where z_mont[] are the int16 Montgomery tables of the reference ntt.c and
 * dim is the per-block NTT size. Converting the *plain* zeta (z_mont * 2^-16)
 * keeps every butterfly congruent to the reference one: the reference
 * computes MontReduce(z_mont * b) === b * z_mont * 2^-16 (mod q), and
 * PlantardMulQ(b, table[k]) === b * (z_mont * 2^-16) (mod q). For q = 3329
 * the table coincides with ML-KEM's CONST_ZETA_POWER_1 (NEV reuses the Kyber
 * roots there).
 *
 * The conversion and the exhaustively verified properties (for every table
 * entry and both fused constants of every q, over all inputs |a| <= 2^16):
 *   PlantardMulQ(a, zp) === a * z_plain (mod q), |result| <= (q - 1) / 2
 * are checked by the generator script; correctness additionally requires only
 * |a| <= 2^(L + alpha) = 2^19, far above any value reaching a butterfly here.
 *
 * NTT_YP holds the evaluation points y_i of the incomplete NTT in the
 * Plantard domain: entry i encodes y_plain_i = y_i * 2^-16 mod q (with y_i
 * the Montgomery-form table of the reference poly.c), so that
 * PlantardMulQ(x, NTT_YP[i]) is congruent to the reference fold
 * NEV_MontReduce(x * y_i), with |result| <= (q - 1) / 2 (same generator, same
 * exhaustive verification).
 */
#if NEV_TQ == 769

static const int32_t NEV_ZETAS_PLANTARD[128] = {
    5585134, 346278248, 223405321, 966228014,
    -759578091, 150798592, -318352582, 1736976371,
    2105595151, 1697880440, -1675539907, -804259155,
    1401868390, 1016494211, 240160721, 2005062756,
    525002505, -1809583100, -474736307, 631120032,
    1614103445, 1290165729, 139628326, 67021597,
    357448514, 686971363, 1413038656, 1709050706,
    -1368357591, 1061175275, 1100271206, -502661972,
    273671519, -212235054, -1938041159, 100532395,
    1435379188, -1200803600, 1580592646, -787503756,
    94947262, 1591762913, -497076839, -753992958,
    -27925665, -1731391237, -1117026604, -536172770,
    -44681064, 1524741316, -1787242567, 860110486,
    1781657435, -1206388733, -1748146636, -1010909077,
    335107982, -698141628, 519417372, 2139105949,
    1669954775, 457980909, -1921285760, 1139367138,
    39095932, -1871019563, 1563837247, -1826338499,
    -1022079343, 1055590142, 2066499220, -726067293,
    1854264165, -999738811, 1156122537, -1334846792,
    1223144133, -1474475118, 1681125041, 1150537404,
    -619949765, 217820188, 971813147, 122872927,
    -1586177779, 441225509, 977398280, 469151175,
    -1792827700, 513832239, 1301335995, -921546949,
    -988568545, -1161707669, -888036150, 776333491,
    1915700628, -1485645384, -681386229, 703726762,
    1457719720, 184309390, -1820753366, -1217558999,
    664630830, -1742561503, 815429422, -982983412,
    -195479655, 765163225, 770748358, 541757904,
    -312767449, 2083254619, 374203913, 1725806105,
    -413299843, 145213459, 647875431, 1513571050,
    -1949211425, -592024100, -659045696, 2088839752,
    -1195218467, -1089100939, -564098435, -614364632,
};
// (2^16 / 128) mod 769 in Plantard domain (fused inverse-NTT scale)
#define NEV_INTT_F_PLANTARD (-1435379187)
// ((2^16 / 128) * zeta[1]) mod 769 in Plantard domain (last GS layer, fused)
#define NEV_INTT_FZETA_PLANTARD 1200803601

static const int32_t NTT_YP[128] = {
    39095932, -39095931, -1871019563, 1871019564,
    1563837247, -1563837246, -1826338499, 1826338500,
    -1022079343, 1022079344, 1055590142, -1055590141,
    2066499220, -2066499219, -726067293, 726067294,
    1854264165, -1854264164, -999738811, 999738812,
    1156122537, -1156122536, -1334846792, 1334846793,
    1223144133, -1223144132, -1474475118, 1474475119,
    1681125041, -1681125040, 1150537404, -1150537403,
    -619949765, 619949766, 217820188, -217820187,
    971813147, -971813146, 122872927, -122872926,
    -1586177779, 1586177780, 441225509, -441225508,
    977398280, -977398279, 469151175, -469151174,
    -1792827700, 1792827701, 513832239, -513832238,
    1301335995, -1301335994, -921546949, 921546950,
    -988568545, 988568546, -1161707669, 1161707670,
    -888036150, 888036151, 776333491, -776333490,
    1915700628, -1915700627, -1485645384, 1485645385,
    -681386229, 681386230, 703726762, -703726761,
    1457719720, -1457719719, 184309390, -184309389,
    -1820753366, 1820753367, -1217558999, 1217559000,
    664630830, -664630829, -1742561503, 1742561504,
    815429422, -815429421, -982983412, 982983413,
    -195479655, 195479656, 765163225, -765163224,
    770748358, -770748357, 541757904, -541757903,
    -312767449, 312767450, 2083254619, -2083254618,
    374203913, -374203912, 1725806105, -1725806104,
    -413299843, 413299844, 145213459, -145213458,
    647875431, -647875430, 1513571050, -1513571049,
    -1949211425, 1949211426, -592024100, 592024101,
    -659045696, 659045697, 2088839752, -2088839751,
    -1195218467, 1195218468, -1089100939, 1089100940,
    -564098435, 564098436, -614364632, 614364633,
};

#elif NEV_TQ == 1409

static const int32_t NEV_ZETAS_PLANTARD[64] = {
    3048238, 1377803562, -417608601, 219473134,
    341402653, -304823796, 472476885, -1188812807,
    118881281, -2100235959, 893133725, -30482379,
    429801554, 996773816, 1246729329, 880940773,
    1344272944, 2020981773, 518200455, -1996595868,
    234714324, -1283308184, -2091091245, -280437892,
    887037249, 1508877794, -1265018756, -557827548,
    563924024, 1490588367, 51820046, 1947824062,
    64012998, -1130896285, -179846040, 313968511,
    -1420478892, -2106332435, 1332079992, 804734824,
    -1798460400, -1155282189, 1575939030, -640129973,
    435898030, -542586358, 411512126, 1319887040,
    -1835039256, -509055740, -2002692344, 1021159720,
    634033498, -1179668093, -963243197, -1594228456,
    1447913035, 1621662599, -795590109, 1170523380,
    -1042497384, 1237584615, 1088220955, -2045367676,
};
// (2^16 / 64) mod 1409 in Plantard domain (fused inverse-NTT scale)
#define NEV_INTT_F_PLANTARD (-1173571617)
// ((2^16 / 64) * zeta[1]) mod 1409 in Plantard domain (last GS layer, fused)
#define NEV_INTT_FZETA_PLANTARD 2121573626

static const int32_t NTT_YP[64] = {
    64012998, -64012997, -1130896285, 1130896286,
    -179846040, 179846041, 313968511, -313968510,
    -1420478892, 1420478893, -2106332435, 2106332436,
    1332079992, -1332079991, 804734824, -804734823,
    -1798460400, 1798460401, -1155282189, 1155282190,
    1575939030, -1575939029, -640129973, 640129974,
    435898030, -435898029, -542586358, 542586359,
    411512126, -411512125, 1319887040, -1319887039,
    -1835039256, 1835039257, -509055740, 509055741,
    -2002692344, 2002692345, 1021159720, -1021159719,
    634033498, -634033497, -1179668093, 1179668094,
    -963243197, 963243198, -1594228456, 1594228457,
    1447913035, -1447913034, 1621662599, -1621662598,
    -795590109, 795590110, 1170523380, -1170523379,
    -1042497384, 1042497385, 1237584615, -1237584614,
    1088220955, -1088220954, -2045367676, 2045367677,
};

#elif NEV_TQ == 3329

static const int32_t NEV_ZETAS_PLANTARD[128] = {
    1290168, -2064267850, -966335387, -51606696,
    -886345008, 812805467, -1847519726, 1094061961,
    1370157786, -1819136043, 249002310, 1028263423,
    -700560901, -89021551, 734105255, -2042335004,
    381889553, -1137927652, 1727534158, 1904287092,
    -365117376, 72249375, -1404992305, 1719793153,
    1839778722, -1593356746, 690239563, -576704830,
    -1207596692, -580575332, -1748176835, 1059227441,
    372858381, 427045412, -98052722, -2029433330,
    1544330386, -1322421591, -1357256111, -1643673275,
    838608815, -1744306333, -1052776603, 815385801,
    -598637676, 42575525, 1703020977, -1824296712,
    -1303069080, 1851390229, 1041165097, 583155668,
    1855260731, -594767174, 1979116802, -1195985185,
    -879894171, -918599193, 1910737929, 836028480,
    -1103093132, -282546662, 1583035408, 1174052340,
    21932846, -732815086, 752167598, -877313836,
    2112004045, 932791035, -1343064270, 1419184148,
    1817845876, -860541660, -61928035, 300609006,
    975366560, -1513366367, -405112565, -359956706,
    -2097812202, 2130066389, -696690399, -1986857805,
    -1912028096, 1228239371, 1884934581, -828287474,
    1211467195, -1317260921, -1150829326, -1214047529,
    945692709, -1279846067, 345764865, 826997308,
    2043625172, -1330162596, -1666896289, -140628247,
    483812778, -1006330577, -1598517416, 2122325384,
    1371447954, 411563403, -717333077, 976656727,
    -1586905909, 723783916, -1113414471, -948273043,
    -677337888, 1408862808, 519937465, 1323711759,
    1474661346, -1521107372, -714752743, 1143088323,
    -2073299022, 1563682897, -1877193576, 1327582262,
    -1572714068, -508325958, 1141798155, -1515946702,
};
// (2^16 / 128) mod 3329 in Plantard domain (fused inverse-NTT scale)
#define NEV_INTT_F_PLANTARD 660565713
// ((2^16 / 128) * zeta[1]) mod 3329 in Plantard domain (last GS layer, fused)
#define NEV_INTT_FZETA_PLANTARD (-343184530)

static const int32_t NTT_YP[128] = {
    21932846, -21932845, -732815086, 732815087,
    752167598, -752167597, -877313836, 877313837,
    2112004045, -2112004044, 932791035, -932791034,
    -1343064270, 1343064271, 1419184148, -1419184147,
    1817845876, -1817845875, -860541660, 860541661,
    -61928035, 61928036, 300609006, -300609005,
    975366560, -975366559, -1513366367, 1513366368,
    -405112565, 405112566, -359956706, 359956707,
    -2097812202, 2097812203, 2130066389, -2130066388,
    -696690399, 696690400, -1986857805, 1986857806,
    -1912028096, 1912028097, 1228239371, -1228239370,
    1884934581, -1884934580, -828287474, 828287475,
    1211467195, -1211467194, -1317260921, 1317260922,
    -1150829326, 1150829327, -1214047529, 1214047530,
    945692709, -945692708, -1279846067, 1279846068,
    345764865, -345764864, 826997308, -826997307,
    2043625172, -2043625171, -1330162596, 1330162597,
    -1666896289, 1666896290, -140628247, 140628248,
    483812778, -483812777, -1006330577, 1006330578,
    -1598517416, 1598517417, 2122325384, -2122325383,
    1371447954, -1371447953, 411563403, -411563402,
    -717333077, 717333078, 976656727, -976656726,
    -1586905909, 1586905910, 723783916, -723783915,
    -1113414471, 1113414472, -948273043, 948273044,
    -677337888, 677337889, 1408862808, -1408862807,
    519937465, -519937464, 1323711759, -1323711758,
    1474661346, -1474661345, -1521107372, 1521107373,
    -714752743, 714752744, 1143088323, -1143088322,
    -2073299022, 2073299023, 1563682897, -1563682896,
    -1877193576, 1877193577, 1327582262, -1327582261,
    -1572714068, 1572714069, -508325958, 508325959,
    1141798155, -1141798154, -1515946702, 1515946703,
};

#else
#error "unsupported NEV_TQ"
#endif

/* ------------------------------------------------------------------ */
/* nev_ntt part: per-block negacyclic NTT of size NEV_TDIM.           */

/*
 * Forward transform: identical Cooley-Tukey structure to the reference ntt(),
 * with the butterfly multiply switched from Montgomery to Plantard reduction.
 * Every butterfly output is congruent (mod q) to the reference one, and the
 * final exact Barrett pass (verified exhaustively: for all int16 inputs the
 * per-q (v, shift) Barrett returns the centered representative, which is
 * unique per residue class) makes the block output BIT-IDENTICAL to the
 * reference forward NTT, so nothing downstream can observe the change.
 *
 * Range: inputs satisfy |x| <= q - 1 (noise, noise + v^-1, or decompressed
 * coefficients in [0, q)); each of the <= 7 layers adds at most
 * |t| <= (q - 1) / 2, so |x| <= (q - 1) + 7 * (q - 1) / 2 < 4.5 * q <= 14981
 * throughout: no int16 overflow, all Plantard inputs far below 2^19, and the
 * Barrett pass input is inside the exhaustively verified int16 range.
 */
static void NttBlock(int16_t *block)
{
    uint32_t len, start, j, k;
    int16_t t;
    int32_t zeta;
    k = 1;
    for (len = NEV_TDIM >> 1; len > 0; len >>= 1) {
        for (start = 0; start < NEV_TDIM; start = j + len) {
            zeta = NEV_ZETAS_PLANTARD[k++];
            for (j = start; j < start + len; j++) {
                t = PlantardMulQ(block[j + len], zeta);
                block[j + len] = block[j] - t;
                block[j] = block[j] + t;
            }
        }
    }
    for (j = 0; j < NEV_TDIM; j++) {
        block[j] = BarrettReduceQ(block[j]);
    }
}

/*
 * Inverse transform: Gentleman-Sande butterflies reusing the forward table
 * backwards (zetas[--k], the reversed difference leg absorbing the negation,
 * exactly as the reference invntt), restructured with ML-KEM-style lazy
 * reduction: the per-butterfly Barrett of the reference is replaced by ONE
 * full Barrett pass after the first three layers, and the final Montgomery
 * scale-by-f loop is fused into the last layer as two Plantard multiplies
 * (fP === 2^16 / dim, fzetaP === (2^16 / dim) * zeta[1] (mod q)).
 *
 * Byte-exactness: every coefficient stays congruent (mod q) to the reference
 * invntt output, whose scale FqMul(x, mont^2 / dim) === x * 2^16 / dim (mod q)
 * is exactly what fP / fzetaP reproduce. Both call sites (nev_kem.c) feed the
 * result into unique canonicalizers - NEV_PolyGetMontgomery (MontReduce, whose
 * output for |x| <= q - 1 is the unique centered representative of
 * x * 2^-16 mod q) or NEV_PolyToMsg (FlipAbs/Caddq, unique for |x| <= q - 1) -
 * so congruence plus |output| <= (q - 1) / 2 < q - 1 preserves the packed
 * bytes and the recovered message bit-for-bit.
 *
 * Range argument (inputs come straight from NEV_PolyReduce, so
 * |x| <= (q - 1) / 2 =: M; each lazy GS layer at most doubles the worst
 * magnitude - sum legs add two values, difference legs return to
 * |t| <= (q - 1) / 2 <= M via Plantard):
 *   layers len = 1, 2, 4:  |x| <= 8 * M = 4 * (q - 1) <= 13312  (int16 ok,
 *                          Barrett pass input inside verified int16 range)
 *   Barrett pass:          |x| <= M
 *   layers len = 8 .. dim/4: at most 3 further layers, |x| <= 8 * M
 *   fused last layer:      |sum|, |diff| <= 16 * M = 8 * (q - 1) <= 26624
 *                          (int16 ok, far below the 2^19 Plantard limit)
 *   output:                |x| <= (q - 1) / 2.
 */
static void InvNttBlock(int16_t *block)
{
    uint32_t start, len, j, k;
    int16_t t;
    int32_t zeta;

    k = NEV_TDIM;
    for (len = 1; len <= (NEV_TDIM >> 2); len <<= 1) {
        for (start = 0; start < NEV_TDIM; start = j + len) {
            zeta = NEV_ZETAS_PLANTARD[--k];
            for (j = start; j < start + len; j++) {
                t = block[j];
                block[j] = (int16_t)(t + block[j + len]);
                block[j + len] = (int16_t)(block[j + len] - t);
                block[j + len] = PlantardMulQ(block[j + len], zeta);
            }
        }
        if (len == 4) { // one exact Barrett pass after the first three layers
            for (j = 0; j < NEV_TDIM; j++) {
                block[j] = BarrettReduceQ(block[j]);
            }
        }
    }
    // Last layer (len = dim / 2, zeta index 1) fused with the scale by
    // mont^2 / dim of the reference: lower leg * fP, upper leg * fzetaP.
    len = NEV_TDIM >> 1;
    for (j = 0; j < len; j++) {
        t = block[j];
        block[j] = PlantardMulQ((int16_t)(t + block[j + len]), NEV_INTT_F_PLANTARD);
        block[j + len] = PlantardMulQ((int16_t)(block[j + len] - t), NEV_INTT_FZETA_PLANTARD);
    }
}

// Reference poly_ntt: apply the per-block transform to each of the n / nttDim
// contiguous blocks of nttDim coefficients.
void NEV_TFN(NEV_PolyNtt)(NEV_Poly *r, uint32_t n)
{
    for (uint32_t i = 0; i < n; i += NEV_TDIM) {
        NttBlock(&r->coeffs[i]);
    }
}

// Reference poly_invntt: inverse transform on every block.
void NEV_TFN(NEV_PolyInvNtt)(NEV_Poly *r, uint32_t n)
{
    for (uint32_t i = 0; i < n; i += NEV_TDIM) {
        InvNttBlock(&r->coeffs[i]);
    }
}

/* ------------------------------------------------------------------ */
/* nev_poly part: arithmetic in the incomplete-NTT (CRT) representation.
 *
 * This is the accumulate-then-reduce version of the reference poly.c, the
 * scalar mirror of the proven ARMv8 v2 backend (asm_nev_poly.c +
 * asm/nev_poly_armv8.S, same per-output formulas). See the git history of
 * nev_poly.c for the full derivation; the complete range-verifier script
 * (RANGE-VERIFY-C3) that proves every int16 store wrap-free and every int32
 * accumulator inside the exact-Montgomery-reduction domain is kept in
 * nev_poly.c. Summary of the discipline:
 *
 *  - Karatsuba slot products combine raw 32-bit products linearly first and
 *    reduce every output ONCE with the exact MontReduceQ (== P * 2^-16 mod q for
 *    any |P| <= 2^31 - 2^15*q - 1); results are CONGRUENT to the reference
 *    rows and every int16 store is provably wrap-free.
 *  - Multiplications by the per-slot constants y_i use PlantardMulQ:
 *    PM(x, yp_i) === x * y_i * 2^-16 (mod q), |result| <= (q - 1) / 2.
 *  - Exactness islands: every value feeding an invertibility '== 0' decision
 *    is canonicalized first (exact Barrett + Caddq of a wrap-free int16), so
 *    it is BIT-IDENTICAL to the reference value.
 *  - Operand discipline: the PolyMontMul path (operands up to the unpack
 *    anchor W = 1023/2047/4095) Barrett-normalizes ONE side of every
 *    Karatsuba operand sum (redA = 1); the inverse tower keeps both sides
 *    raw (redA = 0, operands <= (q - 1) / 2).
 */

/*
 * Fermat inversion a^(q-2) in the Montgomery domain, one fixed addition chain
 * per q. Kept verbatim from the reference (bit-exact island feeding
 * BatchMont2Inv).
 */
#if NEV_TQ == 769
/* Addition chain: 1, 2, 4, 8, 16, 32, 64, 72, 73, 137, 274, 347, 694, 767. */
static int16_t Mont2Inv(int16_t a)
{
    int16_t y0;
    int16_t y1;

    y0 = FqMulQ(a, a);     // 2
    y0 = FqMulQ(y0, y0);   // 4
    y0 = FqMulQ(y0, y0);   // 8

    y1 = FqMulQ(y0, y0);   // 16
    y1 = FqMulQ(y1, y1);   // 32
    y1 = FqMulQ(y1, y1);   // 64

    y0 = FqMulQ(y1, y0);   // 72
    y0 = FqMulQ(y0, a);    // 73

    y1 = FqMulQ(y0, y1);   // 137
    y1 = FqMulQ(y1, y1);   // 274
    y1 = FqMulQ(y1, y0);   // 347
    y1 = FqMulQ(y1, y1);   // 694
    y1 = FqMulQ(y1, y0);   // 767 = q - 2

    return y1;
}
#elif NEV_TQ == 1409
/* Addition chain: 1, 2, 4, 8, 16, 32, 64, 128, 192, 200, 201, 402, 804, 1206, 1407. */
static int16_t Mont2Inv(int16_t a)
{
    int16_t y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13;

    y0 = FqMulQ(a, a);       // 2
    y1 = FqMulQ(y0, y0);     // 4
    y2 = FqMulQ(y1, y1);     // 8
    y3 = FqMulQ(y2, y2);     // 16
    y4 = FqMulQ(y3, y3);     // 32
    y5 = FqMulQ(y4, y4);     // 64
    y6 = FqMulQ(y5, y5);     // 128

    y7 = FqMulQ(y5, y6);     // 192
    y8 = FqMulQ(y7, y2);     // 200
    y9 = FqMulQ(y8, a);      // 201

    y10 = FqMulQ(y9, y9);    // 402
    y11 = FqMulQ(y10, y10);  // 804
    y12 = FqMulQ(y10, y11);  // 1206
    y13 = FqMulQ(y12, y9);   // 1407 = q - 2

    return y13;
}
#else
/* Addition chain: 1, 2, 4, 8, 16, 32, 64, 128, 144, 145, 273, 418, 836, 1109, 2218, 3327. */
static int16_t Mont2Inv(int16_t a)
{
    int16_t y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14;

    y0 = FqMulQ(a, a);       // 2
    y1 = FqMulQ(y0, y0);     // 4
    y2 = FqMulQ(y1, y1);     // 8
    y3 = FqMulQ(y2, y2);     // 16
    y4 = FqMulQ(y3, y3);     // 32
    y5 = FqMulQ(y4, y4);     // 64
    y6 = FqMulQ(y5, y5);     // 128

    y7 = FqMulQ(y3, y6);     // 144
    y8 = FqMulQ(y7, a);      // 145
    y9 = FqMulQ(y8, y6);     // 273
    y10 = FqMulQ(y9, y8);    // 418
    y11 = FqMulQ(y10, y10);  // 836
    y12 = FqMulQ(y11, y9);   // 1109
    y13 = FqMulQ(y12, y12);  // 2218
    y14 = FqMulQ(y13, y12);  // 3327 = q - 2

    return y14;
}
#endif

/* Montgomery batch inversion of nttDim field elements; returns 0 if any element is 0 mod q.
 * Kept verbatim from the reference: its inputs (the s array) are bit-identical to the
 * reference, so its '== 0' decision and its outputs are too. */
static int32_t BatchMont2Inv(int16_t *r, const int16_t *a)
{
    int32_t i;
    int16_t acc;
    int16_t tmp;
    const int32_t dim = NEV_TDIM;

    r[0] = a[0];
    for (i = 1; i < dim; i++) {
        r[i] = FqMulQ(r[i - 1], a[i]);
    }

    if (r[dim - 1] == 0) {
        return 0;
    }

    acc = Mont2Inv(r[dim - 1]);

    for (i = dim - 1; i > 0; i--) {
        tmp = FqMulQ(acc, r[i - 1]);
        acc = FqMulQ(acc, a[i]);
        r[i] = tmp;
    }

    r[0] = acc;
    return 1;
}

/*
 * Slot-wise Karatsuba product of two degree-3 slot elements (4 + 4 blocks in,
 * 7 blocks out), one exact Montgomery reduction per output row (congruent to
 * the reference MontMul4 by linearity of MontReduce mod q):
 *     R0 = MR(P0)                         R6 = MR(P3)
 *     R1 = MR(P01 - P0 - P1)              R5 = MR(P23 - P2 - P3)
 *     R2 = MR(PA0 - P0 - P2 + P1)         R4 = MR(PA1 - P1 - P3 + P2)
 *     R3 = Barrett(MR(PA01 - PA0 - PA1 - (P01-P0-P1) - (P23-P2-P3)))
 * with P_i = a_i*b_i, P01 = (a0+a1)(b0+b1), P23 = (a2+a3)(b2+b3),
 * PA0 = (a0+a2)(b0+b2), PA1 = (a1+a3)(b1+b3), PA01 = (Sa)(Sb).
 * dbl = 1 computes a * (2b) (same raw products doubled). The worst
 * accumulator is 36*|a|*|b| (72 with dbl), inside the exact-MR domain for
 * every call-site anchor of the range script (largest: raw sums of q-1
 * operands in MontMul8K, 36*(2(q-1))^2). In-place r == a or r == b is safe
 * (each slot's loads precede its stores).
 */
static void MontMul4K(int16_t *r, const int16_t *a, const int16_t *b, int32_t dbl)
{
    const int32_t dim = NEV_TDIM;

    for (int32_t i = 0; i < dim; i++) {
        const int32_t a0 = a[i];
        const int32_t a1 = a[dim + i];
        const int32_t a2 = a[2 * dim + i];
        const int32_t a3 = a[3 * dim + i];
        const int32_t b0 = (int32_t)b[i] << dbl;
        const int32_t b1 = (int32_t)b[dim + i] << dbl;
        const int32_t b2 = (int32_t)b[2 * dim + i] << dbl;
        const int32_t b3 = (int32_t)b[3 * dim + i] << dbl;

        const int32_t p0 = a0 * b0;
        const int32_t p1 = a1 * b1;
        const int32_t p2 = a2 * b2;
        const int32_t p3 = a3 * b3;
        const int32_t d01 = (a0 + a1) * (b0 + b1) - p0 - p1;
        const int32_t d23 = (a2 + a3) * (b2 + b3) - p2 - p3;
        const int32_t pa0 = (a0 + a2) * (b0 + b2);
        const int32_t pa1 = (a1 + a3) * (b1 + b3);
        const int32_t pa01 = (a0 + a1 + a2 + a3) * (b0 + b1 + b2 + b3);

        r[i] = MontReduceQ(p0);
        r[dim + i] = MontReduceQ(d01);
        r[2 * dim + i] = MontReduceQ(pa0 - p0 - p2 + p1);
        r[3 * dim + i] = BarrettReduceQ(MontReduceQ(pa01 - pa0 - pa1 - d01 - d23));
        r[4 * dim + i] = MontReduceQ(pa1 - p1 - p3 + p2);
        r[5 * dim + i] = MontReduceQ(d23);
        r[6 * dim + i] = MontReduceQ(p3);
    }
}

/*
 * Slot-wise square of a degree-3 slot element (4 blocks in, 7 blocks out),
 * one exact Montgomery reduction per output (congruent to the reference
 * MontSquare4):
 *     o0 = MR(a0^2)              o1 = MR(2 a0 a1)
 *     o2 = MR(a1^2 + 2 a0 a2)    o3 = MR(2 (a0+a1)(a2+a3) - 2 a1 a3 - 2 a0 a2)
 *     o4 = MR(2 a1 a3 + a2^2)    o5 = MR(2 a2 a3)          o6 = MR(a3^2)
 * Worst accumulator 12*(q-1)^2 at the q-1 tower anchor (range script).
 */
static void MontSquare4(int16_t *r, const int16_t *a)
{
    const int32_t dim = NEV_TDIM;

    for (int32_t i = 0; i < dim; i++) {
        const int32_t a0 = a[i];
        const int32_t a1 = a[dim + i];
        const int32_t a2 = a[2 * dim + i];
        const int32_t a3 = a[3 * dim + i];
        const int32_t x02 = 2 * a0 * a2;
        const int32_t x13 = 2 * a1 * a3;

        r[i] = MontReduceQ(a0 * a0);
        r[dim + i] = MontReduceQ(2 * a0 * a1);
        r[2 * dim + i] = MontReduceQ(a1 * a1 + x02);
        r[3 * dim + i] = MontReduceQ(2 * (a0 + a1) * (a2 + a3) - x13 - x02);
        r[4 * dim + i] = MontReduceQ(x13 + a2 * a2);
        r[5 * dim + i] = MontReduceQ(2 * a2 * a3);
        r[6 * dim + i] = MontReduceQ(a3 * a3);
    }
}

/*
 * Karatsuba product of two degree-7 slot elements (8 + 8 blocks in, 15 blocks
 * out; dbl = 1 computes a * (2b)). Operand contract per the range script:
 * redA = 0 (inverse tower): |a|, |b| <= q - 1 with both sums RAW; redA = 1
 * (PolyMontMul path, operands up to W): the a-side sum is Barrett-normalized,
 * the b-side sum stays raw. The recombination runs as fused per-row passes
 * (scalar NEV_MontMul8TailAsm; all pre-Barrett values wrap-free) instead of
 * 11 elementwise sweeps. Rows 3, 4..10 and 11 come out Barrett-normalized.
 */
static void MontMul8K(int16_t *r, const int16_t *a, const int16_t *b, int32_t dbl, int32_t redA)
{
    int16_t t1[7 * NEV_TDIM];
    int16_t t2[4 * NEV_TDIM];
    const int32_t dim = NEV_TDIM;

    if (redA != 0) {
        for (int32_t i = 0; i < 4 * dim; i++) {
            t1[i] = BarrettReduceQ((int16_t)(a[i] + a[4 * dim + i]));
            t2[i] = (int16_t)(b[i] + b[4 * dim + i]);
        }
    } else {
        for (int32_t i = 0; i < 4 * dim; i++) {
            t1[i] = (int16_t)(a[i] + a[4 * dim + i]);
            t2[i] = (int16_t)(b[i] + b[4 * dim + i]);
        }
    }
    MontMul4K(t1, t1, t2, dbl);                           // middle
    MontMul4K(&r[8 * dim], &a[4 * dim], &b[4 * dim], dbl);// high
    MontMul4K(r, a, b, dbl);                              // low

    for (int32_t j = 0; j < dim; j++) {                   // row 7
        r[7 * dim + j] = BarrettReduceQ(
            (int16_t)(t1[3 * dim + j] - r[3 * dim + j] - r[11 * dim + j]));
    }
    for (int32_t i = 0; i < 3; i++) {                     // rows 4+i, 8+i
        const int16_t *ri = &r[i * dim];
        const int16_t *r12 = &r[(12 + i) * dim];
        const int16_t *m0 = &t1[i * dim];
        const int16_t *m4 = &t1[(4 + i) * dim];
        int16_t *r4 = &r[(4 + i) * dim];
        int16_t *r8 = &r[(8 + i) * dim];
        for (int32_t j = 0; j < dim; j++) {
            const int16_t a4 = r4[j];
            const int16_t a8 = r8[j];
            r4[j] = BarrettReduceQ((int16_t)(a4 + m0[j] - ri[j] - a8));
            r8[j] = BarrettReduceQ((int16_t)(m4[j] - a4 - r12[j] + a8));
        }
    }
}

/* Square of a degree-7 slot element (8 blocks in, 15 blocks out); the middle
 * term 2 * a_lo * a_hi comes from the dbl variant of MontMul4K (its row 3 is
 * already the centered Barrett representative, so row 7 is a plain copy). */
static void MontSquare8(int16_t *r, const int16_t *a)
{
    int16_t t1[7 * NEV_TDIM];
    const int32_t dim = NEV_TDIM;

    MontMul4K(t1, a, &a[4 * dim], 1);                     // 2 * a_lo * a_hi
    MontSquare4(&r[8 * dim], &a[4 * dim]);
    MontSquare4(r, a);

    for (int32_t j = 0; j < dim; j++) {
        r[7 * dim + j] = t1[3 * dim + j];
    }
    for (int32_t i = 0; i < 3; i++) {
        const int16_t *m0 = &t1[i * dim];
        const int16_t *m4 = &t1[(4 + i) * dim];
        int16_t *r4 = &r[(4 + i) * dim];
        int16_t *r8 = &r[(8 + i) * dim];
        for (int32_t j = 0; j < dim; j++) {
            r4[j] = BarrettReduceQ((int16_t)(r4[j] + m0[j]));
            r8[j] = BarrettReduceQ((int16_t)(r8[j] + m4[j]));
        }
    }
}

#if NEV_TQ == 1409
/*
 * Karatsuba product of two degree-15 slot elements (16 + 16 blocks in, 31
 * blocks out); only reached for q = 1409 (t = 32). Same redA operand
 * contract as MontMul8K (forwarded to every level); the fused recombination
 * rows stay wrap-free without Barrett normalization (range script mm16).
 */
static void MontMul16K(int16_t *r, const int16_t *a, const int16_t *b, int32_t redA)
{
    int16_t t1[15 * NEV_TDIM];
    int16_t t2[8 * NEV_TDIM];
    const int32_t dim = NEV_TDIM;

    if (redA != 0) {
        for (int32_t i = 0; i < 8 * dim; i++) {
            t1[i] = BarrettReduceQ((int16_t)(a[i] + a[8 * dim + i]));
            t2[i] = (int16_t)(b[i] + b[8 * dim + i]);
        }
    } else {
        for (int32_t i = 0; i < 8 * dim; i++) {
            t1[i] = (int16_t)(a[i] + a[8 * dim + i]);
            t2[i] = (int16_t)(b[i] + b[8 * dim + i]);
        }
    }
    MontMul8K(t1, t1, t2, 0, redA);                             // middle
    MontMul8K(&r[16 * dim], &a[8 * dim], &b[8 * dim], 0, redA); // high
    MontMul8K(r, a, b, 0, redA);                                // low

    for (int32_t j = 0; j < dim; j++) {                   // row 15
        r[15 * dim + j] = (int16_t)(t1[7 * dim + j] - r[7 * dim + j] - r[23 * dim + j]);
    }
    for (int32_t i = 0; i < 7; i++) {                     // rows 8+i, 16+i
        const int16_t *ri = &r[i * dim];
        const int16_t *r24 = &r[(24 + i) * dim];
        const int16_t *m0 = &t1[i * dim];
        const int16_t *m8 = &t1[(8 + i) * dim];
        int16_t *r8 = &r[(8 + i) * dim];
        int16_t *r16 = &r[(16 + i) * dim];
        for (int32_t j = 0; j < dim; j++) {
            const int16_t a8 = r8[j];
            const int16_t a16 = r16[j];
            r8[j] = (int16_t)(a8 + m0[j] - ri[j] - a16);
            r16[j] = (int16_t)(m8[j] - a8 - r24[j] + a16);
        }
    }
}

/* Square of a degree-15 slot element (16 blocks in, 31 blocks out); q = 1409
 * only. Plain copies and wrap-free int16 adds of the three sub-squares. */
static void MontSquare16(int16_t *r, const int16_t *a)
{
    int16_t t0[15 * NEV_TDIM];
    int16_t t1[15 * NEV_TDIM];
    int16_t t2[15 * NEV_TDIM];
    const int32_t dim = NEV_TDIM;

    MontSquare8(t0, a);
    MontMul8K(t1, a, &a[8 * dim], 1, 0);                  // 2 * a_lo * a_hi
    MontSquare8(t2, &a[8 * dim]);

    for (int32_t i = 0; i < 8 * dim; i++) {
        r[i] = t0[i];
        r[23 * dim + i] = t2[7 * dim + i];
    }
    for (int32_t i = 0; i < 7 * dim; i++) {
        r[8 * dim + i] = (int16_t)(t0[8 * dim + i] + t1[i]);
        r[16 * dim + i] = (int16_t)(t1[8 * dim + i] + t2[i]);
    }
    for (int32_t i = 0; i < dim; i++) {
        r[15 * dim + i] = t1[7 * dim + i];
    }
}
#endif // NEV_TQ == 1409

/*
 * Norm-map pass shared by Mont2Inverse4 and Mont2Inverse4Judge (per-output
 * combined reductions, congruent to the reference):
 *     a2_0 = PM(MR(t2^2 - 2 t1 t3), yp) + MR(t0^2)
 *     a2_1 = MR(2 t0 t2 - t1^2) - PM(MR(t3^2), yp)
 *     s    = Caddq(Barrett(MR(a2_0^2) - PM(MR(a2_1^2), yp)))
 * s is BIT-IDENTICAL to the reference s: the pre-Barrett value is a wrap-free
 * int16 (|.| <= 3515, range script) congruent to the reference one, and the
 * exact Barrett + Caddq return the unique standard representative in
 * [0, q - 1] of that class, which only depends on the inputs mod q. Every
 * '== 0' invertibility decision downstream is therefore unchanged.
 */
static void Inv4Norm(int16_t *a20, int16_t *a21, int16_t *s, const int16_t *a)
{
    const int32_t dim = NEV_TDIM;

    for (int32_t i = 0; i < dim; i++) {
        const int32_t yp = NTT_YP[i];
        const int32_t t0 = a[i];
        const int32_t t1 = a[dim + i];
        const int32_t t2 = a[2 * dim + i];
        const int32_t t3 = a[3 * dim + i];

        const int16_t x1 = MontReduceQ(t2 * t2 - 2 * t1 * t3);
        const int16_t v20 = (int16_t)(PlantardMulQ(x1, yp) + MontReduceQ(t0 * t0));
        const int16_t y1 = MontReduceQ(2 * t0 * t2 - t1 * t1);
        const int16_t v21 = (int16_t)(y1 - PlantardMulQ(MontReduceQ(t3 * t3), yp));

        const int16_t t6 = MontReduceQ((int32_t)v20 * v20);
        const int16_t t7 = PlantardMulQ(MontReduceQ((int32_t)v21 * v21), yp);

        a20[i] = v20;
        a21[i] = v21;
        s[i] = CaddqQ(BarrettReduceQ((int16_t)(t6 - t7)));
    }
}

/* Inversion of a degree-3 slot element via the norm map to F_q and batch
 * inversion. The back-substitution uses one exact reduction per product and
 * Barrett-normalized outputs (|r| <= (q-1)/2), congruent to the reference. */
static int32_t Mont2Inverse4(int16_t *r, const int16_t *a)
{
    int16_t a20[NEV_TDIM];
    int16_t a21[NEV_TDIM];
    int16_t sArr[NEV_TDIM];
    int16_t sInv[NEV_TDIM];
    const int32_t dim = NEV_TDIM;

    Inv4Norm(a20, a21, sArr, a);

    if (BatchMont2Inv(sInv, sArr) == 0) {
        return 0;
    }

    for (int32_t i = 0; i < dim; i++) {
        const int32_t yp = NTT_YP[i];
        const int32_t t0 = a[i];
        const int32_t t1 = a[dim + i];
        const int32_t t2 = a[2 * dim + i];
        const int32_t t3 = a[3 * dim + i];
        const int32_t s = sInv[i];

        const int32_t t4 = MontReduceQ((int32_t)a20[i] * s);   // a2'_0
        const int32_t t5 = MontReduceQ((int32_t)a21[i] * s);   // a2'_1
        const int32_t t6 = MontReduceQ(t0 * t4);
        const int32_t t7 = MontReduceQ(t1 * t4);
        const int32_t u0 = MontReduceQ((t0 + t2) * (t4 - t5));
        const int32_t u1 = MontReduceQ((t1 - t3) * (t4 + t5));
        const int32_t t2p = MontReduceQ(t2 * t5);
        const int32_t t3p = MontReduceQ(t3 * t5);
        const int32_t t4pp = PlantardMulQ((int16_t)t2p, yp);
        const int32_t t5pp = PlantardMulQ((int16_t)t3p, yp);

        r[i] = BarrettReduceQ((int16_t)(t6 - t4pp));
        r[dim + i] = BarrettReduceQ((int16_t)(t5pp - t7));
        r[2 * dim + i] = BarrettReduceQ((int16_t)(u0 - t6 + t2p));
        r[3 * dim + i] = BarrettReduceQ((int16_t)(u1 - t7 + t3p));
    }

    return 1;
}

/* Invertibility test for a degree-3 slot element (norm map only). */
static int32_t Mont2Inverse4Judge(const int16_t *a)
{
    int16_t a20[NEV_TDIM];
    int16_t a21[NEV_TDIM];
    int16_t sArr[NEV_TDIM];
    const int32_t dim = NEV_TDIM;

    Inv4Norm(a20, a21, sArr, a);

    for (int32_t i = 0; i < dim; i++) {
        if (sArr[i] == 0) {                     // no inverse
            return 0;
        }
    }
    return 1;
}

/*
 * Split a into even/odd halves and reduce the degree-7 inversion to a
 * degree-3 one. The recombination rows merge the reference's MR(x*y) fold
 * pairs into single Plantard folds of the combined int16 value (congruent);
 * the Barrett normalization fuses into the same pass, so b0 feeds the next
 * level with |b0| <= (q-1)/2.
 */
static void Mont2Inverse8Norm(int16_t *t0, int16_t *t1, int16_t *b0, int16_t *b1, const int16_t *a)
{
    const int32_t dim = NEV_TDIM;

    for (int32_t j = 0; j < 4; j++) {
        for (int32_t i = 0; i < dim; i++) {
            t0[j * dim + i] = a[2 * j * dim + i];
            t1[j * dim + i] = a[(2 * j + 1) * dim + i];
        }
    }

    MontSquare4(b0, t0);
    MontSquare4(b1, t1);

    for (int32_t j = 0; j < dim; j++) {
        const int32_t yp = NTT_YP[j];
        b0[j] = BarrettReduceQ((int16_t)(b0[j] +
            PlantardMulQ((int16_t)(b0[4 * dim + j] - b1[3 * dim + j]), yp)));
        b0[dim + j] = BarrettReduceQ((int16_t)(b0[dim + j] - b1[j] +
            PlantardMulQ((int16_t)(b0[5 * dim + j] - b1[4 * dim + j]), yp)));
        b0[2 * dim + j] = BarrettReduceQ((int16_t)(b0[2 * dim + j] - b1[dim + j] +
            PlantardMulQ((int16_t)(b0[6 * dim + j] - b1[5 * dim + j]), yp)));
        b0[3 * dim + j] = BarrettReduceQ((int16_t)(b0[3 * dim + j] - b1[2 * dim + j] -
            PlantardMulQ(b1[6 * dim + j], yp)));
    }
}

/* Inversion of a degree-7 slot element via the tower F_q[x]/(x^8-y) over
 * F_q[x]/(x^4-y'). Outputs are Barrett-normalized (rows 6/7 already carry
 * centered MontMul4K row-3 values, so plain copy/negate suffices). */
static int32_t Mont2Inverse8(int16_t *r, const int16_t *a)
{
    int16_t t0[4 * NEV_TDIM];
    int16_t t1[4 * NEV_TDIM];
    int16_t b0[7 * NEV_TDIM];
    int16_t b1[7 * NEV_TDIM];
    const int32_t dim = NEV_TDIM;

    Mont2Inverse8Norm(t0, t1, b0, b1, a);

    if (Mont2Inverse4(b1, b0) == 0) {
        return 0;
    }

    MontMul4K(b0, b1, t0, 0);
    MontMul4K(b1, b1, t1, 0);

    for (int32_t i = 0; i < 3; i++) {
        // r_{2i} = b0_i + PM(b0_{4+i}); r_{2i+1} = -b1_i - PM(b1_{4+i})
        const int16_t *p0 = &b0[i * dim];
        const int16_t *p4 = &b0[(4 + i) * dim];
        const int16_t *n0 = &b1[i * dim];
        const int16_t *n4 = &b1[(4 + i) * dim];
        int16_t *re = &r[2 * i * dim];
        int16_t *ro = &r[(2 * i + 1) * dim];
        for (int32_t j = 0; j < dim; j++) {
            const int32_t yp = NTT_YP[j];
            re[j] = BarrettReduceQ((int16_t)(p0[j] + PlantardMulQ(p4[j], yp)));
            ro[j] = BarrettReduceQ((int16_t)(-n0[j] - PlantardMulQ(n4[j], yp)));
        }
    }
    for (int32_t j = 0; j < dim; j++) {
        r[6 * dim + j] = b0[3 * dim + j];
        r[7 * dim + j] = (int16_t)(-b1[3 * dim + j]);
    }

    return 1;
}

static int32_t Mont2Inverse8Judge(const int16_t *a)
{
    int16_t t0[4 * NEV_TDIM];
    int16_t t1[4 * NEV_TDIM];
    int16_t b0[7 * NEV_TDIM];
    int16_t b1[7 * NEV_TDIM];

    Mont2Inverse8Norm(t0, t1, b0, b1, a);

    return Mont2Inverse4Judge(b0);
}

/* Split a into even/odd halves and reduce the degree-15 inversion to a
 * degree-7 one; same fused fold + Barrett rows as Mont2Inverse8Norm. */
static void Mont2Inverse16Norm(int16_t *t0, int16_t *t1, int16_t *b0, int16_t *b1, const int16_t *a)
{
    const int32_t dim = NEV_TDIM;

    for (int32_t j = 0; j < 8; j++) {
        for (int32_t i = 0; i < dim; i++) {
            t0[j * dim + i] = a[2 * j * dim + i];
            t1[j * dim + i] = a[(2 * j + 1) * dim + i];
        }
    }

    MontSquare8(b0, t0);
    MontSquare8(b1, t1);

    for (int32_t j = 0; j < dim; j++) {
        b0[j] = BarrettReduceQ((int16_t)(b0[j] +
            PlantardMulQ((int16_t)(b0[8 * dim + j] - b1[7 * dim + j]), NTT_YP[j])));
    }
    for (int32_t i = 0; i < 6; i++) {
        const int16_t *ba = &b0[(9 + i) * dim];
        const int16_t *bb = &b1[(8 + i) * dim];
        const int16_t *b1i = &b1[i * dim];
        int16_t *row = &b0[(1 + i) * dim];
        for (int32_t j = 0; j < dim; j++) {
            row[j] = BarrettReduceQ((int16_t)(row[j] - b1i[j] +
                PlantardMulQ((int16_t)(ba[j] - bb[j]), NTT_YP[j])));
        }
    }
    for (int32_t j = 0; j < dim; j++) {
        b0[7 * dim + j] = BarrettReduceQ((int16_t)(b0[7 * dim + j] - b1[6 * dim + j] -
            PlantardMulQ(b1[14 * dim + j], NTT_YP[j])));
    }
}

/* Inversion of a degree-15 slot element (rows 14/15 carry centered MontMul8K
 * row-7 values, so plain copy/negate suffices). */
static int32_t Mont2Inverse16(int16_t *r, const int16_t *a)
{
    int16_t t0[8 * NEV_TDIM];
    int16_t t1[8 * NEV_TDIM];
    int16_t b0[15 * NEV_TDIM];
    int16_t b1[15 * NEV_TDIM];
    const int32_t dim = NEV_TDIM;

    Mont2Inverse16Norm(t0, t1, b0, b1, a);

    if (Mont2Inverse8(b1, b0) == 0) {
        return 0;
    }

    MontMul8K(b0, b1, t0, 0, 0);
    MontMul8K(b1, b1, t1, 0, 0);

    for (int32_t i = 0; i < 7; i++) {
        const int16_t *p0 = &b0[i * dim];
        const int16_t *p8 = &b0[(8 + i) * dim];
        const int16_t *n0 = &b1[i * dim];
        const int16_t *n8 = &b1[(8 + i) * dim];
        int16_t *re = &r[2 * i * dim];
        int16_t *ro = &r[(2 * i + 1) * dim];
        for (int32_t j = 0; j < dim; j++) {
            const int32_t yp = NTT_YP[j];
            re[j] = BarrettReduceQ((int16_t)(p0[j] + PlantardMulQ(p8[j], yp)));
            ro[j] = BarrettReduceQ((int16_t)(-n0[j] - PlantardMulQ(n8[j], yp)));
        }
    }
    for (int32_t j = 0; j < dim; j++) {
        r[14 * dim + j] = b0[7 * dim + j];
        r[15 * dim + j] = (int16_t)(-b1[7 * dim + j]);
    }
    return 1;
}

static int32_t Mont2Inverse16Judge(const int16_t *a)
{
    int16_t t0[8 * NEV_TDIM];
    int16_t t1[8 * NEV_TDIM];
    int16_t b0[15 * NEV_TDIM];
    int16_t b1[15 * NEV_TDIM];

    Mont2Inverse16Norm(t0, t1, b0, b1, a);

    return Mont2Inverse8Judge(b0);
}

#if NEV_TQ == 1409
/* Split a into even/odd halves and reduce the degree-31 inversion to a degree-15 one.
 * t = 32 occurs only for NEV-2048-1409 (nttDim 64), so 16 * dim = NEV_N_MAX / 2. */
static void Mont2Inverse32Norm(int16_t *t0, int16_t *t1, int16_t *b0, int16_t *b1, const int16_t *a)
{
    const int32_t dim = NEV_TDIM;

    for (int32_t j = 0; j < 16; j++) {
        for (int32_t i = 0; i < dim; i++) {
            t0[j * dim + i] = a[2 * j * dim + i];
            t1[j * dim + i] = a[(2 * j + 1) * dim + i];
        }
    }

    MontSquare16(b0, t0);
    MontSquare16(b1, t1);

    for (int32_t j = 0; j < dim; j++) {
        b0[j] = BarrettReduceQ((int16_t)(b0[j] +
            PlantardMulQ((int16_t)(b0[16 * dim + j] - b1[15 * dim + j]), NTT_YP[j])));
    }
    for (int32_t i = 0; i < 14; i++) {
        const int16_t *ba = &b0[(17 + i) * dim];
        const int16_t *bb = &b1[(16 + i) * dim];
        const int16_t *b1i = &b1[i * dim];
        int16_t *row = &b0[(1 + i) * dim];
        for (int32_t j = 0; j < dim; j++) {
            row[j] = BarrettReduceQ((int16_t)(row[j] - b1i[j] +
                PlantardMulQ((int16_t)(ba[j] - bb[j]), NTT_YP[j])));
        }
    }
    for (int32_t j = 0; j < dim; j++) {
        b0[15 * dim + j] = BarrettReduceQ((int16_t)(b0[15 * dim + j] - b1[14 * dim + j] -
            PlantardMulQ(b1[30 * dim + j], NTT_YP[j])));
    }
}

/* Inversion of a degree-31 slot element (rows 30/31 are MontMul16K tail rows,
 * not yet centered, so they go through the Barrett like rows 0..29). */
static int32_t Mont2Inverse32(int16_t *r, const int16_t *a)
{
    int16_t t0[16 * NEV_TDIM];
    int16_t t1[16 * NEV_TDIM];
    int16_t b0[32 * NEV_TDIM];
    int16_t b1[32 * NEV_TDIM];
    const int32_t dim = NEV_TDIM;

    Mont2Inverse32Norm(t0, t1, b0, b1, a);

    if (Mont2Inverse16(b1, b0) == 0) {
        return 0;
    }

    MontMul16K(b0, b1, t0, 0);
    MontMul16K(b1, b1, t1, 0);

    for (int32_t i = 0; i < 15; i++) {
        const int16_t *p0 = &b0[i * dim];
        const int16_t *p16 = &b0[(16 + i) * dim];
        const int16_t *n0 = &b1[i * dim];
        const int16_t *n16 = &b1[(16 + i) * dim];
        int16_t *re = &r[2 * i * dim];
        int16_t *ro = &r[(2 * i + 1) * dim];
        for (int32_t j = 0; j < dim; j++) {
            const int32_t yp = NTT_YP[j];
            re[j] = BarrettReduceQ((int16_t)(p0[j] + PlantardMulQ(p16[j], yp)));
            ro[j] = BarrettReduceQ((int16_t)(-n0[j] - PlantardMulQ(n16[j], yp)));
        }
    }
    for (int32_t j = 0; j < dim; j++) {
        r[30 * dim + j] = BarrettReduceQ(b0[15 * dim + j]);
        r[31 * dim + j] = BarrettReduceQ((int16_t)(-b1[15 * dim + j]));
    }
    return 1;
}

static int32_t Mont2Inverse32Judge(const int16_t *a)
{
    int16_t t0[16 * NEV_TDIM];
    int16_t t1[16 * NEV_TDIM];
    int16_t b0[32 * NEV_TDIM];
    int16_t b1[32 * NEV_TDIM];

    Mont2Inverse32Norm(t0, t1, b0, b1, a);

    return Mont2Inverse16Judge(b0);
}
#endif // NEV_TQ == 1409

#if NEV_TQ != 1409
/* r = a * b mod (X^4 - y_i) per slot, t = 4: MontMul4K core with the
 * wrap-around fold r_j = c_j + PM(c_{4+j}, yp), r_3 = c_3 fused into the
 * same per-slot pass (scalar NEV_PolyMulRed4Asm). Operands up to W. */
static void PolyMontMul4(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b)
{
    const int32_t dim = NEV_TDIM;
    const int16_t *ac = a->coeffs;
    const int16_t *bc = b->coeffs;

    for (int32_t i = 0; i < dim; i++) {
        const int32_t a0 = ac[i];
        const int32_t a1 = ac[dim + i];
        const int32_t a2 = ac[2 * dim + i];
        const int32_t a3 = ac[3 * dim + i];
        const int32_t b0 = bc[i];
        const int32_t b1 = bc[dim + i];
        const int32_t b2 = bc[2 * dim + i];
        const int32_t b3 = bc[3 * dim + i];
        const int32_t yp = NTT_YP[i];

        const int32_t p0 = a0 * b0;
        const int32_t p1 = a1 * b1;
        const int32_t p2 = a2 * b2;
        const int32_t p3 = a3 * b3;
        const int32_t d01 = (a0 + a1) * (b0 + b1) - p0 - p1;
        const int32_t d23 = (a2 + a3) * (b2 + b3) - p2 - p3;
        const int32_t pa0 = (a0 + a2) * (b0 + b2);
        const int32_t pa1 = (a1 + a3) * (b1 + b3);
        const int32_t pa01 = (a0 + a1 + a2 + a3) * (b0 + b1 + b2 + b3);

        const int16_t c0 = MontReduceQ(p0);
        const int16_t c1 = MontReduceQ(d01);
        const int16_t c2 = MontReduceQ(pa0 - p0 - p2 + p1);
        const int16_t c3 = BarrettReduceQ(MontReduceQ(pa01 - pa0 - pa1 - d01 - d23));
        const int16_t c4 = MontReduceQ(pa1 - p1 - p3 + p2);
        const int16_t c5 = MontReduceQ(d23);
        const int16_t c6 = MontReduceQ(p3);

        r->coeffs[i] = (int16_t)(c0 + PlantardMulQ(c4, yp));
        r->coeffs[dim + i] = (int16_t)(c1 + PlantardMulQ(c5, yp));
        r->coeffs[2 * dim + i] = (int16_t)(c2 + PlantardMulQ(c6, yp));
        r->coeffs[3 * dim + i] = c3;
    }
}
#endif // NEV_TQ != 1409

/*
 * Shared wrap-around recombination of PolyMontMul{8,16,32} (the scalar
 * NEV_Sub2ArrAsm + NEV_MulYCombAsm passes): with the direct products in t0
 * (low) and t2 (high), the middle product in t1 and h = t/2 blocks per half,
 *     t1_i (in place) = t1_i - t0_i - t2_i               i = 0..2h-2
 *     r_i        = t0_i + PM(t2_i + t1_{h+i}, yp)        i = 0..h-2
 *     r_{h-1}    = t0_{h-1} + PM(t2_{h-1}, yp)
 *     r_{h+i}    = t0_{h+i} + t1_i + PM(t2_{h+i}, yp)    i = 0..h-2
 *     r_{2h-1}   = t1_{h-1}
 * Congruent to the reference recombination (fold pairs merged before one
 * Plantard reduction); every value wrap-free by the range script. static
 * inline so each caller's constant h propagates into the loop bounds.
 */
static inline void PolyMontMulComb(NEV_Poly *r, const int16_t *t0, int16_t *t1, const int16_t *t2,
    int32_t h)
{
    const int32_t dim = NEV_TDIM;

    for (int32_t i = 0; i < (2 * h - 1) * dim; i++) {
        t1[i] = (int16_t)(t1[i] - t0[i] - t2[i]);
    }
    for (int32_t i = 0; i < h - 1; i++) {
        const int16_t *lo = &t0[i * dim];
        const int16_t *hi = &t2[i * dim];
        const int16_t *mid = &t1[(h + i) * dim];
        int16_t *out = &r->coeffs[i * dim];
        for (int32_t j = 0; j < dim; j++) {
            out[j] = (int16_t)(lo[j] + PlantardMulQ((int16_t)(hi[j] + mid[j]), NTT_YP[j]));
        }
    }
    for (int32_t j = 0; j < dim; j++) {
        r->coeffs[(h - 1) * dim + j] = (int16_t)(t0[(h - 1) * dim + j] +
            PlantardMulQ(t2[(h - 1) * dim + j], NTT_YP[j]));
    }
    for (int32_t i = 0; i < h - 1; i++) {
        const int16_t *lo = &t0[(h + i) * dim];
        const int16_t *hi = &t2[(h + i) * dim];
        const int16_t *mid = &t1[i * dim];
        int16_t *out = &r->coeffs[(h + i) * dim];
        for (int32_t j = 0; j < dim; j++) {
            out[j] = (int16_t)(lo[j] + mid[j] + PlantardMulQ(hi[j], NTT_YP[j]));
        }
    }
    for (int32_t j = 0; j < dim; j++) {
        r->coeffs[(2 * h - 1) * dim + j] = t1[(h - 1) * dim + j];
    }
}

/* r = a * b mod (X^8 - y_i) per slot, t = 8 (so n = 8 * dim): one Karatsuba
 * layer over MontMul4K. Operands up to W feed the low/high cores directly
 * (safe at the mm4(W, W) anchor); the middle gets the Barrett-normalized
 * a-side sum and the raw b-side sum (mm4(S, 2W) anchor). */
static void PolyMontMul8(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b)
{
    int16_t t0[7 * NEV_TDIM];
    int16_t t1[7 * NEV_TDIM];
    int16_t t2[7 * NEV_TDIM];
    const int32_t half = 4 * NEV_TDIM; // n / 2

    for (int32_t i = 0; i < half; i++) {
        t0[i] = BarrettReduceQ((int16_t)(a->coeffs[i] + a->coeffs[half + i]));
        t1[i] = (int16_t)(b->coeffs[i] + b->coeffs[half + i]);
    }

    MontMul4K(t1, t0, t1, 0);
    MontMul4K(t0, a->coeffs, b->coeffs, 0);
    MontMul4K(t2, &a->coeffs[half], &b->coeffs[half], 0);

    PolyMontMulComb(r, t0, t1, t2, 4);
}

/* r = a * b mod (X^16 - y_i) per slot, t = 16 (n = 16 * dim): one Karatsuba
 * layer over MontMul8K with the one-side (redA = 1) sum discipline at every
 * level. */
static void PolyMontMul16(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b)
{
    int16_t t0[15 * NEV_TDIM];
    int16_t t1[15 * NEV_TDIM];
    int16_t t2[15 * NEV_TDIM];
    const int32_t half = 8 * NEV_TDIM; // n / 2

    for (int32_t i = 0; i < half; i++) {
        t0[i] = BarrettReduceQ((int16_t)(a->coeffs[i] + a->coeffs[half + i]));
        t1[i] = (int16_t)(b->coeffs[i] + b->coeffs[half + i]);
    }

    MontMul8K(t1, t0, t1, 0, 1);
    MontMul8K(t0, a->coeffs, b->coeffs, 0, 1);
    MontMul8K(t2, &a->coeffs[half], &b->coeffs[half], 0, 1);

    PolyMontMulComb(r, t0, t1, t2, 8);
}

#if NEV_TQ == 1409
/* r = a * b mod (X^32 - y_i) per slot, t = 32 (n = 32 * dim): one Karatsuba
 * layer over MontMul16K with the one-side (redA = 1) sum discipline at every
 * level. */
static void PolyMontMul32(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b)
{
    int16_t t0[31 * NEV_TDIM];
    int16_t t1[31 * NEV_TDIM];
    int16_t t2[31 * NEV_TDIM];
    const int32_t half = 16 * NEV_TDIM; // n / 2

    for (int32_t i = 0; i < half; i++) {
        t0[i] = BarrettReduceQ((int16_t)(a->coeffs[i] + a->coeffs[half + i]));
        t1[i] = (int16_t)(b->coeffs[i] + b->coeffs[half + i]);
    }

    MontMul16K(t1, t0, t1, 1);
    MontMul16K(t0, a->coeffs, b->coeffs, 1);
    MontMul16K(t2, &a->coeffs[half], &b->coeffs[half], 1);

    PolyMontMulComb(r, t0, t1, t2, 16);
}
#endif // NEV_TQ == 1409

/* ------------------------------------------------------------------ */
/* Full-polynomial passes (bit-exact ports).
 *
 * Each streaming pass is an inline body taking n as a parameter that the
 * public entry point hands over as one of the literals 512 / 1024 / 2048
 * (the only n values in the nev.c parameter table, for every q). A constant
 * trip count that is a multiple of the vector width lets GCC's -O2
 * (very-cheap cost model) vectorizer emit SIMD loops exactly as it does for
 * the reference's compile-time PARAM_N; with runtime n these loops stayed
 * scalar. The bodies are unchanged, so the outputs are bit-identical.
 */

static inline void PolyReduceN(NEV_Poly *r, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        r->coeffs[i] = BarrettReduceQ(r->coeffs[i]);
    }
}

void NEV_TFN(NEV_PolyReduce)(NEV_Poly *r, uint32_t n)
{
    if (n == 512) {
        PolyReduceN(r, 512);
    } else if (n == 1024) {
        PolyReduceN(r, 1024);
    } else { // n == 2048
        PolyReduceN(r, 2048);
    }
}

static inline void PolyCaddqN(NEV_Poly *r, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        r->coeffs[i] = CaddqQ(r->coeffs[i]);
    }
}

void NEV_TFN(NEV_PolyCaddq)(NEV_Poly *r, uint32_t n)
{
    if (n == 512) {
        PolyCaddqN(r, 512);
    } else if (n == 1024) {
        PolyCaddqN(r, 1024);
    } else { // n == 2048
        PolyCaddqN(r, 2048);
    }
}

void NEV_TFN(NEV_PolyAddVinv)(NEV_Poly *f)
{
    const uint16_t qdiv2 = (uint16_t)((NEV_TQ + 1) / 2);

    f->coeffs[0] = (int16_t)(f->coeffs[0] + qdiv2);
    f->coeffs[NEV_TDIM / 2] = (int16_t)(f->coeffs[NEV_TDIM / 2] + qdiv2);
    f->coeffs[NEV_TDIM / 4] = (int16_t)(f->coeffs[NEV_TDIM / 4] + qdiv2);
    f->coeffs[NEV_TDIM * 3 / 4] = (int16_t)(f->coeffs[NEV_TDIM * 3 / 4] + qdiv2);
}

static inline void PolyGetMontgomeryN(NEV_Poly *r, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        r->coeffs[i] = MontReduceQ((int32_t)r->coeffs[i]);
    }
}

void NEV_TFN(NEV_PolyGetMontgomery)(NEV_Poly *r, uint32_t n)
{
    if (n == 512) {
        PolyGetMontgomeryN(r, 512);
    } else if (n == 1024) {
        PolyGetMontgomeryN(r, 1024);
    } else { // n == 2048
        PolyGetMontgomeryN(r, 2048);
    }
}

// Fused full-polynomial passes (see nev_local.h). Each applies, per
// coefficient, exactly the operation sequence of the NEV_Poly* calls it
// replaces (same inline helpers in the same order), so the results are
// bit-identical to the reference call sequences; only redundant memory
// passes are removed.

static inline void PolyReduceCaddqN(NEV_Poly *r, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        r->coeffs[i] = CaddqQ(BarrettReduceQ(r->coeffs[i]));
    }
}

void NEV_TFN(NEV_PolyReduceCaddq)(NEV_Poly *r, uint32_t n)
{
    if (n == 512) {
        PolyReduceCaddqN(r, 512);
    } else if (n == 1024) {
        PolyReduceCaddqN(r, 1024);
    } else { // n == 2048
        PolyReduceCaddqN(r, 2048);
    }
}

/* The NEV_Poly arguments of the backend contract are whole objects: any two
 * of them are either identical or disjoint (partial overlap cannot arise from
 * the API - nev_kem.c hands out distinct pool entries; the ARMv8 backend's
 * vector loads/stores rely on the same property). The aliasing cases
 * therefore reduce to r == a, r == b (the int16 add is commutative, so both
 * collapse to the same in-place body) and all-distinct, each of which can be
 * restrict-qualified so the fused loop vectorizes. */
static inline void PolyAddReduceCaddqIpN(int16_t *restrict rc, const int16_t *restrict bc,
    uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        int16_t t = (int16_t)(rc[i] + bc[i]);
        rc[i] = CaddqQ(BarrettReduceQ(t));
    }
}

static inline void PolyAddReduceCaddq3N(int16_t *restrict rc, const int16_t *restrict ac,
    const int16_t *restrict bc, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        int16_t t = (int16_t)(ac[i] + bc[i]);
        rc[i] = CaddqQ(BarrettReduceQ(t));
    }
}

static inline void PolyAddReduceCaddqSel(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b,
    uint32_t n)
{
    if (r == a) {
        PolyAddReduceCaddqIpN(r->coeffs, b->coeffs, n);
    } else if (r == b) {
        PolyAddReduceCaddqIpN(r->coeffs, a->coeffs, n);
    } else {
        PolyAddReduceCaddq3N(r->coeffs, a->coeffs, b->coeffs, n);
    }
}

void NEV_TFN(NEV_PolyAddReduceCaddq)(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b, uint32_t n)
{
    if (n == 512) {
        PolyAddReduceCaddqSel(r, a, b, 512);
    } else if (n == 1024) {
        PolyAddReduceCaddqSel(r, a, b, 1024);
    } else { // n == 2048
        PolyAddReduceCaddqSel(r, a, b, 2048);
    }
}

static inline void PolyGetMontgomeryCaddqN(NEV_Poly *r, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        r->coeffs[i] = CaddqQ(MontReduceQ((int32_t)r->coeffs[i]));
    }
}

void NEV_TFN(NEV_PolyGetMontgomeryCaddq)(NEV_Poly *r, uint32_t n)
{
    if (n == 512) {
        PolyGetMontgomeryCaddqN(r, 512);
    } else if (n == 1024) {
        PolyGetMontgomeryCaddqN(r, 1024);
    } else { // n == 2048
        PolyGetMontgomeryCaddqN(r, 2048);
    }
}

/* t = n / nttDim dispatch; the t sets per modulus are fixed by the parameter
 * table (see the file header), so the unused towers are not instantiated. */
void NEV_TFN(NEV_PolyMontMul)(NEV_Poly *r, const NEV_Poly *a, const NEV_Poly *b, uint32_t n)
{
    const uint32_t t = n / NEV_TDIM;

#if NEV_TQ == 1409
    if (t == 8) {
        PolyMontMul8(r, a, b);
    } else if (t == 16) {
        PolyMontMul16(r, a, b);
    } else { // t == 32 (NEV-2048-1409)
        PolyMontMul32(r, a, b);
    }
#else
    if (t == 4) {
        PolyMontMul4(r, a, b);
    } else if (t == 8) {
        PolyMontMul8(r, a, b);
    } else { // t == 16 (n == 2048)
        PolyMontMul16(r, a, b);
    }
#endif
}

int32_t NEV_TFN(NEV_PolyMont2Inverse)(NEV_Poly *r, const NEV_Poly *a, uint32_t n)
{
    const uint32_t t = n / NEV_TDIM;

#if NEV_TQ == 1409
    if (t == 8) {
        return Mont2Inverse8(r->coeffs, a->coeffs);
    }
    if (t == 16) {
        return Mont2Inverse16(r->coeffs, a->coeffs);
    }
    return Mont2Inverse32(r->coeffs, a->coeffs);
#else
    if (t == 4) {
        return Mont2Inverse4(r->coeffs, a->coeffs);
    }
    if (t == 8) {
        return Mont2Inverse8(r->coeffs, a->coeffs);
    }
    return Mont2Inverse16(r->coeffs, a->coeffs);
#endif
}

int32_t NEV_TFN(NEV_PolyMont2InverseJudge)(const NEV_Poly *a, uint32_t n)
{
    const uint32_t t = n / NEV_TDIM;

#if NEV_TQ == 1409
    if (t == 8) {
        return Mont2Inverse8Judge(a->coeffs);
    }
    if (t == 16) {
        return Mont2Inverse16Judge(a->coeffs);
    }
    return Mont2Inverse32Judge(a->coeffs);
#else
    if (t == 4) {
        return Mont2Inverse4Judge(a->coeffs);
    }
    if (t == 8) {
        return Mont2Inverse8Judge(a->coeffs);
    }
    return Mont2Inverse16Judge(a->coeffs);
#endif
}

/* ------------------------------------------------------------------ */
/* nev_pack part: packing / message codecs (byte-exact ports of the
 * reference pack.c). Packed sizes (info->polyBytes):
 *   q = 769:  5 coefficients into 6 bytes (base-97 high parts) plus an
 *             n-dependent tail
 *   q = 1409: 16 coefficients into 21 bytes (pairs combined as
 *             x0 + 1409 * x1, 21 bits each)
 *   q = 3329: 2 coefficients into 3 bytes (12 bits per coefficient)
 */

#if NEV_TQ == 769
// q = 769 codec: 5 coefficients -> 6 bytes.
// Each coefficient splits into 3 low bits (packed into wl) and a high part < 97
// (packed into wh in base 97, with a carry trick spilling 2 bits into wl).
static inline void Encode5(uint8_t *buf, const int16_t x[5])
{
    int32_t i;
    uint32_t wl, wh;
    uint32_t t;

    wl = (uint16_t)x[0] & 0x07;
    for (i = 1; i < 5; i++) {
        wl |= (uint32_t)((uint16_t)x[i] & 0x07) << (3 * i);
    }

    wl <<= 1;
    wh = (uint16_t)x[4] >> 3;
    for (i = 3; i > 0; i--) {
        wh = (wh * 97) + ((uint16_t)x[i] >> 3);
    }

    t = wh * 48;
    wl |= t >> 31;
    t <<= 1;
    wh = wh + ((uint16_t)x[0] >> 3);
    wh = t + wh;
    wl |= ((t & ~wh) >> 31);

    buf[0] = (uint8_t)wl;
    buf[1] = (uint8_t)(wl >> 8);
    buf[2] = (uint8_t)wh;
    for (i = 3; i < 6; i++) {
        wh = wh >> 8;
        buf[i] = (uint8_t)wh;
    }
}

static inline void Decode5(int16_t *x, const uint8_t *buf)
{
    // Useful facts:
    //    512 = 27 mod 97
    //    2^19 = 3 mod 97
    //    for any x in 0..57519, (43241 * x) >> 22 = floor(x / 97)
    //    97 * 1594008481 = 1 mod 2^32
    uint32_t wl, wh, z;
    int32_t i;

    wl = ((uint32_t)buf[1] << 8) | buf[0];
    wh = buf[5];
    for (i = 4; i > 1; i--) {
        wh = (wh << 8) | (uint32_t)buf[i];
    }

    z = (((wl & 0x01) << 13) | (wh >> 19)) * 3;
    z += wh & 0x7FFFF;
    wl >>= 1;

    z = (z >> 9) * 27 + (z & 0x1FF);
    z -= ((z * 43241) >> 22) * 97;

    x[0] = (int16_t)(uint16_t)((z << 3) + (wl & 0x07));
    wl >>= 3;

    wh -= z;
    wh = wh * 1594008481u;

    z = (wh >> 19) * 3 + (wh & 0x7FFFF);
    z = (z >> 9) * 27 + (z & 0x1FF);
    z -= ((z * 43241) >> 22) * 97;

    x[1] = (int16_t)(uint16_t)((z << 3) + (wl & 0x07));
    wl >>= 3;

    wh -= z;
    wh = wh * 1594008481u;

    z = (wh >> 9) * 27 + (wh & 0x1FF);
    z -= ((z * 43241) >> 22) * 97;

    x[2] = (int16_t)(uint16_t)((z << 3) + (wl & 0x07));
    wl >>= 3;

    wh -= z;
    z = wh * 1594008481u;

    wh = (z * 43241) >> 22;
    z -= wh * 97;

    x[3] = (int16_t)(uint16_t)((z << 3) + (wl & 0x07));
    wl >>= 3;

    x[4] = (int16_t)(uint16_t)((wh << 3) + wl);
}

// n mod 5 = 2 (n = 512), 4 (n = 1024) or 3 (n = 2048) tail coefficients, 10 bits each.
static void PolyToBytes769(uint8_t *r, const NEV_Poly *a, uint32_t n)
{
    uint32_t i;
    uint16_t t[4];

    for (i = 0; i < n / 5; i++) {
        Encode5(&r[6 * i], &a->coeffs[5 * i]);
    }

    t[0] = (uint16_t)a->coeffs[5 * i];
    t[1] = (uint16_t)a->coeffs[5 * i + 1];

    if (n == 512) {
        r[6 * i] = (uint8_t)t[0];
        r[6 * i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
        r[6 * i + 2] = (uint8_t)(t[1] >> 6);
    } else if (n == 1024) {
        t[2] = (uint16_t)a->coeffs[5 * i + 2];
        t[3] = (uint16_t)a->coeffs[5 * i + 3];

        r[6 * i] = (uint8_t)t[0];
        r[6 * i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
        r[6 * i + 2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
        r[6 * i + 3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
        r[6 * i + 4] = (uint8_t)(t[3] >> 2);
    } else { // n == 2048
        t[2] = (uint16_t)a->coeffs[5 * i + 2];

        r[6 * i] = (uint8_t)t[0];
        r[6 * i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
        r[6 * i + 2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
        r[6 * i + 3] = (uint8_t)(t[2] >> 4);
    }
}

static void PolyFromBytes769(NEV_Poly *r, const uint8_t *a, uint32_t n)
{
    uint32_t i;

    for (i = 0; i < n / 5; i++) {
        Decode5(&r->coeffs[5 * i], &a[6 * i]);
    }

    r->coeffs[5 * i] = (int16_t)((uint16_t)a[6 * i] | (((uint16_t)a[6 * i + 1] & 0x03) << 8));
    r->coeffs[5 * i + 1] = (int16_t)(((uint16_t)a[6 * i + 1] >> 2) | (((uint16_t)a[6 * i + 2] & 0x0f) << 6));

    if (n == 1024) {
        r->coeffs[5 * i + 2] = (int16_t)(((uint16_t)a[6 * i + 2] >> 4) | (((uint16_t)a[6 * i + 3] & 0x3f) << 4));
        r->coeffs[5 * i + 3] = (int16_t)(((uint16_t)a[6 * i + 3] >> 6) | ((uint16_t)a[6 * i + 4] << 2));
    } else if (n == 2048) {
        r->coeffs[5 * i + 2] = (int16_t)(((uint16_t)a[6 * i + 2] >> 4) | (((uint16_t)a[6 * i + 3] & 0x3f) << 4));
    }
}

#elif NEV_TQ == 1409
// q = 1409 codec: 16 coefficients -> 21 bytes. Pairs are combined as
// x[2i] + 1409 * x[2i+1] (21 bits) and the eight 21-bit words are bit-packed.
static inline void Encode16(uint8_t *buf, const int16_t x[16])
{
    uint32_t t[8];
    int32_t i;

    for (i = 0; i < 8; i++) {
        t[i] = (uint16_t)x[2 * i + 1];
        t[i] = t[i] * 1409 + (uint16_t)x[2 * i];
    }

    buf[0] = (uint8_t)(t[0] & 0xff);
    buf[1] = (uint8_t)((t[0] >> 8) & 0xff);
    buf[2] = (uint8_t)(((t[0] >> 16) & 0xff) | ((t[1] << 5) & 0xff));
    buf[3] = (uint8_t)((t[1] >> 3) & 0xff);
    buf[4] = (uint8_t)((t[1] >> 11) & 0xff);
    buf[5] = (uint8_t)(((t[1] >> 19) & 0xff) | ((t[2] << 2) & 0xff));
    buf[6] = (uint8_t)((t[2] >> 6) & 0xff);
    buf[7] = (uint8_t)(((t[2] >> 14) & 0xff) | ((t[3] << 7) & 0xff));
    buf[8] = (uint8_t)((t[3] >> 1) & 0xff);
    buf[9] = (uint8_t)((t[3] >> 9) & 0xff);
    buf[10] = (uint8_t)(((t[3] >> 17) & 0xff) | ((t[4] << 4) & 0xff));
    buf[11] = (uint8_t)((t[4] >> 4) & 0xff);
    buf[12] = (uint8_t)((t[4] >> 12) & 0xff);
    buf[13] = (uint8_t)(((t[4] >> 20) & 0xff) | ((t[5] << 1) & 0xff));
    buf[14] = (uint8_t)((t[5] >> 7) & 0xff);
    buf[15] = (uint8_t)(((t[5] >> 15) & 0xff) | ((t[6] << 6) & 0xff));
    buf[16] = (uint8_t)((t[6] >> 2) & 0xff);
    buf[17] = (uint8_t)((t[6] >> 10) & 0xff);
    buf[18] = (uint8_t)(((t[6] >> 18) & 0xff) | ((t[7] << 3) & 0xff));
    buf[19] = (uint8_t)((t[7] >> 5) & 0xff);
    buf[20] = (uint8_t)((t[7] >> 13) & 0xff);
}

static inline void Decode16(int16_t *x, const uint8_t *buf)
{
    uint32_t t[8];
    uint32_t hi;
    int32_t i;

    t[0] = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)(buf[2] & 0x1f) << 16);
    t[1] = ((uint32_t)buf[2] >> 5) | ((uint32_t)buf[3] << 3) | ((uint32_t)buf[4] << 11) |
        ((uint32_t)(buf[5] & 0x03) << 19);
    t[2] = ((uint32_t)buf[5] >> 2) | ((uint32_t)buf[6] << 6) | ((uint32_t)(buf[7] & 0x7f) << 14);
    t[3] = ((uint32_t)buf[7] >> 7) | ((uint32_t)buf[8] << 1) | ((uint32_t)buf[9] << 9) |
        ((uint32_t)(buf[10] & 0x0f) << 17);
    t[4] = ((uint32_t)buf[10] >> 4) | ((uint32_t)buf[11] << 4) | ((uint32_t)buf[12] << 12) |
        ((uint32_t)(buf[13] & 0x01) << 20);
    t[5] = ((uint32_t)buf[13] >> 1) | ((uint32_t)buf[14] << 7) | ((uint32_t)(buf[15] & 0x3f) << 15);
    t[6] = ((uint32_t)buf[15] >> 6) | ((uint32_t)buf[16] << 2) | ((uint32_t)buf[17] << 10) |
        ((uint32_t)(buf[18] & 0x07) << 18);
    t[7] = ((uint32_t)buf[18] >> 3) | ((uint32_t)buf[19] << 5) | ((uint32_t)buf[20] << 13);

    for (i = 0; i < 8; i++) {
        // x[2i+1] = t[i] / 1409, x[2i] = t[i] % 1409, via (t * 3048238) >> 32 = floor(t / 1409)
        hi = (uint32_t)(((uint64_t)t[i] * 3048238) >> 32);
        x[2 * i + 1] = (int16_t)(uint16_t)hi;
        x[2 * i] = (int16_t)(uint16_t)(t[i] - hi * 1409);
    }
}

#else
// q = 3329 codec: 2 coefficients -> 3 bytes (12 bits each).
static inline void Encode2(uint8_t buf[3], const int16_t x[2])
{
    buf[0] = (uint8_t)(uint16_t)x[0];
    buf[1] = (uint8_t)(((uint16_t)x[0] >> 8) | ((uint16_t)x[1] << 4));
    buf[2] = (uint8_t)((uint16_t)x[1] >> 4);
}

static inline void Decode2(int16_t x[2], const uint8_t buf[3])
{
    x[0] = (int16_t)((uint16_t)buf[0] | (((uint16_t)buf[1] & 0x0f) << 8));
    x[1] = (int16_t)(((uint16_t)buf[1] >> 4) | ((uint16_t)buf[2] << 4));
}
#endif

void NEV_TFN(NEV_PolyToBytes)(uint8_t *r, const NEV_Poly *a, uint32_t n)
{
#if NEV_TQ == 769
    PolyToBytes769(r, a, n);
#elif NEV_TQ == 1409
    for (uint32_t i = 0; i < n / 16; i++) {
        Encode16(&r[21 * i], &a->coeffs[16 * i]);
    }
#else
    for (uint32_t i = 0; i < n / 2; i++) {
        Encode2(&r[3 * i], &a->coeffs[2 * i]);
    }
#endif
}

void NEV_TFN(NEV_PolyFromBytes)(NEV_Poly *r, const uint8_t *a, uint32_t n)
{
#if NEV_TQ == 769
    PolyFromBytes769(r, a, n);
#elif NEV_TQ == 1409
    for (uint32_t i = 0; i < n / 16; i++) {
        Decode16(&r->coeffs[16 * i], &a[21 * i]);
    }
#else
    for (uint32_t i = 0; i < n / 2; i++) {
        Decode2(&r->coeffs[2 * i], &a[3 * i]);
    }
#endif
}

// 8-bit per-coefficient ciphertext decompression: x[i] = round(c[i] * q / 256).
// The poly and the packed ciphertext buffer never overlap (whole-object
// arguments, see PolyAddReduceCaddqSel above), so restrict is safe and lets
// the widening u8 -> s16 loop vectorize.
static inline void PolyDecompressN(NEV_Poly *restrict x, const uint8_t *restrict c, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        x->coeffs[i] = (int16_t)(((uint32_t)c[i] * NEV_TQ + (1U << 7)) >> 8);
    }
}

void NEV_TFN(NEV_PolyDecompress)(NEV_Poly *x, const uint8_t *c, uint32_t n)
{
    if (n == 512) {
        PolyDecompressN(x, c, 512);
    } else if (n == 1024) {
        PolyDecompressN(x, c, 1024);
    } else { // n == 2048
        PolyDecompressN(x, c, 2048);
    }
}

// |x mod+- q| : distance of x from the nearest multiple of q, folded to [0, q/2].
static inline uint16_t FlipAbs(int16_t x)
{
    int16_t r, m;

    r = CaddqQ(x);
    r = (int16_t)(r - NEV_TQ / 2);
    m = r >> 15;
    return (uint16_t)((r + m) ^ m);
}

// Each message bit is carried by 4 coefficients located a quarter NTT block apart;
// the bit is 1 when the summed distances from q/2 stay below q.
// nttDim = 64 packs 2 message bytes per block, nttDim = 128 packs 4.
void NEV_TFN(NEV_PolyToMsg)(uint8_t *msg, const NEV_Poly *r, uint32_t seedLen)
{
    uint32_t i, j, k;
    uint16_t t;
    const uint32_t dim = NEV_TDIM;
    const uint32_t bytesPerBlock = NEV_TDIM / 32; // message bytes carried by one NTT block
    const uint32_t quarter = NEV_TDIM / 4;        // stride between the 4 carriers of one bit

    for (i = 0; i < seedLen / bytesPerBlock; i++) {
        for (j = 0; j < bytesPerBlock; j++) {
            msg[bytesPerBlock * i + j] = 0;
            for (k = 0; k < 8; k++) {
                t = FlipAbs(r->coeffs[dim * i + 8 * j + k]);
                t += FlipAbs(r->coeffs[dim * i + 8 * j + k + quarter]);
                t += FlipAbs(r->coeffs[dim * i + 8 * j + k + 2 * quarter]);
                t += FlipAbs(r->coeffs[dim * i + 8 * j + k + 3 * quarter]);
                t = (uint16_t)(t - NEV_TQ);
                t >>= 15;
                msg[bytesPerBlock * i + j] |= (uint8_t)(t << k);
            }
        }
    }
}
