/* Copyright (c) 2025 LiuYing
 *    Key Laboratory of Cyberspace Security Defense,Institute of Information Engineering, CAS
 *    School of Cyber Security, University of Chinese Academy of Sciences
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

// This file implements the C-language version of 512-length NTT and NTT-based multiplication for PolarLAC128.
#ifdef PQCP_POLARLAC
#include "polarlac_local.h"
#include <stdint.h>

#define POLAR_LAC_LIGHT_128_DIM 512
#define INVERSE_N               18397
#define INVERSE_N_BETA          128

// twiddle factors for 1024 length in NTT use Montgomery
static int16_t M[512] = {
    10237, 1356,  4658,  6948,  8459,  2028,  9087,  11370, 17111, 11095, 6113,  16558, 12704, 2891,  1965,  4047,
    8745,  8161,  765,   872,   2802,  14326, 18109, 3751,  1532,  14806, 16006, 1643,  16483, 1753,  13172, 17954,
    14691, 3156,  1380,  17476, 2886,  9940,  4837,  14718, 16498, 7553,  10802, 4771,  6241,  4608,  9304,  9256,
    6651,  9533,  18256, 5292,  1954,  5938,  4629,  1879,  4055,  13417, 4465,  18342, 14547, 2775,  5699,  3942,
    9726,  388,   11664, 12428, 9326,  5474,  1132,  1459,  14901, 10624, 5066,  17244, 13640, 14584, 1541,  18286,
    3481,  6522,  2992,  1772,  1128,  12201, 6106,  7707,  16642, 7934,  6483,  18305, 4662,  14639, 724,   9596,
    3388,  7428,  17686, 6088,  6372,  12251, 7039,  18240, 10865, 10698, 16032, 5552,  5157,  3276,  14679, 16949,
    14953, 9,     15283, 17011, 16654, 12574, 4587,  4072,  5619,  16019, 15415, 12752, 10198, 4709,  10820, 11731,
    8452,  11610, 10193, 8920,  9215,  17853, 237,   17908, 4341,  1117,  14576, 7844,  12691, 10153, 4019,  17930,
    6770,  12536, 17887, 10076, 16650, 4883,  5219,  2672,  17195, 6709,  11274, 9092,  13319, 1062,  15393, 16534,
    15104, 9241,  9858,  14562, 10518, 11700, 15559, 13133, 12224, 1621,  4073,  1944,  5232,  13843, 2829,  6333,
    12168, 4545,  12921, 777,   4822,  8918,  12310, 10297, 17346, 15941, 5849,  6643,  7183,  188,   7932,  7162,
    8889,  8542,  14879, 14406, 1223,  5924,  9529,  4091,  18207, 17067, 17275, 13065, 18095, 4482,  16538, 10731,
    3949,  3152,  2780,  18108, 9821,  12544, 15087, 8812,  1712,  10674, 5999,  9344,  9901,  467,   2447,  18379,
    10738, 10746, 17665, 16401, 14102, 8894,  2277,  14089, 17907, 11665, 9376,  230,   10632, 481,   15980, 16167,
    14411, 17776, 8754,  11641, 836,   3748,  15376, 16105, 13772, 10325, 17551, 9187,  11299, 6470,  2759,  9988,
    5488,  8376,  17680, 3768,  3314,  3392,  10945, 17054, 12877, 8341,  11497, 9298,  4088,  7744,  17684, 11459,
    4265,  2452,  8151,  18110, 6868,  7419,  2403,  7510,  13215, 3859,  13392, 17000, 5246,  13112, 617,   11233,
    6248,  13459, 8198,  11706, 6245,  12299, 8672,  10656, 9743,  817,   8978,  18378, 16692, 2690,  17016, 17372,
    10579, 4565,  5921,  16050, 7013,  14331, 16359, 2961,  17544, 336,   11431, 2211,  7316,  2460,  5351,  16846,
    10814, 9411,  5657,  6135,  1492,  11628, 3893,  6076,  13907, 7226,  14654, 1138,  15579, 14722, 8540,  14915,
    296,   16144, 8531,  11435, 10067, 15499, 13085, 2747,  8675,  11816, 11825, 13238, 11506, 12778, 6919,  8706,
    5594,  208,   932,   4002,  8040,  12056, 1557,  12184, 13119, 3605,  10127, 1833,  12443, 12569, 6337,  4862,
    7377,  13758, 14146, 1330,  8586,  1980,  7454,  521,   18233, 2543,  13167, 3732,  1169,  3477,  18061, 3624,
    4902,  15274, 18103, 1431,  16140, 10446, 12067, 8502,  62,    17829, 8637,  3267,  14937, 6111,  17811, 11411,
    2016,  5334,  13266, 5146,  14760, 11403, 8911,  4760,  12254, 13221, 17766, 12444, 4135,  1340,  10258, 9476,
    4721,  12875, 9835,  11813, 4940,  5390,  12099, 14731, 7648,  14091, 8194,  4015,  16495, 6393,  11276, 3721,
    1919,  16982, 10159, 8062,  4175,  4518,  3938,  5043,  9598,  12338, 13455, 4494,  489,   4750,  14903, 5253,
    3197,  13451, 10998, 12970, 1682,  17507, 10739, 17277, 17037, 7059,  17805, 9091,  5579,  12841, 3302,  17185,
    15258, 1200,  3959,  13163, 2429,  11419, 3311,  2232,  11880, 3783,  3126,  10575, 7980,  7289,  11037, 9617,
    15597, 3249,  5696,  2782,  2936,  4696,  15370, 13785, 829,   13330, 16482, 13655, 13311, 4113,  16657, 13734,
    14469, 9481,  18023, 13508, 18377, 2924,  8848,  17266, 14600, 17124, 15758, 4059,  6828,  4241,  8723,  11943};
static int16_t Mn[512] = {
    10237, 17077, 11485, 13775, 7063,  9346,  16405, 9974,  14386, 16468, 15542, 5729,  1875,  12320, 7338,  1322,
    479,   5261,  16680, 1950,  16790, 2427,  3627,  16901, 14682, 324,   4107,  15631, 17561, 17668, 10272, 9688,
    14491, 12734, 15658, 3886,  91,    13968, 5016,  14378, 16554, 13804, 12495, 16479, 13141, 177,   8900,  11782,
    9177,  9129,  13825, 12192, 13662, 7631,  10880, 1935,  3715,  13596, 8493,  15547, 957,   17053, 15277, 3742,
    6702,  7613,  13724, 8235,  5681,  3018,  2414,  12814, 14361, 13846, 5859,  1779,  1422,  3150,  18424, 3480,
    1484,  3754,  15157, 13276, 12881, 2401,  7735,  7568,  193,   11394, 6182,  12061, 12345, 747,   11005, 15045,
    8837,  17709, 3794,  13771, 128,   11950, 10499, 1791,  10726, 12327, 6232,  17305, 16661, 15441, 11911, 14952,
    147,   16892, 3849,  4793,  1189,  13367, 7809,  3532,  16974, 17301, 12959, 9107,  6005,  6769,  18045, 8707,
    8445,  15674, 11963, 7134,  9246,  882,   8108,  4661,  2328,  3057,  14685, 17597, 6792,  9679,  657,   4022,
    2266,  2453,  17952, 7801,  18203, 9057,  6768,  526,   4344,  16156, 9539,  4331,  2032,  768,   7687,  7695,
    54,    15986, 17966, 8532,  9089,  12434, 7759,  16721, 9621,  3346,  5889,  8612,  325,   15653, 15281, 14484,
    7702,  1895,  13951, 338,   5368,  1158,  1366,  226,   14342, 8904,  12509, 17210, 4027,  3554,  9891,  9544,
    11271, 10501, 18245, 11250, 11790, 12584, 2492,  1087,  8136,  6123,  9515,  13611, 17656, 5512,  13888, 6265,
    12100, 15604, 4590,  13201, 16489, 14360, 16812, 6209,  5300,  2874,  6733,  7915,  3871,  8575,  9192,  3329,
    1899,  3040,  17371, 5114,  9341,  7159,  11724, 1238,  15761, 13214, 13550, 1783,  8357,  546,   5897,  11663,
    503,   14414, 8280,  5742,  10589, 3857,  17316, 14092, 525,   18196, 580,   9218,  9513,  8240,  6823,  9981,
    6490,  9710,  14192, 11605, 14374, 2675,  1309,  3833,  1167,  9585,  15509, 56,    4925,  410,   8952,  3964,
    4699,  1776,  14320, 5122,  4778,  1951,  5103,  17604, 4648,  3063,  13737, 15497, 15651, 12737, 15184, 2836,
    8816,  7396,  11144, 10453, 7858,  15307, 14650, 6553,  16201, 15122, 7014,  16004, 5270,  14474, 17233, 3175,
    1248,  15131, 5592,  12854, 9342,  628,   11374, 1396,  1156,  7694,  926,   16751, 5463,  7435,  4982,  15236,
    13180, 3530,  13683, 17944, 13939, 4978,  6095,  8835,  13390, 14495, 13915, 14258, 10371, 8274,  1451,  16514,
    14712, 7157,  12040, 1938,  14418, 10239, 4342,  10785, 3702,  6334,  13043, 13493, 6620,  8598,  5558,  13712,
    8957,  8175,  17093, 14298, 5989,  667,   5212,  6179,  13673, 9522,  7030,  3673,  13287, 5167,  13099, 16417,
    7022,  622,   12322, 3496,  15166, 9796,  604,   18371, 9931,  6366,  7987,  2293,  17002, 330,   3159,  13531,
    14809, 372,   14956, 17264, 14701, 5266,  15890, 200,   17912, 10979, 16453, 9847,  17103, 4287,  4675,  11056,
    13571, 12096, 5864,  5990,  16600, 8306,  14828, 5314,  6249,  16876, 6377,  10393, 14431, 17501, 18225, 12839,
    9727,  11514, 5655,  6927,  5195,  6608,  6617,  9758,  15686, 5348,  2934,  8366,  6998,  9902,  2289,  18137,
    3518,  9893,  3711,  2854,  17295, 3779,  11207, 4526,  12357, 14540, 6805,  16941, 12298, 12776, 9022,  7619,
    1587,  13082, 15973, 11117, 16222, 7002,  18097, 889,   15472, 2074,  4102,  11420, 2383,  12512, 13868, 7854,
    1061,  1417,  15743, 1741,  55,    9455,  17616, 8690,  7777,  9761,  6134,  12188, 6727,  10235, 4974,  12185,
    7200,  17816, 5321,  13187, 1433,  5041,  14574, 5218,  10923, 16030, 11014, 11565, 323,   10282, 15981, 14168,
    6974,  749,   10689, 14345, 9135,  6936,  10092, 5556,  1379,  7488,  15041, 15119, 14665, 753,   10057, 12945};

/**
 * @brief Performs the Number Theoretic Transform (NTT) with lazy reduction.
 *
 * This function applies the NTT algorithm to the input array `a` using lazy
 * modular reduction. Lazy reduction allows intermediate values to exceed
 * the modulus temporarily, reducing the number of modular operations and
 * improving performance.
 *
 * @param a Pointer to the input array of integers (int16_t) to be transformed.
 *          The array is modified in-place to contain the transformed values.
 *
 * @return Returns an integer status code. Typically, 0 indicates success,
 *         while other values may indicate errors or specific conditions.
 */
void PQCP_POLAR_LAC_NttLazy(int16_t *a)
{
    int32_t t; // Step size, distance between elements in butterfly operations
    int32_t m; // Current stage number in NTT
    int32_t i; // Index for iterating over blocks at current stage
    int32_t j; // Index for iterating within each block
    int32_t s; // Start index for current block
    int32_t e; // End index for current block
    int16_t u = 0; // First element in butterfly operation
    int16_t v = 0; // Second element in butterfly operation
    uint16_t twiddle; // Twiddle factor for the current butterfly operation
    t = POLAR_LAC_LIGHT_128_DIM;
    // t is the step size, starting from POLAR_LAC_LIGHT_128_DIM,
    // t indics the distance between the elements to be processed in the same butterfly operation

    // First level in the computation in NTT
    m = 1;
    t = (t >> 1); // Halve the step size
    for (i = 0; i < m; i++) {
        s = (i * t) << 1; // Start index for coefficients using the same twiddle factor
        e = s + t; // End index for coefficients using the same twiddle factor
        twiddle = M[m + i]; // Twiddle factor for the current stage
        // Since the output of the Montgomery algorithm is rβ^(-1) mod NTTQ,
        //  a scaling factor β is introduced into the root-of-unity array M to eliminate the Montgomery factor.
        //  As a result, the roots of unity used here differ from those f[i] in the standard NTT algorithm.
        //  That is M[i]=f[i]*β mod NTTQ

        for (j = s; j < e; j++) {
            u = a[j];
            v = a[j + t];

            v = MontgomeryMapFull((int32_t)v * (int32_t)twiddle); // Use Montgomery to reduce multiplications

            // Because the all inputs at this stage are within (0, Q),
            // modular reduction is not required for addition and subtraction.
            a[j] = u + v - NTTQ; // in the range of [-NTTQ, NTTQ]
            a[j + t] = u - v; // in the range of [-NTTQ, NTTQ]
        }
    }

    // Subsequent stages of the butterfly operation (m = 2, 4, ..., POLAR_LAC_LIGHT_128_DIM/2)
    // 2~log_2N−2 level : perform the modular reduction to u
    for (m = 2; m < POLAR_LAC_LIGHT_128_DIM / 2; m <<= 1) {
        t = (t >> 1);
        for (i = 0; i < m; i++) {
            s = (i * t) << 1;
            e = s + t;
            twiddle = M[m + i];
            for (j = s; j < e; j++) {
                u = a[j];
                v = a[j + t];

                v = MontgomeryMapFull((int32_t)v * (int32_t)twiddle);
                u = u + ((u >> 15) & NTTQ); // lightweight modular reduction to the u to map it to （-NTTQ, NTTQ）

                a[j] = (u + v - NTTQ);
                a[j + t] = (u - v);
            }
        }
    }

    // final level : perform the modular reductions to u, a[j] and a[j+t]
    m = POLAR_LAC_LIGHT_128_DIM / 2;
    t = (t >> 1);
    for (i = 0; i < m; i++) {
        s = (i * t) << 1;
        e = s + t;
        twiddle = M[m + i];
        for (j = s; j < e; j++) {
            u = a[j];
            v = a[j + t];

            v = MontgomeryMapFull((int32_t)v * (int32_t)twiddle);
            u = u + ((u >> 15) & NTTQ);

            // Map each coefficient to its standard representation.
            a[j] = u + v - NTTQ;
            a[j] = a[j] + ((a[j] >> 15) & NTTQ);

            a[j + t] = u - v;
            a[j + t] = a[j + t] + ((a[j + t] >> 15) & NTTQ);
        }
    }
}

/**
 * @brief Performs the Inverse Number Theoretic Transform (INTT) with lazy reduction.
 *
 * This function applies the INTT algorithm to the input array `a` using lazy
 * modular reduction. Lazy reduction allows intermediate values to exceed
 * the modulus temporarily, reducing the number of modular operations and
 * improving performance.
 *
 * @param a Pointer to the input array of integers (int16_t) to be transformed.
 *          The array is modified in-place to contain the transformed values.
 *
 * @return Returns an integer status code. Typically, 0 indicates success,
 *         while other values may indicate errors or specific conditions.
 */

/**
 *Notice：
 *
 * GS butterfly structure used in the inverse transform exhibits weaker symmetry properties.
 * Due to the use of a 15-bit modulus, the intermediate results of additions and subtractions
 * are more likely to exceed the modulus range.
 * So modular reduction must be performed explicitly at each layer of the inverse transform.
 *
 */
void PQCP_POLAR_LAC_InttLazy(int16_t *a)
{
    int32_t t; // Step size, starting from 1 and doubling at each stage
    int32_t m; // Current stage size in INTT
    int32_t i; // Index for iterating over half stages
    int32_t j; // Index for iterating within each block
    int32_t s; // Start index for current block
    int32_t e; // End index for current block
    int32_t h; // Half of current stage size
    int16_t u = 0; // First element in butterfly operation
    int16_t v = 0; // Second element in butterfly operation
    uint16_t twiddle; // Twiddle factor for the current butterfly operation
    t = 1;

    // Perform the butterfly operations for each stage of the INTT
    for (m = POLAR_LAC_LIGHT_128_DIM; m > 1; m /= 2) {
        s = 0; // Start index for coefficients using the same twiddle factor
        h = m / 2; // Half the size of the current stage
        for (i = 0; i < h; i++) {
            e = s + t; // End index for coefficients using the same twiddle factor
            twiddle = Mn[h + i]; // Twiddle factor for the current stage
            for (j = s; j < e; j++) {
                u = a[j];
                v = a[j + t];

                // Update the first element of the butterfly
                a[j] = (u + v - NTTQ);
                a[j] = a[j] + ((a[j] >> 15) & NTTQ); // Ensure the result is in the range (0, NTTQ)

                // Update the second element of the butterfly using Montgomery reduction
                a[j + t] = MontgomeryMapFull((int32_t)(u - v) * (int32_t)twiddle);
            }
            s = s + 2 * t; // Move to the next pair of coefficients
        }
        t *= 2; // Double the step size at each stage
    }

    // Multiply each coefficient by the scaling factor N^(-1)*β mod NTTQ
    // The β is used to emliminate the Montgomery factor introduced in the point-mul stage in the fucntion
    // PQCP_POLAR_LAC_PolyMulNttLazy
    for (i = 0; i < POLAR_LAC_LIGHT_128_DIM; i++) {
        a[i] = (a[i] * INVERSE_N_BETA) % NTTQ;
    }
}
#endif // PQCP_POLARLAC
