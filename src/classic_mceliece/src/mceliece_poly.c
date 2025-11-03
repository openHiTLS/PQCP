/*
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

#include "mceliece_poly.h"

GFPolynomial *PolynomialCreate(const int32_t maxDegree)
{
    GFPolynomial *poly = BSL_SAL_Malloc(sizeof(GFPolynomial));
    if (poly == NULL) {
        return NULL;
    }

    poly->coeffs = BSL_SAL_Calloc(maxDegree + 1, sizeof(GFElement));
    if (poly->coeffs == NULL) {
        BSL_SAL_FREE(poly);
        return NULL;
    }

    poly->degree = -1;  // Sentinel value indicating “zero polynomial” or “degree not yet determined”
    poly->maxDegree = maxDegree;
    return poly;
}

void PolynomialFree(GFPolynomial *poly)
{
    if (poly != NULL) {
        if (poly->coeffs != NULL) {
            BSL_SAL_FREE(poly->coeffs);
        }
        BSL_SAL_FREE(poly);
    }
}

void PolynomialRoots(GFElement *out, const GFElement *f, const GFElement *L, const int32_t n, const int32_t t)
{
    for (int32_t i = 0; i < n; i++) {
        GFElement r = f[t];
        GFElement a = L[i];

        // r = r*a + f[k]
        for (int32_t k = t - 1; k >= 0; k--) {
            r = GFAddtion(GFMultiplication(r, a), f[k]);
        }
        out[i] = r;  // f(L[i])
    }
}

// Efficient polynomial evaluation using Horner's method
GFElement PolynomialEval(const GFPolynomial *poly, GFElement x)
{
    if (poly->degree < 0) {
        return 0;  // Zero polynomial
    }

    // Use Horner's method: start with highest degree coefficient
    GFElement result = poly->coeffs[poly->degree];

    // Iterate down to constant term
    for (int32_t i = poly->degree - 1; i >= 0; i--) {
        result = GFMultiplication(result, x);
        result = GFAddtion(result, poly->coeffs[i]);
    }

    return result;
}

CRYPT_ERROR PolynomialSetCoeff(GFPolynomial *poly, const int32_t degree, const GFElement coeff)
{
    if (degree > poly->maxDegree) {
        return PQCP_MCELIECE_INVALID_ARG;
    }

    poly->coeffs[degree] = coeff;
    if (coeff != 0 && degree > poly->degree) {
        poly->degree = degree;
    } else if (coeff == 0 && degree == poly->degree) {
        int32_t newDegree = -1;     // Initial sentinel while scanning downward to find highest non-zero coefficient
        for (int32_t i = poly->maxDegree; i >= 0; i--) {
            if (poly->coeffs[i] != 0) {
                newDegree = i;
                break;
            }
        }
        poly->degree = newDegree;
    }
}

CRYPT_ERROR PolynomialCopy(GFPolynomial *dst, const GFPolynomial *src)
{
    if (dst == NULL || src == NULL) {
        return PQCP_NULL_INPUT;
    }

    memset_s(dst->coeffs, (dst->maxDegree + 1) * sizeof(GFElement), 0, (dst->maxDegree + 1) * sizeof(GFElement));
    int32_t termsToCopy = (src->degree < dst->maxDegree) ? src->degree : dst->maxDegree;

    if (src->degree < 0) {
        dst->degree = -1;   // Sentinel assigned when source polynomial has no terms (source degree < 0)
        return PQCP_MCELIECE_INVALID_ARG;
    }

    for (int32_t i = 0; i <= termsToCopy; i++) {
        dst->coeffs[i] = src->coeffs[i];
    }

    dst->degree = termsToCopy;
    while (dst->degree >= 0 && dst->coeffs[dst->degree] == 0) {
        dst->degree--;
    }
}
