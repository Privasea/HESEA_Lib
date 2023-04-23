// @file UnitTestCKKS.cpp - Unit tests for the CKKS scheme
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <ctime>
#include <iostream>
#include <list>
#include <vector>
#include "gtest/gtest.h"

#include "cryptocontext.h"
#include "cryptocontextgen.h"
#include "cryptocontexthelper.h"
#include "hesea.h"
#include "utils/testcasegen.h"

using namespace std;
using namespace lbcrypto;

class UTCKKS : public ::testing::Test {
 public:
  const usint m = 16;
  UTCKKS() {}
  ~UTCKKS() {}

 protected:
  void SetUp() {}

  void TearDown() {
    CryptoContextFactory<Poly>::ReleaseAllContexts();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
  }
};

#if NATIVEINT == 128
#define GENERATE_TEST_CASES_FUNC_BV(x, y, ORD, SCALE, NUMPRIME, RELIN, BATCH) \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN,  \
                          BATCH, BV, APPROXRESCALE)                           \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN,  \
                          BATCH, BV, APPROXAUTO)

#define GENERATE_TEST_CASES_FUNC_GHS(x, y, ORD, SCALE, NUMPRIME, RELIN, BATCH) \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN,   \
                          BATCH, GHS, APPROXRESCALE)                           \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN,   \
                          BATCH, GHS, APPROXAUTO)

#define GENERATE_TEST_CASES_FUNC_HYBRID(x, y, ORD, SCALE, NUMPRIME, RELIN,   \
                                        BATCH)                               \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXRESCALE)                      \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXAUTO)

#else
#define GENERATE_TEST_CASES_FUNC_BV(x, y, ORD, SCALE, NUMPRIME, RELIN, BATCH) \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN,  \
                          BATCH, BV, APPROXRESCALE)                           \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN,  \
                          BATCH, BV, APPROXAUTO)                              \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN,  \
                          BATCH, BV, EXACTRESCALE)

#define GENERATE_TEST_CASES_FUNC_GHS(x, y, ORD, SCALE, NUMPRIME, RELIN, BATCH) \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN,   \
                          BATCH, GHS, APPROXRESCALE)                           \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN,   \
                          BATCH, GHS, APPROXAUTO)                              \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN,   \
                          BATCH, GHS, EXACTRESCALE)

#define GENERATE_TEST_CASES_FUNC_HYBRID(x, y, ORD, SCALE, NUMPRIME, RELIN,   \
                                        BATCH)                               \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXRESCALE)                      \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, APPROXAUTO)                         \
  GENERATE_CKKS_TEST_CASE(x, y, DCRTPoly, CKKS, ORD, SCALE, NUMPRIME, RELIN, \
                          BATCH, HYBRID, EXACTRESCALE)
#endif

/* *
 * ORDER: Cyclotomic order. Must be a power of 2 for CKKS.
 * NUMPRIME: Number of towers comprising the ciphertext modulus.
 * SCALE: Scaling factor bit-length.
 *       Should fit into a machine word, i.e., less than 64.
 * RELIN: The bit decomposition count used in BV relinearization.
 * BATCH: The length of the packed vectors to be used with CKKS.
 */
static const usint ORDER = 1024;  // 16384;
#if NATIVEINT == 128
static const usint SCALE = 90;
#else
static const usint SCALE = 50;
#endif
static const usint NUMPRIME = 8;
static const usint RELIN = 20;
static const usint BATCH = 8;

/**
 * This function checks whether vectors of approximate numbers a and b are
 * equal. This is useful for CKKS tests, because numbers are approximate, so
 * results will never be exactly as expected.
 *
 * @param vectorSize The length of the two vectors.
 * @param epsilon Minimum precision to consider a and b equal.
 *       E.g., a={0.1, 0.123} and b={0.1, 0.124} are equal for
 * epsilon = 0.01, but different for epsilon = 0.001.
 * @param failmsg Debug message to display upon failure.
 */
static void checkApproximateEquality(std::vector<std::complex<double>>& a,
                                     std::vector<std::complex<double>>& b,
                                     int vectorSize, double epsilon,
                                     const string& failmsg) {
  std::vector<std::complex<double>> allTrue(vectorSize);
  std::vector<std::complex<double>> tmp(vectorSize);
  for (int i = 0; i < vectorSize; i++) {
    allTrue[i] = 1;
    tmp[i] = abs(a[i] - b[i]) <= epsilon;
  }
  EXPECT_TRUE(tmp == allTrue) << failmsg;
}

/**
 * Tests whether addition for CKKS works properly.
 */
template <class Element>
static void UnitTest_Add_Packed(const CryptoContext<Element> cc,
                                const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
              cc->HESea_GetCryptoParameters());

  // The precision after which we consider two values equal.
  // This is necessary because CKKS works for approximate numbers.
  double eps = 0.000000001;

  // vectorOfInts1 = { 0,1,2,3,4,5,6,7 };
  std::vector<std::complex<double>> vectorOfInts1(vecSize);
  std::vector<std::complex<double>> negativeInts1(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts1[i] = i;
    negativeInts1[i] = -i;
  }
  Plaintext plaintext1 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts1);
  Plaintext negatives1 = cc->HESea_MakeCKKSPackedPlaintext(negativeInts1);

  // vectorOfInts2 = { 7,6,5,4,3,2,1,0 };
  std::vector<std::complex<double>> vectorOfInts2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts2[i] = vecSize - i - 1;
  }
  Plaintext plaintext2 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts2);

  // vectorOfIntsAdd = { 7,7,7,7,7,7,7,7 };
  std::vector<std::complex<double>> vectorOfIntsAdd(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfIntsAdd[i] = vecSize - 1;
  }
  Plaintext plaintextAdd = cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsAdd);

  // vectorOfIntsSub = { -7,-5,-3,-1,1,3,5,7 };
  std::vector<std::complex<double>> vectorOfIntsSub(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfIntsSub[i] = 2 * i - vecSize + 1;
  }
  Plaintext plaintextSub = cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsSub);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->HESea_Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ciphertext1_mutable =
      cc->HESea_Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ciphertext2 = cc->HESea_Encrypt(kp.publicKey, plaintext2);
  Ciphertext<Element> cResult;
  Plaintext results;

  /* Testing HESea_EvalAdd
   */
  cResult = cc->HESea_EvalAdd(ciphertext1, ciphertext2);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextAdd->GetLength());
  auto tmp_a = plaintextAdd->GetCKKSPackedValue();
  auto tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " HESea_EvalAdd fails");

  /* Testing EvalAddInPlace
   */
  cc->HESea_EvalAddInPlace(ciphertext1_mutable, ciphertext2);
  cc->HESea_Decrypt(kp.secretKey, ciphertext1_mutable, &results);
  results->SetLength(plaintextAdd->GetLength());
  tmp_a = plaintextAdd->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " EvalAddInPlace fails");

  /* Testing operator+
   */
  cResult = ciphertext1 + ciphertext2;
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextAdd->GetLength());
  tmp_a = plaintextAdd->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " operator+ fails");

  /* Testing operator+=
   */
  Ciphertext<Element> caddInplace(ciphertext1);
  caddInplace += ciphertext2;
  cc->HESea_Decrypt(kp.secretKey, caddInplace, &results);
  results->SetLength(plaintextAdd->GetLength());
  tmp_a = plaintextAdd->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " operator+= fails");

  /* Testing EvalSub
   */
  cResult = cc->HESea_EvalSub(ciphertext1, ciphertext2);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextSub->GetLength());
  tmp_a = plaintextSub->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " HESea_EvalSub fails");

  /* Testing operator-
   */
  cResult = ciphertext1 - ciphertext2;
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextSub->GetLength());
  tmp_a = plaintextSub->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " operator- fails");

  /* Testing operator-=
   */
  Ciphertext<Element> csubInplace(ciphertext1);
  csubInplace -= ciphertext2;
  cc->HESea_Decrypt(kp.secretKey, csubInplace, &results);
  results->SetLength(plaintextSub->GetLength());
  tmp_a = plaintextSub->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " operator-= fails");

  /* Testing HESea_EvalAdd ciphertext + plaintext
   */
  cResult = cc->HESea_EvalAdd(ciphertext1, plaintext2);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextAdd->GetLength());
  tmp_a = plaintextAdd->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " HESea_EvalAdd Ct and Pt fails");

  /* Testing HESea_EvalSub ciphertext - plaintext
   */
  cResult = cc->HESea_EvalSub(ciphertext1, plaintext2);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextSub->GetLength());
  tmp_a = plaintextSub->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " HESea_EvalSub Ct and Pt fails fails");

  /* Testing HESea_EvalNegate
   */
  cResult = cc->HESea_EvalNegate(ciphertext1);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(negatives1->GetLength());
  tmp_a = negatives1->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " HESea_EvalNegate fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_Add_Packed, ORDER, SCALE, NUMPRIME,
                            RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_Add_Packed, ORDER, SCALE,
                             NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_Add_Packed, ORDER, SCALE,
                                NUMPRIME, RELIN, BATCH)

/**
 * Tests whether multiplication for CKKS works properly.
 */
template <class Element>
static void UnitTest_Mult_Packed(const CryptoContext<Element> cc,
                                 const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
              cc->HESea_GetCryptoParameters());

  double eps = 0.000000001;

  // vectorOfInts1 = { 0,1,2,3,4,5,6,7 };
  std::vector<std::complex<double>> vectorOfInts1(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts1[i] = i;
  }
  Plaintext plaintext1 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts1);

  // vectorOfInts2 = { 7,6,5,4,3,2,1,0 };
  std::vector<std::complex<double>> vectorOfInts2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts2[i] = vecSize - i - 1;
  }
  Plaintext plaintext2 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts2);

  // vectorOfIntsMult = { 0,6,10,12,12,10,6,0 };
  std::vector<std::complex<double>> vectorOfIntsMult(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfIntsMult[i] = i * vecSize - i * i - i;
  }
  Plaintext plaintextMult = cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsMult);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  // Generate multiplication keys
  cc->HESea_EvalMultKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->HESea_Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ciphertext2 = cc->HESea_Encrypt(kp.publicKey, plaintext2);
  Ciphertext<Element> cResult;
  Plaintext results;

  /* Testing HESea_EvalMult
   */
  cc->HESea_EvalMult(ciphertext1, plaintext1);
  cc->HESea_EvalMult(ciphertext2, plaintext2);
  cResult = cc->HESea_EvalMult(ciphertext1, ciphertext2);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextMult->GetLength());
  auto tmp_a = plaintextMult->GetCKKSPackedValue();
  auto tmp_b = results->GetCKKSPackedValue();
  //  stringstream buffer;
  //  buffer << "p1: " << plaintext1 << ", p2: " << plaintext2 << ", expect: "
  //<< tmp_a << " - we get: " << tmp_b << endl;
  // checkApproximateEquality(tmp_a,
  // tmp_b, vecSize, eps, failmsg +       " HESea_EvalMult fails" +
  // buffer.str());
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " HESea_EvalMult fails");

  /* Testing operator*
   */
  cResult = ciphertext1 * ciphertext2;
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextMult->GetLength());
  tmp_a = plaintextMult->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " operator* fails");

  /* Testing operator*=
   */
  Ciphertext<Element> cmultInplace(ciphertext1);
  cmultInplace *= ciphertext2;
  cc->HESea_Decrypt(kp.secretKey, cmultInplace, &results);
  results->SetLength(plaintextMult->GetLength());
  tmp_a = plaintextMult->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " operator*= fails");

  /* Testing HESea_EvalMult ciphertext * plaintext
   */
  cResult = cc->HESea_EvalMult(ciphertext1, plaintext2);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextMult->GetLength());
  tmp_a = plaintextMult->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " HESea_EvalMult Ct and Pt fails");

  /* Testing HESea_EvalMultNoRelin ciphertext * ciphertext
   */
  cResult = cc->HESea_EvalMultNoRelin(ciphertext1, ciphertext2);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextMult->GetLength());
  tmp_a = plaintextMult->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " HESea_EvalMultNoRelin Ct and Ct fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_Mult_Packed, ORDER, SCALE,
                            NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_Mult_Packed, ORDER, SCALE,
                             NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_Mult_Packed, ORDER, SCALE,
                                NUMPRIME, RELIN, BATCH)

/**
 * Tests the correct operation of the following:
 * - addition/subtraction of constant to ciphertext of depth > 1
 * - addition/subtraction of plaintext to ciphertext of depth > 1
 * - encoding of plaintext at depth > 1
 * - automatic scaling up of plaintexts to a depth that matches that of a
 * ciphertext
 */
template <class Element>
static void UnitTest_ScaleFactorAdjustments(const CryptoContext<Element> cc,
                                            const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
              cc->HESea_GetCryptoParameters());

  double eps = 0.00000001;

  // vectorOfInts1 = { 0,1,2,3,4,5,6,7 };
  std::vector<std::complex<double>> vectorOfInts1(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts1[i] = i;
  }
  Plaintext plaintext1 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts1);

  // constantInts = { 11,11,11,11,11,11,11,11 };
  std::vector<std::complex<double>> constantInts(vecSize);
  for (int i = 0; i < vecSize; i++) {
    constantInts[i] = 11;
  }
  Plaintext plaintextConst = cc->HESea_MakeCKKSPackedPlaintext(constantInts);
  Plaintext plaintextConstDeep = cc->HESea_MakeCKKSPackedPlaintext(constantInts, 3);

  // constantInts2 = { -11,-11,-11,-11,-11,-11,-11,-11 };
  std::vector<std::complex<double>> constantInts2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    constantInts2[i] = -constantInts[i];
  }
  Plaintext plaintextConst2 = cc->HESea_MakeCKKSPackedPlaintext(constantInts2);
  Plaintext plaintextConst2Deep = cc->HESea_MakeCKKSPackedPlaintext(constantInts2, 3);

  // vectorOfInts2 = { 7,6,5,4,3,2,1,0 };
  std::vector<std::complex<double>> vectorOfInts2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts2[i] = vecSize - i - 1;
  }
  Plaintext plaintext2 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts2);

  // vectorOfInts3 = { 0,-1,-2,-3,-4,-5,-6,-7 };
  std::vector<std::complex<double>> vectorOfInts3(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts3[i] = -i;
  }
  Plaintext plaintext3 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts3);

  // vectorOfIntsMult = { 0,6,10,12,12,10,6,0 };
  std::vector<std::complex<double>> vectorOfIntsMult(vecSize);
  // vectorOfIntsMult2 = { 0,6,20,36,48,50,36,0 };
  std::vector<std::complex<double>> vectorOfIntsMult2(vecSize);
  // vectorOfIntsAddAfterMult = { 10,16,20,22,22,20,16,10 };
  std::vector<std::complex<double>> vectorOfIntsAddAfterMult(vecSize);
  // vectorOfIntsSubAfterMult = { -10,-4,0,2,2,0,-4,-10 };
  std::vector<std::complex<double>> vectorOfIntsSubAfterMult(vecSize);
  // vectorOfIntsAddAfterMult2 = { 11,17,31,47,59,61,47,11 };
  std::vector<std::complex<double>> vectorOfIntsAddAfterMult2(vecSize);
  // vectorOfIntsSubAfterMult2 = { -11,-5,9,25,37,39,25,-11 };
  std::vector<std::complex<double>> vectorOfIntsSubAfterMult2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfIntsMult[i] = i * vecSize - i * i - i;
    vectorOfIntsAddAfterMult[i] = vectorOfIntsMult[i] + complex<double>(10, 0);
    vectorOfIntsSubAfterMult[i] = vectorOfIntsMult[i] - complex<double>(10, 0);
    vectorOfIntsMult2[i] = vectorOfIntsMult[i] * vectorOfInts1[i];
    vectorOfIntsAddAfterMult2[i] =
        vectorOfIntsMult2[i] + constantInts[i];  // complex<double>({11,0});
    vectorOfIntsSubAfterMult2[i] =
        vectorOfIntsMult2[i] - constantInts[i];  // complex<double>({11,0});
  }
  Plaintext plaintextMult = cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsMult);
  Plaintext plaintexAddAfterMult =
          cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsAddAfterMult);
  Plaintext plaintexSubAfterMult =
          cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsSubAfterMult);
  Plaintext plaintexttMult2 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsMult2);
  Plaintext plaintexAddAfterMult2 =
          cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsAddAfterMult2);
  Plaintext plaintexSubAfterMult2 =
          cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsSubAfterMult2);
  Plaintext plaintex2AddAfterMult2 =
          cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsSubAfterMult2);
  Plaintext plaintex2SubAfterMult2 =
          cc->HESea_MakeCKKSPackedPlaintext(vectorOfIntsAddAfterMult2);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  // Generate multiplication keys
  cc->HESea_EvalMultKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->HESea_Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ciphertext2 = cc->HESea_Encrypt(kp.publicKey, plaintext2);
  Ciphertext<Element> cResult;
  Plaintext results;

  auto cMult = cc->HESea_EvalMult(ciphertext1, ciphertext2);
  auto cAddAfterMult = cc->HESea_EvalAdd(cMult, 10);
  auto cSubAfterMult = cc->HESea_EvalSub(cMult, 10);
  auto cMult2 = cc->HESea_EvalMult(ciphertext1, cMult);
  auto cAddAfterMult2 = cc->HESea_EvalAdd(cMult2, 11);
  auto cSubAfterMult2 = cc->HESea_EvalSub(cMult2, 11);
  auto c2AddAfterMult2 = cc->HESea_EvalAdd(cMult2, -11);
  auto c2SubAfterMult2 = cc->HESea_EvalSub(cMult2, -11);
  auto cAddPtAfterMult2 = cc->HESea_EvalAdd(cMult2, plaintextConst);
  auto cSubPtAfterMult2 = cc->HESea_EvalSub(cMult2, plaintextConst);
  auto cAddPt2AfterMult2 = cc->HESea_EvalAdd(cMult2, plaintextConst2);
  auto cSubPt2AfterMult2 = cc->HESea_EvalSub(cMult2, plaintextConst2);
  auto cDeepAdd = cc->HESea_EvalAdd(cMult2, plaintextConstDeep);
  auto cDeepSub = cc->HESea_EvalSub(cMult2, plaintextConstDeep);
  auto c2DeepAdd = cc->HESea_EvalAdd(cMult2, plaintextConst2Deep);
  auto c2DeepSub = cc->HESea_EvalSub(cMult2, plaintextConst2Deep);

  cc->HESea_Decrypt(kp.secretKey, cAddAfterMult, &results);
  results->SetLength(plaintexAddAfterMult->GetLength());
  auto tmp_a = plaintexAddAfterMult->GetCKKSPackedValue();
  auto tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " add after 1 multiplication fails");

  cc->HESea_Decrypt(kp.secretKey, cSubAfterMult, &results);
  results->SetLength(plaintexSubAfterMult->GetLength());
  tmp_a = plaintexSubAfterMult->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " subtract after 1 multiplication fails");

  cc->HESea_Decrypt(kp.secretKey, cAddAfterMult2, &results);
  results->SetLength(plaintexAddAfterMult2->GetLength());
  tmp_a = plaintexAddAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " add after 2 multiplications fails");

  cc->HESea_Decrypt(kp.secretKey, cSubAfterMult2, &results);
  results->SetLength(plaintexSubAfterMult2->GetLength());
  tmp_a = plaintexSubAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " subtract after 2 multiplications fails");

  cc->HESea_Decrypt(kp.secretKey, c2AddAfterMult2, &results);
  results->SetLength(plaintex2AddAfterMult2->GetLength());
  tmp_a = plaintex2AddAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  //  stringstream buffer;
  //  buffer << " we expect: " << tmp_a << endl;
  //  buffer << " we get: " << tmp_b << endl;
  //  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps, failmsg +
  //      " add (negative) after 2 multiplications fails: " +
  //      buffer.str());
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " add (negative) after 2 multiplications fails");

  cc->HESea_Decrypt(kp.secretKey, c2SubAfterMult2, &results);
  results->SetLength(plaintex2SubAfterMult2->GetLength());
  tmp_a = plaintex2SubAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  //  buffer.str("");
  //  buffer << " we expect: " << tmp_a << endl;
  //  buffer << " we get: " << tmp_b << endl;
  //  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps, failmsg +
  //      " subtract (negative) after 2 multiplications fails: " +
  //      buffer.str());
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " subtract (negative) after 2 multiplications fails");

  cc->HESea_Decrypt(kp.secretKey, cAddPtAfterMult2, &results);
  results->SetLength(plaintexAddAfterMult2->GetLength());
  tmp_a = plaintexAddAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg +
                               " add plaintext (auto scale factor matching) "
                               "after 2 multiplications fails");

  cc->HESea_Decrypt(kp.secretKey, cSubPtAfterMult2, &results);
  results->SetLength(plaintexSubAfterMult2->GetLength());
  tmp_a = plaintexSubAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg +
                               " subtract plaintext (auto scale factor "
                               "matching) after 2 multiplications fails");

  cc->HESea_Decrypt(kp.secretKey, cAddPt2AfterMult2, &results);
  results->SetLength(plaintex2AddAfterMult2->GetLength());
  tmp_a = plaintex2AddAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg +
                               " add negative plaintext (auto scale factor "
                               "matching) after 2 multiplications fails");

  cc->HESea_Decrypt(kp.secretKey, cSubPt2AfterMult2, &results);
  results->SetLength(plaintex2SubAfterMult2->GetLength());
  tmp_a = plaintex2SubAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg +
          " subtract negative plaintext (auto scale factor matching) after 2 "
          "multiplications fails");

  cc->HESea_Decrypt(kp.secretKey, cDeepAdd, &results);
  results->SetLength(plaintexAddAfterMult2->GetLength());
  tmp_a = plaintexAddAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " add with deep plaintext fails");

  cc->HESea_Decrypt(kp.secretKey, cDeepSub, &results);
  results->SetLength(plaintexSubAfterMult2->GetLength());
  tmp_a = plaintexSubAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " subtract with deep plaintext fails");

  cc->HESea_Decrypt(kp.secretKey, c2DeepAdd, &results);
  results->SetLength(plaintex2AddAfterMult2->GetLength());
  tmp_a = plaintex2AddAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " add with deep negative plaintext fails");

  cc->HESea_Decrypt(kp.secretKey, c2DeepSub, &results);
  results->SetLength(plaintex2SubAfterMult2->GetLength());
  tmp_a = plaintex2SubAfterMult2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " subtract with deep negative plaintext fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_ScaleFactorAdjustments, ORDER,
                            SCALE, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_ScaleFactorAdjustments, ORDER,
                             SCALE, NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_ScaleFactorAdjustments, ORDER,
                                SCALE, NUMPRIME, RELIN, BATCH)

template <typename Element>
static void UnitTest_AutoLevelReduce(const CryptoContext<Element> cc,
                                     const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
              cc->HESea_GetCryptoParameters());

  double eps = 0.000001;

  // vectorOfInts1 = { 0,1,2,3,4,5,6,7 };
  std::vector<std::complex<double>> vectorOfInts1(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts1[i] = i;
  }
  Plaintext plaintext1 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts1);

  // vectorOfInts2 = { 7,6,5,4,3,2,1,0 };
  std::vector<std::complex<double>> vectorOfInts2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts2[i] = vecSize - i - 1;
  }
  Plaintext plaintext2 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts2);

  std::vector<std::complex<double>> pCtMult(vecSize);
  std::vector<std::complex<double>> pCtMult3(vecSize);
  std::vector<std::complex<double>> pCt3(vecSize);
  std::vector<std::complex<double>> pCt3_b(vecSize);
  std::vector<std::complex<double>> pCt4(vecSize);
  std::vector<std::complex<double>> pCt5(vecSize);
  std::vector<std::complex<double>> pCt6(vecSize);
  std::vector<std::complex<double>> pCt7(vecSize);
  std::vector<std::complex<double>> pCt_5(vecSize);
  std::vector<std::complex<double>> pCt_6(vecSize);
  std::vector<std::complex<double>> pCt_7(vecSize);
  std::vector<std::complex<double>> pCt8(vecSize);
  std::vector<std::complex<double>> pCt9(vecSize);
  std::vector<std::complex<double>> pCt10(vecSize);
  std::vector<std::complex<double>> pCt11(vecSize);
  std::vector<std::complex<double>> pCt12(vecSize);
  std::vector<std::complex<double>> pCt13(vecSize);
  std::vector<std::complex<double>> pCt14(vecSize);
  for (int i = 0; i < vecSize; i++) {
    pCtMult[i] = vectorOfInts1[i] * vectorOfInts2[i];
    pCt3[i] = pCtMult[i] + vectorOfInts1[i];
    pCt4[i] = pCtMult[i] - vectorOfInts1[i];
    pCt5[i] = pCtMult[i] * vectorOfInts1[i];
    pCt6[i] = vectorOfInts1[i] + pCtMult[i];
    pCt7[i] = vectorOfInts1[i] - pCtMult[i];
    auto tmp = (vectorOfInts1[i] * vectorOfInts1[i] +
                vectorOfInts1[i] * vectorOfInts1[i]) *
               vectorOfInts1[i];
    pCt_5[i] = tmp + vectorOfInts2[i];
    pCt_6[i] = tmp - vectorOfInts2[i];
    pCt_7[i] = tmp * vectorOfInts2[i];
    pCt8[i] = vectorOfInts1[i] * pCtMult[i];
    pCtMult3[i] = pCtMult[i] * vectorOfInts1[i] * vectorOfInts1[i];
    pCt9[i] = pCtMult3[i] + vectorOfInts1[i];
    pCt10[i] = pCtMult3[i] - vectorOfInts1[i];
    pCt11[i] = pCtMult3[i] * vectorOfInts1[i];
    pCt12[i] = vectorOfInts1[i] + pCtMult3[i];
    pCt13[i] = vectorOfInts1[i] - pCtMult3[i];
    pCt14[i] = vectorOfInts1[i] * pCtMult3[i];
  }
  Plaintext plaintextCt3 = cc->HESea_MakeCKKSPackedPlaintext(pCt3);
  Plaintext plaintextCt4 = cc->HESea_MakeCKKSPackedPlaintext(pCt4);
  Plaintext plaintextCt5 = cc->HESea_MakeCKKSPackedPlaintext(pCt5);
  Plaintext plaintextCt6 = cc->HESea_MakeCKKSPackedPlaintext(pCt6);
  Plaintext plaintextCt7 = cc->HESea_MakeCKKSPackedPlaintext(pCt7);
  Plaintext plaintextCt_5 = cc->HESea_MakeCKKSPackedPlaintext(pCt_5);
  Plaintext plaintextCt_6 = cc->HESea_MakeCKKSPackedPlaintext(pCt_6);
  Plaintext plaintextCt_7 = cc->HESea_MakeCKKSPackedPlaintext(pCt_7);
  Plaintext plaintextCt8 = cc->HESea_MakeCKKSPackedPlaintext(pCt8);
  Plaintext plaintextCt9 = cc->HESea_MakeCKKSPackedPlaintext(pCt9);
  Plaintext plaintextCt10 = cc->HESea_MakeCKKSPackedPlaintext(pCt10);
  Plaintext plaintextCt11 = cc->HESea_MakeCKKSPackedPlaintext(pCt11);
  Plaintext plaintextCt12 = cc->HESea_MakeCKKSPackedPlaintext(pCt12);
  Plaintext plaintextCt13 = cc->HESea_MakeCKKSPackedPlaintext(pCt13);
  Plaintext plaintextCt14 = cc->HESea_MakeCKKSPackedPlaintext(pCt14);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  // Generate multiplication keys
  cc->HESea_EvalMultKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> ct = cc->HESea_Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ct2 = cc->HESea_Encrypt(kp.publicKey, plaintext2);
  Ciphertext<Element> cResult;
  Plaintext results;

  auto ctMul = cc->HESea_EvalMult(ct, ct2);
  auto ctRed = cc->HESea_ModReduce(ctMul);
  auto ctRedClone = ctRed->Clone();
  Ciphertext<Element> ctClone = ct->Clone();

  auto ct3 = cc->HESea_EvalAdd(ctRed, ct);  // Addition with tower diff = 1
  cc->HESea_Decrypt(kp.secretKey, ct3, &results);
  results->SetLength(plaintextCt3->GetLength());
  auto tmp_a = plaintextCt3->GetCKKSPackedValue();
  auto tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " addition with tower diff = 1 fails");

  // in-place addition with tower diff = 1
  cc->HESea_EvalAddInPlace(ctRedClone, ctClone);
  cc->HESea_Decrypt(kp.secretKey, ctRedClone, &results);
  results->SetLength(plaintextCt3->GetLength());
  tmp_a = plaintextCt3->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " in-place addition with tower diff = 1 fails");

  auto ct4 = cc->HESea_EvalSub(ctRed, ct);  // Subtraction with tower diff = 1
  cc->HESea_Decrypt(kp.secretKey, ct4, &results);
  results->SetLength(plaintextCt4->GetLength());
  tmp_a = plaintextCt4->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " subtraction with tower diff = 1 fails");

  auto ct5 = cc->HESea_EvalMult(ctRed, ct);  // Multiplication with tower diff = 1
  cc->HESea_Decrypt(kp.secretKey, ct5, &results);
  results->SetLength(plaintextCt5->GetLength());
  tmp_a = plaintextCt5->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " multiplication with tower diff = 1 fails");

  auto ct6 =
      cc->HESea_EvalAdd(ct, ctRed);  // Addition with tower diff = 1 (inputs reversed)
  cc->HESea_Decrypt(kp.secretKey, ct6, &results);
  results->SetLength(plaintextCt6->GetLength());
  tmp_a = plaintextCt6->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " addition (reverse) with tower diff = 1 fails");

  // in-place addition with tower diff = 1 (inputs reversed)
  ctClone = ct->Clone();
  cc->HESea_EvalAddInPlace(ctClone, ctRed);
  cc->HESea_Decrypt(kp.secretKey, ctClone, &results);
  results->SetLength(plaintextCt6->GetLength());
  tmp_a = plaintextCt6->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " in-place addition (reverse) with tower diff = 1 fails");

  auto ct7 = cc->HESea_EvalSub(
      ct, ctRed);  // Subtraction with tower diff = 1 (inputs reversed)
  cc->HESea_Decrypt(kp.secretKey, ct7, &results);
  results->SetLength(plaintextCt7->GetLength());
  tmp_a = plaintextCt7->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " subtraction (reverse) with tower diff = 1 fails");

  auto ct8 = cc->HESea_EvalMult(
      ct, ctRed);  // Multiplication with tower diff = 1 (inputs reversed)
  cc->HESea_Decrypt(kp.secretKey, ct8, &results);
  results->SetLength(plaintextCt8->GetLength());
  tmp_a = plaintextCt8->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " multiplication (reverse) with tower diff = 1 fails");

  auto ctMul2 = cc->HESea_EvalMult(ctRed, ct);
  auto ctRed2 = cc->HESea_ModReduce(ctMul2);
  auto ctMul3 = cc->HESea_EvalMult(ctRed2, ct);
  auto ctRed3 = cc->HESea_ModReduce(ctMul3);
  auto ctRed3Clone = ctRed3->Clone();

  auto ct9 =
      cc->HESea_EvalAdd(ctRed3, ct);  // Addition with more than 1 level difference
  cc->HESea_Decrypt(kp.secretKey, ct9, &results);
  results->SetLength(plaintextCt9->GetLength());
  tmp_a = plaintextCt9->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " addition with tower diff > 1 fails");

  // In-place addition with more than 1 level difference
  cc->HESea_EvalAddInPlace(ctRed3Clone, ct);
  cc->HESea_Decrypt(kp.secretKey, ctRed3Clone, &results);
  results->SetLength(plaintextCt9->GetLength());
  tmp_a = plaintextCt9->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " in-place addition with tower diff > 1 fails");

  auto ct10 =
      cc->HESea_EvalSub(ctRed3, ct);  // Subtraction with more than 1 level difference
  cc->HESea_Decrypt(kp.secretKey, ct10, &results);
  results->SetLength(plaintextCt10->GetLength());
  tmp_a = plaintextCt10->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " subtraction with tower diff > 1 fails");

  auto ct11 = cc->HESea_EvalMult(
      ctRed3, ct);  // Multiplication with more than 1 level difference
  cc->HESea_Decrypt(kp.secretKey, ct11, &results);
  results->SetLength(plaintextCt11->GetLength());
  tmp_a = plaintextCt11->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " multiplication with tower diff > 1 fails");

  auto ct12 = cc->HESea_EvalAdd(
      ct,
      ctRed3);  // Addition with more than 1 level difference (inputs reversed)
  cc->HESea_Decrypt(kp.secretKey, ct12, &results);
  results->SetLength(plaintextCt12->GetLength());
  tmp_a = plaintextCt12->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " addition (reverse) with tower diff > 1 fails");

  // In-place addition with more than 1 level difference (inputs reversed)
  ctClone = ct->Clone();
  cc->HESea_EvalAddInPlace(ctClone, ctRed3);
  cc->HESea_Decrypt(kp.secretKey, ctClone, &results);
  results->SetLength(plaintextCt12->GetLength());
  tmp_a = plaintextCt12->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " in-place addition (reverse) with tower diff > 1 fails");

  auto ct13 = cc->HESea_EvalSub(ct, ctRed3);  // Subtraction with more than 1 level
                                        // difference (inputs reversed)
  cc->HESea_Decrypt(kp.secretKey, ct13, &results);
  results->SetLength(plaintextCt13->GetLength());
  tmp_a = plaintextCt13->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " subtraction (reverse) with tower diff > 1 fails");

  auto ct14 = cc->HESea_EvalMult(ct, ctRed3);  // Multiplication with more than 1
                                         // level difference (inputs reversed)
  cc->HESea_Decrypt(kp.secretKey, ct14, &results);
  results->SetLength(plaintextCt14->GetLength());
  tmp_a = plaintextCt14->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " multiplication (reverse) with tower diff > 1 fails");

  // This scenario tests for operations on
  // ciphertext and plaintext that differ on
  // both scaling factor and number of towers.
  auto ct_1 = cc->HESea_EvalMult(ct, plaintext1);
  auto ct_2 = cc->HESea_EvalAdd(ct_1, ct_1);
  auto ct_3 = cc->HESea_ModReduce(ct_2);
  auto ct_4 = cc->HESea_EvalMult(ct_3, plaintext1);
  auto ct_5 = cc->HESea_EvalAdd(
      ct_4, plaintext2);  // Addition with plaintext and tower diff = 1
  auto ct_6 = cc->HESea_EvalSub(
      ct_4, plaintext2);  // Subtraction with plaintext and tower diff = 1
  auto ct_7 = cc->HESea_EvalMult(
      ct_4, plaintext2);  // Multiplication with plaintext and tower diff = 1
  cc->HESea_Decrypt(kp.secretKey, ct_5, &results);
  results->SetLength(plaintextCt_5->GetLength());
  tmp_a = plaintextCt_5->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " addition with plaintext and tower diff = 1 fails");

  cc->HESea_Decrypt(kp.secretKey, ct_6, &results);
  results->SetLength(plaintextCt_6->GetLength());
  tmp_a = plaintextCt_6->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " subtraction with plaintext and tower diff = 1 fails");

  cc->HESea_Decrypt(kp.secretKey, ct_7, &results);
  results->SetLength(plaintextCt_7->GetLength());
  tmp_a = plaintextCt_7->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " multiplication with plaintext and tower diff = 1 fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_AutoLevelReduce, ORDER, SCALE,
                            NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_AutoLevelReduce, ORDER, SCALE,
                             NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_AutoLevelReduce, ORDER, SCALE,
                                NUMPRIME, RELIN, BATCH)

template <typename Element>
static void UnitTest_Compress(const CryptoContext<Element> cc,
                              const string& failmsg) {
  int vecSize = 8;
  size_t targetTowers = 1;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
              cc->HESea_GetCryptoParameters());

  double eps = 0.000001;

  // vectorOfInts1 = { 0,1,2,3,4,5,6,7 };
  std::vector<std::complex<double>> vectorOfInts(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts[i] = i;
  }
  Plaintext plaintext = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  // Generate multiplication keys
  cc->HESea_EvalMultKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> ct = cc->HESea_Encrypt(kp.publicKey, plaintext);
  ct *= ct;
  Ciphertext<Element> cResult;
  Plaintext result;
  Plaintext resultCompressed;
  auto ctCompressed = cc->HESea_Compress(ct, targetTowers);

  size_t towersLeft = ctCompressed->GetElements()[0].GetNumOfElements();
  EXPECT_TRUE(towersLeft == targetTowers)
      << " compress fails - towers mismatch";

  cc->HESea_Decrypt(kp.secretKey, ct, &result);
  cc->HESea_Decrypt(kp.secretKey, ctCompressed, &resultCompressed);
  auto tmp_a = result->GetCKKSPackedValue();
  auto tmp_b = resultCompressed->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " compress fails - result is incorrect");
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_Compress, ORDER, SCALE, NUMPRIME,
                            RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_Compress, ORDER, SCALE, NUMPRIME,
                             RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_Compress, ORDER, SCALE,
                                NUMPRIME, RELIN, BATCH)

/**
 * Tests whether EvalFastRotate for CKKS works properly.
 */
template <class Element>
static void UnitTest_EvalFastRotation(const CryptoContext<Element> cc,
                                      const string& failmsg) {
  uint32_t N = cc->HESea_GetRingDimension();
  uint32_t Nh = N >> 1;
  uint32_t M = N << 1;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
              cc->HESea_GetCryptoParameters());

  double eps = 0.000000001;

  std::vector<std::complex<double>> vectorOfInts1(Nh);
  for (uint32_t i = 0; i < Nh; i++) {
    vectorOfInts1[i] = rand() % 10;
  }
  Plaintext plaintext1 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts1);

  std::vector<std::complex<double>> vOnes(Nh);
  for (uint32_t i = 0; i < Nh; i++) {
    vOnes[i] = 1;
  }
  Plaintext pOnes = cc->HESea_MakeCKKSPackedPlaintext(vOnes);

  std::vector<std::complex<double>> vIntsRightRotate2(Nh);
  for (uint32_t i = 0; i < Nh; i++) {
    vIntsRightRotate2[(i + Nh + 2) % Nh] = vectorOfInts1[i];
  }

  Plaintext plaintextRight2 = cc->HESea_MakeCKKSPackedPlaintext(vIntsRightRotate2);

  std::vector<std::complex<double>> vIntsLeftRotate2(Nh);
  for (uint32_t i = 0; i < Nh; i++) {
    vIntsLeftRotate2[(i + Nh - 2) % Nh] = vectorOfInts1[i];
  }
  Plaintext plaintextLeft2 = cc->HESea_MakeCKKSPackedPlaintext(vIntsLeftRotate2);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  // Generate multiplication keys
  cc->HESea_EvalMultKeyGen(kp.secretKey);
  // Generate rotation keys for offsets +2 (left rotate) and -2 (right rotate)
  cc->HESea_EvalAtIndexKeyGen(kp.secretKey, {2, -2});

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->HESea_Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> cOnes = cc->HESea_Encrypt(kp.publicKey, pOnes);
  Ciphertext<Element> cResult;
  Plaintext results;

  /* First, do one multiplication and apply the rotation to the result.
   * This helps hide the rotation noise and get the correct result without
   * using a smaller relinWindow in BV (when creating the crypto context cc).
   */
  ciphertext1 *= cOnes;

  /* Testing EvalFastRotate +2 (left rotate)
   */
  auto cPrecomp1 = cc->HESea_EvalFastRotationPrecompute(ciphertext1);
  cResult = cc->HESea_EvalFastRotation(ciphertext1, 2, M, cPrecomp1);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextLeft2->GetLength());
  auto tmp_a = plaintextLeft2->GetCKKSPackedValue();
  auto tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, Nh, eps,
                           failmsg + " EvalFastRotation(+2) fails");

  /* Testing EvalFastRotate -2 (right rotate)
   */
  cResult = cc->HESea_EvalFastRotation(ciphertext1, -2, M, cPrecomp1);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextRight2->GetLength());
  tmp_a = plaintextRight2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, Nh, eps,
                           failmsg + " EvalFastRotation(-2) fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_EvalFastRotation, ORDER, SCALE,
                            NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_EvalFastRotation, ORDER, SCALE,
                             NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_EvalFastRotation, ORDER, SCALE,
                                NUMPRIME, RELIN, BATCH)

/**
 * Tests whether EvalAtIndex for CKKS works properly.
 */
template <class Element>
static void UnitTest_EvalAtIndex(const CryptoContext<Element> cc,
                                 const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
              cc->HESea_GetCryptoParameters());

  double eps = 0.000000001;

  // vectorOfInts1 = { 1,2,3,4,5,6,7,8 };
  std::vector<std::complex<double>> vectorOfInts1(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vectorOfInts1[i] = i + 1;
  }
  Plaintext plaintext1 = cc->HESea_MakeCKKSPackedPlaintext(vectorOfInts1);

  // vOnes = { 1,1,1,1,1,1,1,1 };
  std::vector<std::complex<double>> vOnes(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vOnes[i] = 1;
  }
  Plaintext pOnes = cc->HESea_MakeCKKSPackedPlaintext(vOnes);

  // vIntsRightShift2 = { 0,0,1,2,3,4,5,6 };
  std::vector<std::complex<double>> vIntsRightShift2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vIntsRightShift2[i] = (i >= 2) ? vectorOfInts1[i - 2] : 0;
  }
  Plaintext plaintextRight2 = cc->HESea_MakeCKKSPackedPlaintext(vIntsRightShift2);

  // vIntsLeftShift2 = { 3,4,5,6,7,8,0,0 };
  std::vector<std::complex<double>> vIntsLeftShift2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vIntsLeftShift2[i] = (i < vecSize - 2) ? vectorOfInts1[i + 2] : 0;
  }
  Plaintext plaintextLeft2 = cc->HESea_MakeCKKSPackedPlaintext(vIntsLeftShift2);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  // Generate multiplication keys
  cc->HESea_EvalMultKeyGen(kp.secretKey);
  // Generate rotation keys for offsets +2 (left shift) and -2 (right shift)
  cc->HESea_EvalAtIndexKeyGen(kp.secretKey, {2, -2});

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->HESea_Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> cOnes = cc->HESea_Encrypt(kp.publicKey, pOnes);
  Ciphertext<Element> cResult;
  Plaintext results;

  /* First, do one multiplication and apply the rotation to the result.
   * This helps hide the rotation noise and get the correct result without
   * using a smaller relinWindow in BV (when creating the crypto context cc).
   */
  ciphertext1 *= cOnes;

  /* Testing EvalAtIndex +2
   */
  cResult = cc->HESea_EvalAtIndex(ciphertext1, 2);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextLeft2->GetLength());
  auto tmp_a = plaintextLeft2->GetCKKSPackedValue();
  auto tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " EvalAtIndex(+2) fails");

  /* Testing EvalAtIndex -2
   */
  cResult = cc->HESea_EvalAtIndex(ciphertext1, -2);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(plaintextRight2->GetLength());
  tmp_a = plaintextRight2->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " EvalAtIndex(-2) fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_EvalAtIndex, ORDER, SCALE,
                            NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_EvalAtIndex, ORDER, SCALE,
                             NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_EvalAtIndex, ORDER, SCALE,
                                NUMPRIME, RELIN, BATCH)

/**
 * Tests whether EvalMerge for CKKS works properly.
 */
template <class Element>
static void UnitTest_EvalMerge(const CryptoContext<Element> cc,
                               const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
              cc->HESea_GetCryptoParameters());

  double eps = 0.000000001;

  // v* = { i,0,0,0,0,0,0,0 };
  std::vector<std::complex<double>> vOne(vecSize);
  std::vector<std::complex<double>> vTwo(vecSize);
  std::vector<std::complex<double>> vThree(vecSize);
  std::vector<std::complex<double>> vFour(vecSize);
  std::vector<std::complex<double>> vFive(vecSize);
  std::vector<std::complex<double>> vSix(vecSize);
  std::vector<std::complex<double>> vSeven(vecSize);
  std::vector<std::complex<double>> vEight(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vOne[i] = (i == 0) ? 1 : 0;
    vTwo[i] = (i == 0) ? 2 : 0;
    vThree[i] = (i == 0) ? 3 : 0;
    vFour[i] = (i == 0) ? 4 : 0;
    vFive[i] = (i == 0) ? 5 : 0;
    vSix[i] = (i == 0) ? 6 : 0;
    vSeven[i] = (i == 0) ? 7 : 0;
    vEight[i] = (i == 0) ? 8 : 0;
  }
  Plaintext pOne = cc->HESea_MakeCKKSPackedPlaintext(vOne);
  Plaintext pTwo = cc->HESea_MakeCKKSPackedPlaintext(vTwo);
  Plaintext pThree = cc->HESea_MakeCKKSPackedPlaintext(vThree);
  Plaintext pFour = cc->HESea_MakeCKKSPackedPlaintext(vFour);
  Plaintext pFive = cc->HESea_MakeCKKSPackedPlaintext(vFive);
  Plaintext pSix = cc->HESea_MakeCKKSPackedPlaintext(vSix);
  Plaintext pSeven = cc->HESea_MakeCKKSPackedPlaintext(vSeven);
  Plaintext pEight = cc->HESea_MakeCKKSPackedPlaintext(vEight);

  // vMerged = { 1,2,3,4,5,6,7,8 };
  std::vector<std::complex<double>> vMerged(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vMerged[i] = i + 1;
  }
  Plaintext pMerged = cc->HESea_MakeCKKSPackedPlaintext(vMerged);

  std::vector<std::complex<double>> vOnes(vecSize);
  for (int i = 0; i < vecSize; i++) {
    vOnes[i] = 1;
  }
  Plaintext pOnes = cc->HESea_MakeCKKSPackedPlaintext(vOnes);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  // Generate multiplication keys
  cc->HESea_EvalMultKeyGen(kp.secretKey);
  // Generate rotation keys for all right rotations 1 to 8.
  vector<int32_t> indexList = {-1, -2, -3, -4, -5, -6, -7, -8};
  cc->HESea_EvalAtIndexKeyGen(kp.secretKey, indexList);

  // Encrypt plaintexts
  Ciphertext<Element> cOnes = cc->HESea_Encrypt(kp.publicKey, pOnes);
  std::vector<Ciphertext<Element>> ciphertexts;

  // Here, we perform the same trick (mult with one) as in
  // UnitTest_EvalAtiIndex.
  ciphertexts.push_back(cc->HESea_Encrypt(kp.publicKey, pOne) * cOnes);
  ciphertexts.push_back(cc->HESea_Encrypt(kp.publicKey, pTwo) * cOnes);
  ciphertexts.push_back(cc->HESea_Encrypt(kp.publicKey, pThree) * cOnes);
  ciphertexts.push_back(cc->HESea_Encrypt(kp.publicKey, pFour) * cOnes);
  ciphertexts.push_back(cc->HESea_Encrypt(kp.publicKey, pFive) * cOnes);
  ciphertexts.push_back(cc->HESea_Encrypt(kp.publicKey, pSix) * cOnes);
  ciphertexts.push_back(cc->HESea_Encrypt(kp.publicKey, pSeven) * cOnes);
  ciphertexts.push_back(cc->HESea_Encrypt(kp.publicKey, pEight) * cOnes);
  Plaintext results;

  /* Testing EvalMerge
   */
  auto cResult = cc->HESea_EvalMerge(ciphertexts);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);
  results->SetLength(pMerged->GetLength());
  auto tmp_a = pMerged->GetCKKSPackedValue();
  auto tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " EvalMerge fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_EvalMerge, ORDER, SCALE, NUMPRIME,
                            RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_EvalMerge, ORDER, SCALE, NUMPRIME,
                             RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_EvalMerge, ORDER, SCALE,
                                NUMPRIME, RELIN, BATCH)

/**
 * Tests whether HESea_EvalLinearWSum for CKKS works properly.
 */
template <class Element>
static void UnitTest_EvalLinearWSum(const CryptoContext<Element> cc,
                                    const string& failmsg) {
  int vecSize = 8;

  const auto cryptoParams =
      std::static_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
              cc->HESea_GetCryptoParameters());

  double eps = 0.0000000001;

  vector<double> weights(3);
  for (int i = 0; i < 3; i++) {
    weights[i] = i;
  }
  vector<complex<double>> in1(vecSize);
  vector<complex<double>> in2(vecSize);
  vector<complex<double>> in3(vecSize);
  vector<complex<double>> out(vecSize);
  for (int i = 0; i < vecSize; i++) {
    in1[i] = 3;
    in2[i] = 2;
    in3[i] = 1;
    out[i] = weights[0] * in1[i] + weights[1] * in2[i] + weights[2] * in3[i];
  }
  Plaintext pIn1 = cc->HESea_MakeCKKSPackedPlaintext(in1);
  Plaintext pIn2 = cc->HESea_MakeCKKSPackedPlaintext(in2);
  Plaintext pIn3 = cc->HESea_MakeCKKSPackedPlaintext(in3);
  Plaintext pOut = cc->HESea_MakeCKKSPackedPlaintext(out);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  // Generate multiplication keys
  cc->HESea_EvalMultKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> cIn1 = cc->HESea_Encrypt(kp.publicKey, pIn1);
  Ciphertext<Element> cIn2 = cc->HESea_Encrypt(kp.publicKey, pIn2);
  Ciphertext<Element> cIn3 = cc->HESea_Encrypt(kp.publicKey, pIn3);
  vector<Ciphertext<Element>> ciphertexts(3);

  ciphertexts[0] = cIn1;
  ciphertexts[1] = cIn2;
  ciphertexts[2] = cIn3;

  Plaintext results;

  auto cResult = cc->HESea_EvalLinearWSum(ciphertexts, weights);
  cc->HESea_Decrypt(kp.secretKey, cResult, &results);

  results->SetLength(pOut->GetLength());
  auto tmp_a = pOut->GetCKKSPackedValue();
  auto tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " HESea_EvalLinearWSum fails");

  auto cResult2 = cc->HESea_EvalLinearWSumMutable(ciphertexts, weights);
  cc->HESea_Decrypt(kp.secretKey, cResult2, &results);

  results->SetLength(pOut->GetLength());
  tmp_a = pOut->GetCKKSPackedValue();
  tmp_b = results->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, vecSize, eps,
                           failmsg + " EvalLinearWSumMutable fails");
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_EvalLinearWSum, ORDER, SCALE,
                            NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_EvalLinearWSum, ORDER, SCALE,
                             NUMPRIME, RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_EvalLinearWSum, ORDER, SCALE,
                                NUMPRIME, RELIN, BATCH)

template <typename Element>
static void UnitTest_ReEncryption(const CryptoContext<Element> cc,
                                  const string& failmsg) {
  size_t vecSize = 128;
  double eps = 0.01;

  auto ptm = 10;

  std::vector<std::complex<double>> intvec;
  for (size_t ii = 0; ii < vecSize; ii++) {
    intvec.push_back((rand() % (ptm / 2)) * (rand() % 2 ? 1 : -1));
  }
  Plaintext plaintextInt = cc->HESea_MakeCKKSPackedPlaintext(intvec);

  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  EXPECT_EQ(kp.good(), true)
      << failmsg << " key generation for scalar encrypt/decrypt failed";

  LPKeyPair<Element> newKp = cc->HESea_KeyGen();
  EXPECT_EQ(newKp.good(), true)
      << failmsg << " second key generation for scalar encrypt/decrypt failed";

  // This generates the keys which are used to perform the key switching.
  LPEvalKey<Element> evalKey;
  evalKey = cc->HESea_ReKeyGen(newKp.publicKey, kp.secretKey);

  Ciphertext<Element> ciphertext = cc->HESea_Encrypt(kp.publicKey, plaintextInt);
  Plaintext plaintextIntNew;
  Ciphertext<Element> reCiphertext = cc->HESea_ReEncrypt(evalKey, ciphertext);
  cc->HESea_Decrypt(newKp.secretKey, reCiphertext, &plaintextIntNew);
  plaintextIntNew->SetLength(plaintextInt->GetLength());
  auto tmp_a = plaintextIntNew->GetCKKSPackedValue();
  auto tmp_b = plaintextInt->GetCKKSPackedValue();
  stringstream buffer;
  buffer << tmp_b << " - we get: " << tmp_a << endl;
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " ReEncrypt integer plaintext " + buffer.str());

  stringstream buffer2;
  Ciphertext<Element> ciphertext2 = cc->HESea_Encrypt(kp.publicKey, plaintextInt);
  Plaintext plaintextIntNew2;
  Ciphertext<Element> reCiphertext2 =
      cc->HESea_ReEncrypt(evalKey, ciphertext2, kp.publicKey);
  cc->HESea_Decrypt(newKp.secretKey, reCiphertext2, &plaintextIntNew2);
  plaintextIntNew2->SetLength(plaintextInt->GetLength());
  tmp_a = plaintextIntNew2->GetCKKSPackedValue();
  tmp_b = plaintextInt->GetCKKSPackedValue();
  buffer2 << tmp_b << " - we get: " << tmp_a << endl;
  checkApproximateEquality(
      tmp_a, tmp_b, vecSize, eps,
      failmsg + " HRA-secure ReEncrypt integer plaintext " + buffer2.str());
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_ReEncryption, ORDER, SCALE,
                            NUMPRIME, RELIN, BATCH)

/**
 * Tests whether EvalPoly for CKKS works properly.
 */
template <class Element>
static void UnitTest_EvalPoly(const CryptoContext<Element> cc,
                              const string& failmsg) {
  const shared_ptr<LPCryptoParametersCKKS<DCRTPoly>> cryptoParams =
      std::dynamic_pointer_cast<LPCryptoParametersCKKS<DCRTPoly>>(
              cc->HESea_GetCryptoParameters());

  // The precision after which we consider two values equal.
  // This is necessary because CKKS works for approximate numbers.
  double eps = 0.0;
  if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE &&
      cryptoParams->GetKeySwitchTechnique() == BV)
    eps = 0.001;
  else if (cryptoParams->GetRescalingTechnique() == APPROXRESCALE &&
           cryptoParams->GetKeySwitchTechnique() == GHS)
    eps = 0.001;
  else if (cryptoParams->GetRescalingTechnique() == EXACTRESCALE &&
           cryptoParams->GetKeySwitchTechnique() == BV)
    eps = 0.001;
  else  // EXACTRESCALE && GHS
    eps = 0.001;

  // Encode inputs as CKKS inputs.

  std::vector<std::complex<double>> input({0.5, 0.7, 0.9, 0.95, 0.93});

  size_t encodedLength = input.size();

  // with only positive coefficients
  // x^16 + x^11 + 2 x^9 + x^8 + x^6 + 1.25 x^3 + 0.75*x + 0.15
  std::vector<double> coefficients1(
      {0.15, 0.75, 0, 1.25, 0, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0, 0, 1});
  // x^16 + x^11 + 2 x^9 - x^8 + x^6 + 1.25 x^3 - 0.75*x + 0.15
  // with negative coefficients
  std::vector<double> coefficients2(
      {0.15, -0.75, 0, 1.25, 0, 0, 1, 0, -1, 2, 0, 1, 0, 0, 0, 0, 1});
  // x^16
  // power function
  std::vector<double> coefficients3(
      {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
  // x^16 + x^11 + 2 x^9 - x^8 + x^6 - 1.25 x^5 + 1.25 x^3 - 1.75*x + 0.15
  // with negative coefficients with magnitude greater than 1
  std::vector<double> coefficients4(
      {0.15, -1.75, 0, 1.25, 0, -1.25, 1, 0, -1, 2, 0, 1, 0, 0, 0, 0, 1});
  // x + x^2 - x^3
  // low-degree function to check linear implementation
  std::vector<double> coefficients5({0, 1, 1, -1});

  Plaintext plaintext1 = cc->HESea_MakeCKKSPackedPlaintext(input);

  std::vector<std::complex<double>> output1(
      {0.705191, 1.38285, 3.97211, 5.60216, 4.86358});
  Plaintext plaintextResult1 = cc->HESea_MakeCKKSPackedPlaintext(output1);

  std::vector<std::complex<double>> output2(
      {-0.0526215, 0.217555, 1.76118, 2.85032, 2.34941});
  Plaintext plaintextResult2 = cc->HESea_MakeCKKSPackedPlaintext(output2);

  std::vector<std::complex<double>> output3(
      {0.0000152588, 0.00332329, 0.185302, 0.440127, 0.313132});
  Plaintext plaintextResult3 = cc->HESea_MakeCKKSPackedPlaintext(output3);

  std::vector<std::complex<double>> output4(
      {-0.59168396, -0.69253274, 0.12306489, 0.93308964, 0.54980166});
  Plaintext plaintextResult4 = cc->HESea_MakeCKKSPackedPlaintext(output4);

  std::vector<std::complex<double>> output5(
      {0.625, 0.847, 0.9809999999, 0.995125, 0.990543});
  Plaintext plaintextResult5 = cc->HESea_MakeCKKSPackedPlaintext(output5);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  // Generate multiplication keys
  cc->HESea_EvalMultKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->HESea_Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> cResult1, cResult2, cResult3, cResult4, cResult5;
  Plaintext results1, results2, results3, results4, results5;

  /* Testing EvalPoly
   */
  cResult1 = cc->HESea_EvalPoly(ciphertext1, coefficients1);
  cc->HESea_Decrypt(kp.secretKey, cResult1, &results1);
  results1->SetLength(encodedLength);
  auto tmp_a = plaintextResult1->GetCKKSPackedValue();
  auto tmp_b = results1->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, encodedLength, eps,
      failmsg + " EvalPoly with positive coefficients failed");

  cResult2 = cc->HESea_EvalPoly(ciphertext1, coefficients2);
  cc->HESea_Decrypt(kp.secretKey, cResult2, &results2);
  results2->SetLength(encodedLength);
  tmp_a = plaintextResult2->GetCKKSPackedValue();
  tmp_b = results2->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, encodedLength, eps,
      failmsg + " EvalPoly with negative coefficients failed");

  cResult3 = cc->HESea_EvalPoly(ciphertext1, coefficients3);
  cc->HESea_Decrypt(kp.secretKey, cResult3, &results3);
  results3->SetLength(encodedLength);
  tmp_a = plaintextResult3->GetCKKSPackedValue();
  tmp_b = results3->GetCKKSPackedValue();
  checkApproximateEquality(tmp_a, tmp_b, encodedLength, eps,
                           failmsg + " EvalPoly for a power function failed");

  cResult4 = cc->HESea_EvalPoly(ciphertext1, coefficients4);
  cc->HESea_Decrypt(kp.secretKey, cResult4, &results4);
  results4->SetLength(encodedLength);
  tmp_a = plaintextResult4->GetCKKSPackedValue();
  tmp_b = results4->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, encodedLength, eps,
      failmsg +
          " EvalPoly for negative coefficients with magnitude > 1 failed");

  cResult5 = cc->HESea_EvalPoly(ciphertext1, coefficients5);
  cc->HESea_Decrypt(kp.secretKey, cResult5, &results5);
  results5->SetLength(encodedLength);
  tmp_a = plaintextResult5->GetCKKSPackedValue();
  tmp_b = results5->GetCKKSPackedValue();
  checkApproximateEquality(
      tmp_a, tmp_b, encodedLength, eps,
      failmsg + " EvalPoly for low-degree polynomial failed");
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_EvalPoly, 1024, 35, 6, 20, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_EvalPoly, 1024, 35, 6, 20, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_EvalPoly, 1024, 35, 6, 20,
                                BATCH)

/**
 * Tests whether metadata is carried over for several operations in CKKS
 */
template <typename Element>
static void UnitTest_Metadata(const CryptoContext<Element> cc,
                              const string& failmsg) {
  int vecSize = 8;

  // input 1 = { 0,1,2,3,4,5,6,7 };
  // input 2 = { 0,-1,-2,-3,-4,-5,-6,-7 };
  std::vector<std::complex<double>> input1(vecSize);
  std::vector<std::complex<double>> input2(vecSize);
  for (int i = 0; i < vecSize; i++) {
    input1[i] = i;
    input2[i] = -i;
  }
  Plaintext plaintext1 = cc->HESea_MakeCKKSPackedPlaintext(input1);
  Plaintext plaintext2 = cc->HESea_MakeCKKSPackedPlaintext(input2);

  // Generate encryption keys
  LPKeyPair<Element> kp = cc->HESea_KeyGen();
  // Generate multiplication keys
  cc->HESea_EvalMultKeyGen(kp.secretKey);
  // Generate rotation keys for offsets +2 (left rotate) and -2 (right rotate)
  cc->HESea_EvalAtIndexKeyGen(kp.secretKey, {2, -2});
  // Generate keys for EvalSum
  cc->HESea_EvalSumKeyGen(kp.secretKey);

  // Encrypt plaintexts
  Ciphertext<Element> ciphertext1 = cc->HESea_Encrypt(kp.publicKey, plaintext1);
  Ciphertext<Element> ciphertext2 = cc->HESea_Encrypt(kp.publicKey, plaintext2);
  Plaintext results;

  // Populating metadata map in ciphertexts
  auto val1 = make_shared<MetadataTest>();
  val1->SetMetadata("ciphertext1");
  MetadataTest::StoreMetadata<Element>(ciphertext1, val1);
  auto val2 = make_shared<MetadataTest>();
  val2->SetMetadata("ciphertext2");
  MetadataTest::StoreMetadata<Element>(ciphertext2, val2);

  // Checking if metadata is carried over in HESea_EvalAdd(ctx,ctx)
  Ciphertext<Element> cAddCC = cc->HESea_EvalAdd(ciphertext1, ciphertext2);
  auto addCCValTest = MetadataTest::GetMetadata<Element>(cAddCC);
  EXPECT_EQ(val1->GetMetadata(), addCCValTest->GetMetadata())
      << "Ciphertext metadata mismatch in HESea_EvalAdd(ctx,ctx)";

  // Checking if metadata is carried over in HESea_EvalAdd(ctx,ctx)
  Ciphertext<Element> ciphertext1Clone = ciphertext1->Clone();
  cc->HESea_EvalAddInPlace(ciphertext1, ciphertext2);
  auto addCCInPlaceValTest =
      MetadataTest::GetMetadata<Element>(ciphertext1Clone);
  EXPECT_EQ(val1->GetMetadata(), addCCInPlaceValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalAddInPlace(ctx,ctx)";

  // Checking if metadata is carried over in HESea_EvalAdd(ctx,ptx)
  Ciphertext<Element> cAddCP = cc->HESea_EvalAdd(ciphertext1, plaintext1);
  auto addCPValTest = MetadataTest::GetMetadata<Element>(cAddCP);
  EXPECT_EQ(val1->GetMetadata(), addCPValTest->GetMetadata())
      << "Ciphertext metadata mismatch in HESea_EvalAdd(ctx,ptx)";

  // Checking if metadata is carried over in HESea_EvalAdd(ctx,double)
  Ciphertext<Element> cAddCD = cc->HESea_EvalAdd(ciphertext1, 2.0);
  auto addCDValTest = MetadataTest::GetMetadata<Element>(cAddCD);
  EXPECT_EQ(val1->GetMetadata(), addCDValTest->GetMetadata())
      << "Ciphertext metadata mismatch in HESea_EvalAdd(ctx,double)";

  // Checking if metadata is carried over in EvalSub(ctx,ctx)
  Ciphertext<Element> cSubCC = cc->HESea_EvalSub(ciphertext1, ciphertext2);
  auto subCCValTest = MetadataTest::GetMetadata<Element>(cSubCC);
  EXPECT_EQ(val1->GetMetadata(), subCCValTest->GetMetadata())
      << "Ciphertext metadata mismatch in HESea_EvalSub(ctx,ctx)";

  // Checking if metadata is carried over in HESea_EvalSub(ctx,ptx)
  Ciphertext<Element> cSubCP = cc->HESea_EvalSub(ciphertext1, plaintext1);
  auto subCPValTest = MetadataTest::GetMetadata<Element>(cSubCP);
  EXPECT_EQ(val1->GetMetadata(), subCPValTest->GetMetadata())
      << "Ciphertext metadata mismatch in HESea_EvalSub(ctx,ptx)";

  // Checking if metadata is carried over in HESea_EvalSub(ctx,double)
  Ciphertext<Element> cSubCD = cc->HESea_EvalSub(ciphertext1, 2.0);
  auto subCDValTest = MetadataTest::GetMetadata<Element>(cSubCD);
  EXPECT_EQ(val1->GetMetadata(), subCDValTest->GetMetadata())
      << "Ciphertext metadata mismatch in HESea_EvalSub(ctx,double)";

  // Checking if metadata is carried over in HESea_EvalMult(ctx,ctx)
  Ciphertext<Element> cMultCC = cc->HESea_EvalMult(ciphertext1, ciphertext2);
  auto multCCValTest = MetadataTest::GetMetadata<Element>(cMultCC);
  EXPECT_EQ(val1->GetMetadata(), multCCValTest->GetMetadata())
      << "Ciphertext metadata mismatch in HESea_EvalMult(ctx,ctx)";

  // Checking if metadata is carried over in HESea_EvalMult(ctx,ptx)
  Ciphertext<Element> cMultCP = cc->HESea_EvalMult(ciphertext1, plaintext1);
  auto multCPValTest = MetadataTest::GetMetadata<Element>(cMultCP);
  EXPECT_EQ(val1->GetMetadata(), multCPValTest->GetMetadata())
      << "Ciphertext metadata mismatch in HESea_EvalMult(ctx,ptx)";

  // Checking if metadata is carried over in HESea_EvalMult(ctx,double)
  Ciphertext<Element> cMultCD = cc->HESea_EvalMult(ciphertext1, 2.0);
  auto multCDValTest = MetadataTest::GetMetadata<Element>(cMultCD);
  EXPECT_EQ(val1->GetMetadata(), multCDValTest->GetMetadata())
      << "Ciphertext metadata mismatch in HESea_EvalMult(ctx,double)";

  // Checking if metadata is carried over in EvalAtIndex +2 (left rotate)
  auto cAtIndex2 = cc->HESea_EvalAtIndex(ciphertext1, 2);
  auto atIndex2ValTest = MetadataTest::GetMetadata<Element>(cAtIndex2);
  EXPECT_EQ(val1->GetMetadata(), atIndex2ValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalAtIndex +2";

  // Checking if metadata is carried over in EvalAtIndex -2 (right rotate)
  auto cAtIndexMinus2 = cc->HESea_EvalAtIndex(ciphertext1, -2);
  auto atIndexMinus2ValTest =
      MetadataTest::GetMetadata<Element>(cAtIndexMinus2);
  EXPECT_EQ(val1->GetMetadata(), atIndexMinus2ValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalAtIndex -2";

  uint32_t N = cc->HESea_GetRingDimension();
  uint32_t M = N << 1;

  // Checking if metadata is carried over EvalFastRotate +2 (left rotate)
  auto cPrecomp1 = cc->HESea_EvalFastRotationPrecompute(ciphertext1);
  auto cFastRot2 = cc->HESea_EvalFastRotation(ciphertext1, 2, M, cPrecomp1);
  auto fastRot2ValTest = MetadataTest::GetMetadata<Element>(cFastRot2);
  EXPECT_EQ(val1->GetMetadata(), fastRot2ValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalFastRotation +2";

  // Checking if metadata is carried over EvalFastRotate -2 (right rotate)
  auto cFastRotMinus2 = cc->HESea_EvalFastRotation(ciphertext1, -2, M, cPrecomp1);
  auto fastRotMinus2ValTest =
      MetadataTest::GetMetadata<Element>(cFastRotMinus2);
  EXPECT_EQ(val1->GetMetadata(), fastRotMinus2ValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalFastRotation -2";

  vector<double> weights(2);
  for (int i = 0; i < 2; i++) weights[i] = i;

  vector<Ciphertext<Element>> ciphertexts(2);
  ciphertexts[0] = ciphertext1;
  ciphertexts[1] = ciphertext2;

  // Checking if metadata is carried over in HESea_EvalLinearWSum
  auto cLWS = cc->HESea_EvalLinearWSum(ciphertexts, weights);
  auto lwsValTest = MetadataTest::GetMetadata<Element>(cLWS);
  EXPECT_EQ(val1->GetMetadata(), lwsValTest->GetMetadata())
      << "Ciphertext metadata mismatch in HESea_EvalLinearWSum";

  // Checking if metadata is carried over in EvalSum
  auto cSum = cc->HESea_EvalSum(ciphertext1, vecSize);
  auto sumValTest = MetadataTest::GetMetadata<Element>(cSum);
  EXPECT_EQ(val1->GetMetadata(), sumValTest->GetMetadata())
      << "Ciphertext metadata mismatch in EvalSum";
}

GENERATE_TEST_CASES_FUNC_BV(UTCKKS, UnitTest_Metadata, ORDER, SCALE, NUMPRIME,
                            RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_GHS(UTCKKS, UnitTest_Metadata, ORDER, SCALE, NUMPRIME,
                             RELIN, BATCH)
GENERATE_TEST_CASES_FUNC_HYBRID(UTCKKS, UnitTest_Metadata, ORDER, SCALE,
                                NUMPRIME, RELIN, BATCH)
