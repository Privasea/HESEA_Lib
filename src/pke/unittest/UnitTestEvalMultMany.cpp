// @file
// @author TPOC: 
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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

#include <fstream>
#include <iostream>
#include "gtest/gtest.h"

#include "cryptocontext.h"

#include "encoding/encodings.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestEvalMultMany : public ::testing::Test {
 protected:
  virtual void SetUp() {}

  virtual void TearDown() {}

 public:
};

static CryptoContext<Poly> MakeBFVPolyCC() {
  DEBUG_FLAG(false);
  DEBUG("in MakeBFVPolyCC");
  int relWindow = 8;
  int plaintextModulus = 256;
  double sigma = 4;
  double rootHermiteFactor = 1.6;

  // Set Crypto Parameters
  CryptoContext<Poly> cryptoContext =
      CryptoContextFactory<Poly>::genCryptoContextBFV(
          plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 3, 0,
          OPTIMIZED, 4);

  cryptoContext->HESea_Enable(ENCRYPTION);
  cryptoContext->HESea_Enable(SHE);
  DEBUG("DONEMakeBFVPolyCC");
  return cryptoContext;
}

static CryptoContext<DCRTPoly> MakeBFVrnsDCRTPolyCC() {
  int plaintextModulus = 256;
  double sigma = 4;
  double rootHermiteFactor = 1.03;

  // Set Crypto Parameters
  CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          plaintextModulus, rootHermiteFactor, sigma, 0, 3, 0, OPTIMIZED, 4);

  cryptoContext->HESea_Enable(ENCRYPTION);
  cryptoContext->HESea_Enable(SHE);

  return cryptoContext;
}

template <typename Element>
static void RunEvalMultManyTest(CryptoContext<Element> cc, string msg);

// Tests HESea_EvalMult w/o keyswitching and HESea_EvalMultMany for BFV in the
// OPTIMIZED mode
TEST(UTBFVEVALMM, Poly_BFV_Eval_Mult_Many_Operations_VERY_LONG) {
  RunEvalMultManyTest(MakeBFVPolyCC(), "BFV");
}

// Tests HESea_EvalMult w/o keyswitching and HESea_EvalMultMany for BFVrns in the
// OPTIMIZED mode
TEST(UTBFVrnsEVALMM, Poly_BFVrns_Eval_Mult_Many_Operations) {
  RunEvalMultManyTest(MakeBFVrnsDCRTPolyCC(), "BFVrns");
}

template <typename Element>
static void RunEvalMultManyTest(CryptoContext<Element> cryptoContext,
                                string msg) {
  DEBUG_FLAG(false);
  ////////////////////////////////////////////////////////////
  // Perform the key generation operation.
  ////////////////////////////////////////////////////////////
  DEBUG("In RunEvalMultManyTest " << msg);
  auto keyPair = cryptoContext->HESea_KeyGen();
  DEBUG("keygen");
  ASSERT_TRUE(keyPair.good()) << "Key generation failed!";
  DEBUG("EvalMultKeysGen");
  // Create evaluation key vector to be used in keyswitching
  cryptoContext->HESea_EvalMultKeysGen(keyPair.secretKey);

  ////////////////////////////////////////////////////////////
  // Plaintext
  ////////////////////////////////////////////////////////////

  std::vector<int64_t> vectorOfInts1 = {5, 4, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0};
  std::vector<int64_t> vectorOfInts2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts3 = {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  std::vector<int64_t> vectorOfInts4 = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  std::vector<int64_t> vectorOfInts5 = {10, 8, 6, 4, 2, 0, 10, 8, 6, 4, 2, 0};
  std::vector<int64_t> vectorOfInts6 = {30, 24, 18, 12, 6, 0,
                                        30, 24, 18, 12, 6, 0};
  std::vector<int64_t> vectorOfInts7 = {120, 96, 72, 48, 24, 0,
                                        120, 96, 72, 48, 24, 0};
  DEBUG("MakeCoefPackedPlaintext");
  Plaintext plaintext1 = cryptoContext->HESea_MakeCoefPackedPlaintext(vectorOfInts1);
  Plaintext plaintext2 = cryptoContext->HESea_MakeCoefPackedPlaintext(vectorOfInts2);
  Plaintext plaintext3 = cryptoContext->HESea_MakeCoefPackedPlaintext(vectorOfInts3);
  Plaintext plaintext4 = cryptoContext->HESea_MakeCoefPackedPlaintext(vectorOfInts4);

  Plaintext plaintextResult1 =
      cryptoContext->HESea_MakeCoefPackedPlaintext(vectorOfInts5);
  Plaintext plaintextResult2 =
      cryptoContext->HESea_MakeCoefPackedPlaintext(vectorOfInts6);
  Plaintext plaintextResult3 =
      cryptoContext->HESea_MakeCoefPackedPlaintext(vectorOfInts7);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////
  DEBUG("Encryption");
  auto ciphertext1 = cryptoContext->HESea_Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->HESea_Encrypt(keyPair.publicKey, plaintext2);
  auto ciphertext3 = cryptoContext->HESea_Encrypt(keyPair.publicKey, plaintext3);
  auto ciphertext4 = cryptoContext->HESea_Encrypt(keyPair.publicKey, plaintext4);

  ////////////////////////////////////////////////////////////
  // EvalMult Operation
  ////////////////////////////////////////////////////////////
  DEBUG("EvalMults");
  // Perform consecutive multiplications and do a keyswtiching at the end.
  auto ciphertextMul12 =
          cryptoContext->HESea_EvalMultNoRelin(ciphertext1, ciphertext2);
  auto ciphertextMul123 =
          cryptoContext->HESea_EvalMultNoRelin(ciphertextMul12, ciphertext3);
  auto ciphertextMul1234 =
      cryptoContext->HESea_EvalMultAndRelinearize(ciphertextMul123, ciphertext4);

  ////////////////////////////////////////////////////////////
  // Decryption of multiplicative results with and without keyswtiching (depends
  // on the level)
  ////////////////////////////////////////////////////////////

  Plaintext plaintextMul1;
  Plaintext plaintextMul2;
  Plaintext plaintextMul3;
  DEBUG("DECRYPTIO");
  cryptoContext->HESea_Decrypt(keyPair.secretKey, ciphertextMul12, &plaintextMul1);
  cryptoContext->HESea_Decrypt(keyPair.secretKey, ciphertextMul123, &plaintextMul2);
  cryptoContext->HESea_Decrypt(keyPair.secretKey, ciphertextMul1234, &plaintextMul3);

  ////////////////////////////////////////////////////////////
  // Prepare HESea_EvalMultMany
  ////////////////////////////////////////////////////////////

  vector<Ciphertext<Element>> cipherTextList;

  cipherTextList.push_back(ciphertext1);
  cipherTextList.push_back(ciphertext2);
  cipherTextList.push_back(ciphertext3);
  cipherTextList.push_back(ciphertext4);

  ////////////////////////////////////////////////////////////
  // Compute HESea_EvalMultMany
  ////////////////////////////////////////////////////////////

  auto ciphertextMul12345 = cryptoContext->HESea_EvalMultMany(cipherTextList);

  ////////////////////////////////////////////////////////////
  // Decrypt HESea_EvalMultMany
  ////////////////////////////////////////////////////////////

  Plaintext plaintextMulMany;
  cryptoContext->HESea_Decrypt(keyPair.secretKey, ciphertextMul12345,
                         &plaintextMulMany);

  plaintextResult1->SetLength(plaintextMul1->GetLength());
  plaintextResult2->SetLength(plaintextMul2->GetLength());
  plaintextResult3->SetLength(plaintextMul3->GetLength());

  EXPECT_EQ(*plaintextMul1, *plaintextResult1)
      << msg << ".HESea_EvalMult gives incorrect results.\n";
  EXPECT_EQ(*plaintextMul2, *plaintextResult2)
      << msg << ".HESea_EvalMult gives incorrect results.\n";
  EXPECT_EQ(*plaintextMul3, *plaintextResult3)
      << msg << ".HESea_EvalMultAndRelinearize gives incorrect results.\n";
  EXPECT_EQ(*plaintextMulMany, *plaintextResult3)
      << msg << ".HESea_EvalMultMany gives incorrect results.\n";
}
