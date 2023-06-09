// @file  polynomial_evaluation.cpp - Example of polynomial evaluation using
// CKKS.
// @author TPOC: 
//
// @copyright Copyright (c) 2020, Duality Technologies Inc.
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

#define PROFILE  // turns on the reporting of timing results

#include "hesea.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char* argv[]) {
  TimeVar t;

  double timeEvalPoly1(0.0), timeEvalPoly2(0.0);

  std::cout << "\n======EXAMPLE FOR EVALPOLY========\n" << std::endl;

  usint m = 4096;

  usint init_size = 7;
  usint dcrtBits = 50;

  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          init_size - 1, dcrtBits, 16, HEStd_NotSet, m / 2, /*ringDimension*/
          EXACTRESCALE, HYBRID, 3,                          /*numLargeDigits*/
          2,                                                /*maxDepth*/
          60,                                               /*firstMod*/
          0, OPTIMIZED);

  cc->HESea_Enable(ENCRYPTION);
  cc->HESea_Enable(SHE);
  cc->HESea_Enable(LEVELEDSHE);

  std::vector<std::complex<double>> input({0.5, 0.7, 0.9, 0.95, 0.93});

  size_t encodedLength = input.size();

  std::vector<double> coefficients1(
      {0.15, 0.75, 0, 1.25, 0, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0, 0, 1});
  std::vector<double> coefficients2(
      {1,   2,   3,   4,   5,   -1,   -2,   -3,   -4,   -5,
       0.1, 0.2, 0.3, 0.4, 0.5, -0.1, -0.2, -0.3, -0.4, -0.5,
       0.1, 0.2, 0.3, 0.4, 0.5, -0.1, -0.2, -0.3, -0.4, -0.5});
  Plaintext plaintext1 = cc->HESea_MakeCKKSPackedPlaintext(input);

  auto keyPair = cc->HESea_KeyGen();

  std::cout << "Generating evaluation key for homomorphic multiplication...";
  cc->HESea_EvalMultKeyGen(keyPair.secretKey);
  std::cout << "Completed." << std::endl;

  auto ciphertext1 = cc->HESea_Encrypt(keyPair.publicKey, plaintext1);

  TIC(t);

  auto result = cc->HESea_EvalPoly(ciphertext1, coefficients1);

  timeEvalPoly1 = TOC(t);

  TIC(t);

  auto result2 = cc->HESea_EvalPoly(ciphertext1, coefficients2);

  timeEvalPoly2 = TOC(t);

  Plaintext plaintextDec;

  cc->HESea_Decrypt(keyPair.secretKey, result, &plaintextDec);

  plaintextDec->SetLength(encodedLength);

  Plaintext plaintextDec2;

  cc->HESea_Decrypt(keyPair.secretKey, result2, &plaintextDec2);

  plaintextDec2->SetLength(encodedLength);

  cout << std::setprecision(15) << std::endl;

  cout << "\n Original Plaintext #1: \n";
  cout << plaintext1 << endl;

  cout << "\n Result of evaluating a polynomial with coefficients "
       << coefficients1 << " \n";
  cout << plaintextDec << endl;

  cout << "\n Expected result: (0.70519107, 1.38285078, 3.97211180, "
          "5.60215665, 4.86357575) "
       << endl;

  cout << "\n Evaluation time: " << timeEvalPoly1 << " ms" << endl;

  cout << "\n Result of evaluating a polynomial with coefficients "
       << coefficients2 << " \n";
  cout << plaintextDec2 << endl;

  cout << "\n Expected result: (3.4515092326, 5.3752765397, 4.8993108833, "
          "3.2495023573, 4.0485229982) "
       << endl;

  cout << "\n Evaluation time: " << timeEvalPoly2 << " ms" << endl;

  return 0;
}
