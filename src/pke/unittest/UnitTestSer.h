// @file UnitTestSer.h - function to test serialization
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

#include <iostream>
#include <string>

#include "cryptocontext-ser.h"
#include "cryptocontext.h"  // NOLINT: clang-format nad cpplint disagree on alphabetical sort
#include "gtest/gtest.h"
#include "math/nbtheory.h"
#include "hesea.h"
#include "utils/parmfactory.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;

template <typename T, typename ST>
void UnitTestContextWithSertype(CryptoContext<T> cc, const ST& sertype,
                                string msg) {
  LPKeyPair<T> kp = cc->HESea_KeyGen();
  try {
    cc->HESea_EvalMultKeyGen(kp.secretKey);
  } catch (...) {
  }
  try {
    cc->HESea_EvalSumKeyGen(kp.secretKey, kp.publicKey);
  } catch (...) {
  }

  stringstream s;

  Serial::Serialize(cc, s, sertype);

  CryptoContext<T> newcc;
  Serial::Deserialize(newcc, s, sertype);

  ASSERT_TRUE(newcc.get() != 0) << msg << " Deserialize failed";

  EXPECT_EQ(*cc, *newcc) << msg << " Mismatched context";

  EXPECT_EQ(*cc->HESea_GetEncryptionAlgorithm(), *newcc->HESea_GetEncryptionAlgorithm())
      << msg << " Scheme mismatch after ser/deser";
  EXPECT_EQ(*cc->HESea_GetCryptoParameters(), *newcc->HESea_GetCryptoParameters())
      << msg << " Crypto parms mismatch after ser/deser";
  EXPECT_EQ(*cc->HESea_GetEncodingParams(), *newcc->HESea_GetEncodingParams())
      << msg << " Encoding parms mismatch after ser/deser";
  EXPECT_EQ(cc->HESea_GetEncryptionAlgorithm()->GetEnabled(),
            newcc->HESea_GetEncryptionAlgorithm()->GetEnabled())
      << msg << " Enabled features mismatch after ser/deser";

  s.str("");
  s.clear();
  Serial::Serialize(kp.publicKey, s, sertype);

  LPPublicKey<T> newPub;
  Serial::Deserialize(newPub, s, sertype);
  ASSERT_TRUE(newPub.get() != 0) << msg << " Key deserialize failed";

  EXPECT_EQ(*kp.publicKey, *newPub) << msg << " Key mismatch";

  CryptoContext<T> newccFromkey = newPub->GetCryptoContext();
  EXPECT_EQ(*cc, *newccFromkey) << msg << " Key deser has wrong context";
}
