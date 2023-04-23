// @file binfhecontext.cpp - Implementation file for Boolean Circuit FHE context
// class
// @author TPOC: contact@hesea-crypto.org
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

#include "binfhecontext.h"
#include <vector>

namespace lbcrypto {

void BinFHEContext::GenerateBinFHEContext(uint32_t n, uint32_t N,
                                          const NativeInteger &q,
                                          const NativeInteger &Q,
                                          const NativeInteger &qKS,
                                          double std,
                                          uint32_t baseKS, uint32_t baseG,
                                          uint32_t baseR, BINFHEMETHOD method) {
  auto lweparams = std::make_shared<LWECryptoParams>(n, N, q, Q, qKS, std, baseKS);
  m_params =
      std::make_shared<RingGSWCryptoParams>(lweparams, baseG, baseR, method);
}

void BinFHEContext::GenerateBinFHEContext(BINFHEPARAMSET set,
                                          BINFHEMETHOD method) {
  shared_ptr<LWECryptoParams> lweparams;
  NativeInteger Q;
  switch (set) {
    case TOY:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 1024),
                                       1024);
      lweparams = std::make_shared<LWECryptoParams>(64, 512, 512, Q, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 32, method);
      break;
    case MEDIUM:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(28, 2048),
                                       2048);
      lweparams = std::make_shared<LWECryptoParams>(422, 1024, 1024, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 10, 32, method);
    case STD128_AP:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(512, 1024, 1024, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 32, method);
      break;
    case STD128_APOPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(502, 1024, 1024, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 32, method);
      break;
    case STD128:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(512, 1024, 1024, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 32, method);
      break;
    case STD128_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(502, 1024, 1024, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 32, method);
      break;
    case STD192:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(37, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 1024, Q, 1 << 19, 3.19, 28);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 13, 32, method);
      break;
    case STD192_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(37, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(805, 2048, 1024, Q, 1 << 15, 3.19, 1 << 5);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 13, 32, method);
      break;
    case STD256:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(29, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 2048, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 8, 46, method);
      break;
    case STD256_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(29, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(990, 2048, 2048, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 8, 46, method);
      break;
    case STD128Q:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(50, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 1024, Q, 1 << 25, 3.19, 32);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 25, 32, method);
      break;
    case STD128Q_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(50, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(585, 2048, 1024, Q, 1 << 15, 3.19, 32);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 25, 32, method);
      break;
    case STD192Q:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(35, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 1024, Q, 1 << 17, 3.19, 64);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 12, 32, method);
      break;
    case STD192Q_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(35, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(875, 2048, 1024, Q, 1 << 15, 3.19, 1 << 5);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 12, 32, method);
      break;
    case STD256Q:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(2048, 2048, 2048, Q, 1 << 16, 3.19, 16);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 46, method);
      break;
    case STD256Q_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1225, 2048, 1024, Q, 1 << 16, 3.19, 16);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 32, method);
      break;
    case SIGNED_MOD_TEST:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(28, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(512, 1024, 512, Q, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 23, method);
      break;
    default:
      std::string errMsg = "ERROR: No such parameter set exists for FHEW.";
      HESEA_THROW(config_error, errMsg);
  }
}


void BinFHEContext::Generate_Default_params(){

  int N = 512;
  int n = 128;
  int baseG = 1<<20;
  int baseKS = 1<<3;
  uint64_t qKS = 1 << 30;
  int baseR = 1<<2;
  BINFHEMETHOD method = GINX;

  NativeInteger q = NativeInteger(1<<30);

  int logQ = 53;


  NativeInteger Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(logQ, 2*N), 2*N);
  
  auto lweparams = std::make_shared<LWECryptoParams>(n, N, q, Q, qKS, 1, baseKS);
  m_params = std::make_shared<RingGSWCryptoParams>(lweparams, baseG, baseR, method);

}

LWEPrivateKey BinFHEContext::KeyGen() const {
  return m_LWEscheme->KeyGen(m_params->GetLWEParams());
}

LWEPrivateKey BinFHEContext::KeyGenN() const {
  return m_LWEscheme->KeyGenN(m_params->GetLWEParams());
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPrivateKey sk,
                                     const LWEPlaintext &m,
                                     BINFHEOUTPUT output) const {
  if (output == FRESH) {
    return m_LWEscheme->Encrypt(m_params->GetLWEParams(), sk, m);
  } else {
    auto ct = m_LWEscheme->Encrypt(m_params->GetLWEParams(), sk, m);
    return m_RingGSWscheme->Bootstrap(m_params, m_BTKey, ct, m_LWEscheme);
  }
}

void BinFHEContext::Decrypt(ConstLWEPrivateKey sk, ConstLWECiphertext ct,
                            LWEPlaintext *result) const {
  return m_LWEscheme->Decrypt(m_params->GetLWEParams(), sk, ct, result);
}

std::shared_ptr<LWESwitchingKey> BinFHEContext::KeySwitchGen(
    ConstLWEPrivateKey sk, ConstLWEPrivateKey skN) const {
  return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(), sk, skN);
}

void BinFHEContext::BTKeyGen(ConstLWEPrivateKey sk) {
  m_BTKey = m_RingGSWscheme->KeyGen(m_params, m_LWEscheme, sk);
  return;
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate,
                                         ConstLWECiphertext ct1,
                                         ConstLWECiphertext ct2) const {
  return m_RingGSWscheme->EvalBinGate(m_params, gate, m_BTKey, ct1, ct2,
                                      m_LWEscheme);
}

LWECiphertext BinFHEContext::Bootstrap(ConstLWECiphertext ct1) const {
  return m_RingGSWscheme->Bootstrap(m_params, m_BTKey, ct1, m_LWEscheme);
}

LWECiphertext BinFHEContext::EvalNOT(ConstLWECiphertext ct) const {
  return m_RingGSWscheme->EvalNOT(m_params, ct);
}

LWECiphertext BinFHEContext::EvalConstant(bool value) const {
  return m_LWEscheme->NoiselessEmbedding(m_params->GetLWEParams(), value);

}


LWECiphertext BinFHEContext::TraivlEncrypt(LWEPlaintext value, LWEPlaintextModulus p){
  NativeInteger q = m_params->GetLWEParams()->Getq();
  uint32_t n = m_params->GetLWEParams()->Getn();

  NativeVector a(n, q);
  for (uint32_t i = 0; i < n; ++i) a[i] = 0;

  NativeInteger b = value * (q/p);

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}


LWECiphertext BinFHEContext::Encrypt(ConstLWEPrivateKey sk, const LWEPlaintext& m, const LWEPlaintextModulus& p, BINFHEOUTPUT output = FRESH){
  NativeVector s = sk->GetElement();
  uint32_t n     = s.GetLength();
  NativeInteger q = m_params->GetLWEParams()->Getq();

  s.SwitchModulus(q);


  NativeInteger b = (m % p) * (q / p) + m_params->GetLWEParams()->GetDgg().GenerateInteger(q);
  // NativeInteger b = (m % p) * (mod / p);

  #if defined(BINFHE_DEBUG)
    std::cout << b % mod << std::endl;
    std::cout << (m % p) * (mod / p) << std::endl;
  #endif

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(q);
  NativeVector a = dug.GenerateVector(n);

  NativeInteger mu = q.ComputeMu();

  for (size_t i = 0; i < n; ++i) {
      b += a[i].ModMulFast(s[i], q, mu);
  }
  b.ModEq(q);
  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
};

void BinFHEContext::Decrypt(ConstLWEPrivateKey sk, ConstLWECiphertext ct, LWEPlaintext* result, LWEPlaintextModulus p) const {
  // Create local variables to speed up the computations
  const NativeInteger& mod = m_params->GetLWEParams()->Getq();


  NativeVector a   = ct->GetA();
  NativeVector s   = sk->GetElement();
  uint32_t n       = s.GetLength();
  NativeInteger mu = mod.ComputeMu();
  s.SwitchModulus(mod);
  NativeInteger inner(0);
  for (size_t i = 0; i < n; ++i) {
      inner += a[i].ModMulFast(s[i], mod, mu);
  }
  inner.ModEq(mod);

  NativeInteger r = ct->GetB();

  r.ModSubFastEq(inner, mod);

  // Alternatively, rounding can be done as
  // *result = (r.MultiplyAndRound(NativeInteger(4),q)).ConvertToInt();
  // But the method below is a more efficient way of doing the rounding
  // the idea is that Round(4/q x) = q/8 + Floor(4/q x)
  r.ModAddFastEq((mod / (p * 2)), mod);
  *result = ((NativeInteger(p) * r) / mod).ConvertToInt();

  #if defined(BINFHE_DEBUG)
      double error =
          (static_cast<double>(p) * (r.ConvertToDouble() - mod.ConvertToInt() / (p * 2))) / mod.ConvertToDouble() -
          static_cast<double>(*result);
      std::cerr << mod << " " << p << " " << r << " error:\t" << error << std::endl;
      std::cerr << error * mod.ConvertToDouble() / static_cast<double>(p) << std::endl;
  #endif

  return;
}

LWECiphertext BinFHEContext::MyEvalSigndFunc(ConstLWECiphertext ct, LWEPlaintextModulus p) const {
  auto ek = m_BTKey.BSkey;
  if (ek == nullptr) {
      std::string errMsg =
          "Bootstrapping keys have not been generated. Please call BTKeyGen before calling bootstrapping.";
      HESEA_THROW(config_error, errMsg);
  }

  auto& LWEParams  = m_params->GetLWEParams();
  auto& RGSWParams = m_params;
  auto polyParams  = RGSWParams->GetPolyParams();

  NativeInteger Q = LWEParams->GetQ();
  NativeInteger q = LWEParams->Getq();
  uint32_t N      = LWEParams->GetN();
  uint32_t n      = LWEParams->Getn();
  NativeVector m(N, Q);

  auto ct1 = m_LWEscheme->ModSwitch(NativeInteger(2*N), ct);

  // For specific function evaluation instead of generalbootstrapping
  NativeInteger ctMod    = ct1->GetA().GetModulus(); //q
  const NativeInteger& b = ct1->GetB();
  const NativeVector&  a = ct1->GetA();
  for (size_t j = 0; j < (ctMod >> 1 ); ++j) {  //q/2
      NativeInteger temp = b.ModSub(j, ctMod);
      m[j] = (temp%ctMod < ctMod/2)?  Q/p : (p-1)*Q/p;        
  }
  std::vector<NativePoly> res(2);
  // no need to do NTT as all coefficients of this poly are zero
  res[0] = NativePoly(polyParams, Format::EVALUATION, true);
  res[1] = NativePoly(polyParams, Format::COEFFICIENT, false);
  res[1].SetValues(std::move(m), Format::COEFFICIENT);
  res[1].SetFormat(Format::EVALUATION);

  // main accumulation computation
  // the following loop is the bottleneck of bootstrapping/binary gate
  // evaluation
  auto acc = std::make_shared<RingGSWCiphertext>(1, 2);
  vector<vector<NativePoly>> res1;
  res1.push_back(res);
  acc->SetElements(std::move(res1));
  // (*acc)[0] = std::move(res);

  auto digitsR = m_params->GetDigitsR();
  auto baseR = m_params->GetBaseR();


  if (m_params->GetMethod() == AP) {
    for (uint32_t i = 0; i < n; i++) {
      NativeInteger aI = ctMod.ModSub(a[i], ctMod);
      for (uint32_t k = 0; k < digitsR.size();
          k++, aI /= NativeInteger(baseR)) {
        uint32_t a0 = (aI.Mod(baseR)).ConvertToInt();
        if (a0) m_RingGSWscheme->AddToACCAP(m_params, (*ek)[i][a0][k], acc);
      }
    }
  } else {  // if GINX
    for (uint32_t i = 0; i < n; i++) {
      // handles -a*E(1) and handles -a*E(-1) = a*E(1)
      m_RingGSWscheme->AddToACCGINX(m_params, (*ek)[0][0][i], (*ek)[0][1][i], ctMod.ModSub(a[i], ctMod), acc);
      // m_RingGSWscheme->AddToACCGINX(m_params, (*ek)[0][0][i], (*ek)[0][1][i], a[i].Mod(ctMod), acc);
      
    }
  }
  
  NativePoly temp = (*acc)[0][0];
  temp = temp.Transpose();
  temp.SetFormat(Format::COEFFICIENT);
  auto aNew = temp.GetValues();

  temp = (*acc)[0][1];
  temp.SetFormat(Format::COEFFICIENT);
  // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
  auto bNew = temp[0];

  // Modulus switching to a middle step Q'
  auto eQN = m_LWEscheme->ModSwitch(m_params->GetLWEParams()->GetqKS(), std::make_shared<LWECiphertextImpl>(aNew, bNew));
  
  
  // std::vector<NativePoly>& accVec = (*acc)[0];
  // // the accumulator result is encrypted w.r.t. the transposed secret key
  // // we can transpose "a" to get an encryption under the original secret key
  // accVec[0] = accVec[0].Transpose();
  // accVec[0].SetFormat(Format::COEFFICIENT);
  // accVec[1].SetFormat(Format::COEFFICIENT);


  // auto ctExt      = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(accVec[1][0]));
  // Modulus switching to a middle step qKS'
  // Modulus switching


  auto ctMS = m_LWEscheme->ModSwitch(LWEParams->GetqKS(), eQN);
  // Key switching
  auto ctKS = m_LWEscheme->KeySwitch(LWEParams, m_BTKey.KSkey, ctMS);
  // Modulus switching
  return m_LWEscheme->ModSwitch(LWEParams->Getq(), ctKS);

}


}  // namespace lbcrypto
