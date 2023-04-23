// @file cryptocontext.cpp -- Control for encryption operations.
// @author TPOC: 
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
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

#include "cryptocontext.h"
#include "utils/serial.h"

namespace lbcrypto {

    //! BinFHE
    template<typename Element>
    void CryptoContextImpl<Element>::Generate_Default_params(){

        int N = 512;
        int n = 128;
        int baseG = 1<<30;
        int baseKS = 1<<3;
        uint64_t qKS = 1 << 30;
        int baseR = 1<<2;
        BINFHEMETHOD method = GINX;

        NativeInteger q = NativeInteger(1<<30);

        int logQ = 53;


        NativeInteger Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(logQ, 2*N), 2*N);
        
        auto lweparams = std::make_shared<LWECryptoParams>(n, N, q, Q, qKS, 0, baseKS);
        m_params = std::make_shared<RingGSWCryptoParams>(lweparams, baseG, baseR, method);

    }

    template<typename Element>
    LWECiphertext CryptoContextImpl<Element>::HESea_TraivlEncrypt(LWEPlaintext value, LWEPlaintextModulus p){
        NativeInteger q = m_params->GetLWEParams()->Getq();
        uint32_t n = m_params->GetLWEParams()->Getn();

        NativeVector a(n, q);
        for (uint32_t i = 0; i < n; ++i) a[i] = 0;

        NativeInteger b = value * (q/p);

        return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
    }   
    
    template<typename Element>
    LWECiphertext CryptoContextImpl<Element>::HESea_Encrypt(ConstLWEPrivateKey sk, const LWEPlaintext& m, const LWEPlaintextModulus& p){
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

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_Decrypt(ConstLWEPrivateKey sk, ConstLWECiphertext ct, LWEPlaintext* result, LWEPlaintextModulus p) const {
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

    template<typename Element>
    LWECiphertext CryptoContextImpl<Element>::HESea_MyEvalSigndFunc(ConstLWECiphertext ct, LWEPlaintextModulus p) const {
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
            m[j] = (temp%ctMod <= ctMod/2)?  Q/p : (p-1)*Q/p;        
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

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_GenerateBinFHEContext(uint32_t n, uint32_t N,
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

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_GenerateBinFHEContext(BINFHEPARAMSET set,
                                                           BINFHEMETHOD method) {
        shared_ptr <LWECryptoParams> lweparams;
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

    template<typename Element>
    LWEPrivateKey CryptoContextImpl<Element>::HESea_KeyGen02() const {
        return m_LWEscheme->KeyGen(m_params->GetLWEParams());
    }

    template<typename Element>
    LWEPrivateKey CryptoContextImpl<Element>::HESea_KeyGenN() const {
        return m_LWEscheme->KeyGenN(m_params->GetLWEParams());
    }

    template<typename Element>
    LWECiphertext CryptoContextImpl<Element>::HESea_Encrypt(ConstLWEPrivateKey sk,
                                                      const LWEPlaintext &m,
                                                      BINFHEOUTPUT output) const {
        if (output == FRESH) {
            return m_LWEscheme->Encrypt(m_params->GetLWEParams(), sk, m);
        } else {
            auto ct = m_LWEscheme->Encrypt(m_params->GetLWEParams(), sk, m);
            return m_RingGSWscheme->Bootstrap(m_params, m_BTKey, ct, m_LWEscheme);
        }
    }

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_Decrypt(ConstLWEPrivateKey sk, ConstLWECiphertext ct,
                                             LWEPlaintext *result) const {
        return m_LWEscheme->Decrypt(m_params->GetLWEParams(), sk, ct, result);
    }

    template<typename Element>
    std::shared_ptr <LWESwitchingKey> CryptoContextImpl<Element>::HESea_KeySwitchGen(
            ConstLWEPrivateKey sk, ConstLWEPrivateKey skN) const {
        return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(), sk, skN);
    }

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_BTKeyGen(ConstLWEPrivateKey sk) {
        m_BTKey = m_RingGSWscheme->KeyGen(m_params, m_LWEscheme, sk);
        return;
    }

    template<typename Element>
    LWECiphertext CryptoContextImpl<Element>::HESea_EvalBinGate(const BINGATE gate,
                                                          ConstLWECiphertext ct1,
                                                          ConstLWECiphertext ct2) const {
        return m_RingGSWscheme->EvalBinGate(m_params, gate, m_BTKey, ct1, ct2,
                                            m_LWEscheme);
    }

    template<typename Element>
    LWECiphertext CryptoContextImpl<Element>::HESea_Bootstrap(ConstLWECiphertext ct1) const {
        return m_RingGSWscheme->Bootstrap(m_params, m_BTKey, ct1, m_LWEscheme);
    }

    template<typename Element>
    LWECiphertext CryptoContextImpl<Element>::HESea_EvalNOT(ConstLWECiphertext ct) const {
        return m_RingGSWscheme->EvalNOT(m_params, ct);
    }

    template<typename Element>
    LWECiphertext CryptoContextImpl<Element>::HESea_EvalConstant(bool value) const {
        return m_LWEscheme->NoiselessEmbedding(m_params->GetLWEParams(), value);
    }

    //! BinFHE




    // Initialize global config variable
    bool SERIALIZE_PRECOMPUTE = true;

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_EvalMultKeyGen(
            const LPPrivateKey <Element> key) {
        if (key == nullptr || Mismatched(key->GetCryptoContext()))
            HESEA_THROW(config_error,
                           "Key passed to EvalMultKeyGen were not generated with this "
                           "crypto context");

        LPEvalKey <Element> k = HESea_GetEncryptionAlgorithm()->EvalMultKeyGen(key);

        HESea_GetAllEvalMultKeys()[k->GetKeyTag()] = {k};
    }

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_EvalMultKeysGen(
            const LPPrivateKey <Element> key) {
        if (key == nullptr || Mismatched(key->GetCryptoContext()))
            HESEA_THROW(config_error,
                           "Key passed to EvalMultsKeyGen were not generated with this "
                           "crypto context");

        const vector <LPEvalKey<Element>> &evalKeys =
                HESea_GetEncryptionAlgorithm()->EvalMultKeysGen(key);

        HESea_GetAllEvalMultKeys()[evalKeys[0]->GetKeyTag()] = evalKeys;
    }

    template<typename Element>
    const vector <LPEvalKey<Element>> &
    CryptoContextImpl<Element>::GetEvalMultKeyVector(const string &keyID) {
        auto ekv = HESea_GetAllEvalMultKeys().find(keyID);
        if (ekv == HESea_GetAllEvalMultKeys().end())
            HESEA_THROW(not_available_error,
                           "You need to use EvalMultKeyGen so that you have an "
                           "EvalMultKey available for this ID");
        return ekv->second;
    }

    template<typename Element>
    std::map <string, std::vector<LPEvalKey < Element>>>&

    CryptoContextImpl<Element>::HESea_GetAllEvalMultKeys() {
        return evalMultKeyMap();
    }

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_ClearEvalMultKeys() {
        HESea_GetAllEvalMultKeys().clear();
    }

    /**
     * ClearEvalMultKeys - flush EvalMultKey cache for a given id
     * @param id
     */
    template<typename Element>
    void CryptoContextImpl<Element>::HESea_ClearEvalMultKeys(const string &id) {
        auto kd = HESea_GetAllEvalMultKeys().find(id);
        if (kd != HESea_GetAllEvalMultKeys().end()) HESea_GetAllEvalMultKeys().erase(kd);
    }

    /**
     * ClearEvalMultKeys - flush EvalMultKey cache for a given context
     * @param cc
     */
    template<typename Element>
    void CryptoContextImpl<Element>::HESea_ClearEvalMultKeys(
            const CryptoContext <Element> cc) {
        for (auto it = HESea_GetAllEvalMultKeys().begin();
             it != HESea_GetAllEvalMultKeys().end();) {
            if (it->second[0]->GetCryptoContext() == cc) {
                it = HESea_GetAllEvalMultKeys().erase(it);
            } else {
                ++it;
            }
        }
    }

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_InsertEvalMultKey(
            const std::vector <LPEvalKey<Element>> &vectorToInsert) {
        HESea_GetAllEvalMultKeys()[vectorToInsert[0]->GetKeyTag()] = vectorToInsert;
    }

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_EvalSumKeyGen(
            const LPPrivateKey <Element> privateKey,
            const LPPublicKey <Element> publicKey) {
        if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
            HESEA_THROW(config_error,
                           "Private key passed to EvalSumKeyGen were not generated "
                           "with this crypto context");
        }

        if (publicKey != nullptr &&
            privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
            HESEA_THROW(
                    config_error,
                    "Public key passed to EvalSumKeyGen does not match private key");
        }

        auto evalKeys =
                HESea_GetEncryptionAlgorithm()->EvalSumKeyGen(privateKey, publicKey);

        HESea_GetAllEvalSumKeys()[privateKey->GetKeyTag()] = evalKeys;
    }

    template<typename Element>
    shared_ptr <std::map<usint, LPEvalKey < Element>>>

    CryptoContextImpl<Element>::HESea_EvalSumRowsKeyGen(
            const LPPrivateKey <Element> privateKey,
            const LPPublicKey <Element> publicKey, usint rowSize, usint subringDim) {
        if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
            HESEA_THROW(config_error,
                           "Private key passed to EvalSumKeyGen were not generated "
                           "with this crypto context");
        }

        if (publicKey != nullptr &&
            privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
            HESEA_THROW(
                    config_error,
                    "Public key passed to EvalSumKeyGen does not match private key");
        }

        auto evalKeys = HESea_GetEncryptionAlgorithm()->EvalSumRowsKeyGen(
                privateKey, publicKey, rowSize, subringDim);

        return evalKeys;
    }

    template<typename Element>
    shared_ptr <std::map<usint, LPEvalKey < Element>>>

    CryptoContextImpl<Element>::HESea_EvalSumColsKeyGen(
            const LPPrivateKey <Element> privateKey,
            const LPPublicKey <Element> publicKey) {
        if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
            HESEA_THROW(config_error,
                           "Private key passed to EvalSumKeyGen were not generated "
                           "with this crypto context");
        }

        if (publicKey != nullptr &&
            privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
            HESEA_THROW(
                    config_error,
                    "Public key passed to EvalSumKeyGen does not match private key");
        }

        auto evalKeys =
                HESea_GetEncryptionAlgorithm()->EvalSumColsKeyGen(privateKey, publicKey);

        return evalKeys;
    }

    template<typename Element>
    const std::map <usint, LPEvalKey<Element>> &
    CryptoContextImpl<Element>::HESea_GetEvalSumKeyMap(const string &keyID) {
        auto ekv = HESea_GetAllEvalSumKeys().find(keyID);
        if (ekv == HESea_GetAllEvalSumKeys().end())
            HESEA_THROW(not_available_error,
                           "You need to use EvalSumKeyGen so that you have EvalSumKeys "
                           "available for this ID");
        return *ekv->second;
    }

    template<typename Element>
    std::map <string, shared_ptr<std::map < usint, LPEvalKey < Element>>>>&

    CryptoContextImpl<Element>::HESea_GetAllEvalSumKeys() {
        return evalSumKeyMap();
    }

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_ClearEvalSumKeys() {
        HESea_GetAllEvalSumKeys().clear();
    }

    /**
     * ClearEvalMultKeys - flush EvalMultKey cache for a given id
     * @param id
     */
    template<typename Element>
    void CryptoContextImpl<Element>::HESea_ClearEvalSumKeys(const string &id) {
        auto kd = HESea_GetAllEvalSumKeys().find(id);
        if (kd != HESea_GetAllEvalSumKeys().end()) HESea_GetAllEvalSumKeys().erase(kd);
    }

    /**
     * ClearEvalMultKeys - flush EvalMultKey cache for a given context
     * @param cc
     */
    template<typename Element>
    void CryptoContextImpl<Element>::HESea_ClearEvalSumKeys(
            const CryptoContext <Element> cc) {
        for (auto it = HESea_GetAllEvalSumKeys().begin();
             it != HESea_GetAllEvalSumKeys().end();) {
            if (it->second->begin()->second->GetCryptoContext() == cc) {
                it = HESea_GetAllEvalSumKeys().erase(it);
            } else {
                ++it;
            }
        }
    }

    template<typename Element>
    void CryptoContextImpl<Element>::HESea_InsertEvalSumKey(
            const shared_ptr <std::map<usint, LPEvalKey < Element>>

    > mapToInsert) {
    // find the tag
    if (!mapToInsert->

    empty()

    ) {
    auto onekey = mapToInsert->begin();

    HESea_GetAllEvalSumKeys()[onekey->second->GetKeyTag()] = mapToInsert;
}
}

template<typename Element>
void CryptoContextImpl<Element>::HESea_EvalAtIndexKeyGen(
        const LPPrivateKey <Element> privateKey,
        const std::vector <int32_t> &indexList,
        const LPPublicKey <Element> publicKey) {
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext())) {
        HESEA_THROW(config_error,
                       "Private key passed to EvalAtIndexKeyGen were not generated "
                       "with this crypto context");
    }

    if (publicKey != nullptr &&
        privateKey->GetKeyTag() != publicKey->GetKeyTag()) {
        HESEA_THROW(
                config_error,
                "Public key passed to EvalAtIndexKeyGen does not match private key");
    }

    auto evalKeys = HESea_GetEncryptionAlgorithm()->EvalAtIndexKeyGen(
            publicKey, privateKey, indexList);

    evalAutomorphismKeyMap()[privateKey->GetKeyTag()] = evalKeys;
}

template<typename Element>
const std::map <usint, LPEvalKey<Element>> &
CryptoContextImpl<Element>::HESea_GetEvalAutomorphismKeyMap(const string &keyID) {
    auto ekv = evalAutomorphismKeyMap().find(keyID);
    if (ekv == evalAutomorphismKeyMap().end())
        HESEA_THROW(not_available_error,
                       "You need to use EvalAutomorphismKeyGen so that you have "
                       "EvalAutomorphismKeys available for this ID");
    return *ekv->second;
}

template<typename Element>
std::map <string, shared_ptr<std::map < usint, LPEvalKey < Element>>>>&

CryptoContextImpl<Element>::HESea_GetAllEvalAutomorphismKeys() {
    return evalAutomorphismKeyMap();
}

template<typename Element>
void CryptoContextImpl<Element>::HESea_ClearEvalAutomorphismKeys() {
    evalAutomorphismKeyMap().clear();
}

/**
 * HESea_ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given id
 * @param id
 */
template<typename Element>
void CryptoContextImpl<Element>::HESea_ClearEvalAutomorphismKeys(const string &id) {
    auto kd = evalAutomorphismKeyMap().find(id);
    if (kd != evalAutomorphismKeyMap().end()) evalAutomorphismKeyMap().erase(kd);
}

/**
 * HESea_ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given
 * context
 * @param cc
 */
template<typename Element>
void CryptoContextImpl<Element>::HESea_ClearEvalAutomorphismKeys(
        const CryptoContext <Element> cc) {
    for (auto it = evalAutomorphismKeyMap().begin();
         it != evalAutomorphismKeyMap().end();) {
        if (it->second->begin()->second->GetCryptoContext() == cc) {
            it = evalAutomorphismKeyMap().erase(it);
        } else {
            ++it;
        }
    }
}

template<typename Element>
void CryptoContextImpl<Element>::HESea_InsertEvalAutomorphismKey(
        const shared_ptr <std::map<usint, LPEvalKey < Element>>

> mapToInsert) {
// find the tag
auto onekey = mapToInsert->begin();

evalAutomorphismKeyMap()[onekey->second->GetKeyTag()] = mapToInsert;

}

template<typename Element>
Ciphertext <Element> CryptoContextImpl<Element>::HESea_EvalSum(
        ConstCiphertext <Element> ciphertext, usint batchSize) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
        HESEA_THROW(config_error,
                       "Information passed to EvalSum was not generated with this "
                       "crypto context");

    auto evalSumKeys =
            CryptoContextImpl<Element>::HESea_GetEvalSumKeyMap(ciphertext->GetKeyTag());
    auto rv =
            HESea_GetEncryptionAlgorithm()->EvalSum(ciphertext, batchSize, evalSumKeys);
    return rv;
}

template<typename Element>
Ciphertext <Element> CryptoContextImpl<Element>::HESea_EvalSumRows(
        ConstCiphertext <Element> ciphertext, usint rowSize,
        const std::map <usint, LPEvalKey<Element>> &evalSumKeys,
        usint subringDim) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
        HESEA_THROW(config_error,
                       "Information passed to EvalSum was not generated with this "
                       "crypto context");

    auto rv = HESea_GetEncryptionAlgorithm()->EvalSumRows(ciphertext, rowSize,
                                                    evalSumKeys, subringDim);
    return rv;
}

template<typename Element>
Ciphertext <Element> CryptoContextImpl<Element>::HESea_EvalSumCols(
        ConstCiphertext <Element> ciphertext, usint rowSize,
        const std::map <usint, LPEvalKey<Element>> &evalSumKeysRight) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
        HESEA_THROW(config_error,
                       "Information passed to EvalSum was not generated with this "
                       "crypto context");

    auto evalSumKeys =
            CryptoContextImpl<Element>::HESea_GetEvalSumKeyMap(ciphertext->GetKeyTag());

    auto rv = HESea_GetEncryptionAlgorithm()->EvalSumCols(
            ciphertext, rowSize, evalSumKeys, evalSumKeysRight);
    return rv;
}

template<typename Element>
Ciphertext <Element> CryptoContextImpl<Element>::HESea_EvalAtIndex(
        ConstCiphertext <Element> ciphertext, int32_t index) const {
    if (ciphertext == nullptr || Mismatched(ciphertext->GetCryptoContext()))
        HESEA_THROW(config_error,
                       "Information passed to EvalAtIndex was not generated with "
                       "this crypto context");

    // If the index is zero, no rotation is needed, copy the ciphertext and return
    // This is done after the keyMap so that it is protected if there's not a valid key.
    if (0 == index) {
        auto rv = ciphertext->Clone();
        return rv;
    }

    auto evalAutomorphismKeys =
            CryptoContextImpl<Element>::HESea_GetEvalAutomorphismKeyMap(
                    ciphertext->GetKeyTag());

    auto rv = HESea_GetEncryptionAlgorithm()->EvalAtIndex(ciphertext, index,
                                                    evalAutomorphismKeys);
    return rv;
}

template<typename Element>
Ciphertext <Element> CryptoContextImpl<Element>::HESea_EvalMerge(
        const vector <Ciphertext<Element>> &ciphertextVector) const {
    if (ciphertextVector[0] == nullptr ||
        Mismatched(ciphertextVector[0]->GetCryptoContext()))
        HESEA_THROW(config_error,
                       "Information passed to EvalMerge was not generated with "
                       "this crypto context");

    auto evalAutomorphismKeys =
            CryptoContextImpl<Element>::HESea_GetEvalAutomorphismKeyMap(
                    ciphertextVector[0]->GetKeyTag());

    auto rv = HESea_GetEncryptionAlgorithm()->EvalMerge(ciphertextVector,
                                                  evalAutomorphismKeys);

    return rv;
}

template<typename Element>
Ciphertext <Element> CryptoContextImpl<Element>::HESea_EvalInnerProduct(
        ConstCiphertext <Element> ct1, ConstCiphertext <Element> ct2,
        usint batchSize) const {
    if (ct1 == nullptr || ct2 == nullptr ||
        ct1->GetKeyTag() != ct2->GetKeyTag() ||
        Mismatched(ct1->GetCryptoContext()))
        HESEA_THROW(config_error,
                       "Information passed to EvalInnerProduct was not generated "
                       "with this crypto context");

    auto evalSumKeys =
            CryptoContextImpl<Element>::HESea_GetEvalSumKeyMap(ct1->GetKeyTag());
    auto ek = GetEvalMultKeyVector(ct1->GetKeyTag());

    auto rv = HESea_GetEncryptionAlgorithm()->EvalInnerProduct(ct1, ct2, batchSize,
                                                         evalSumKeys, ek[0]);
    return rv;
}

template<typename Element>
Ciphertext <Element> CryptoContextImpl<Element>::HESea_EvalInnerProduct(
        ConstCiphertext <Element> ct1, ConstPlaintext ct2, usint batchSize) const {
    if (ct1 == nullptr || ct2 == nullptr || Mismatched(ct1->GetCryptoContext()))
        HESEA_THROW(config_error,
                       "Information passed to EvalInnerProduct was not generated "
                       "with this crypto context");

    auto evalSumKeys =
            CryptoContextImpl<Element>::HESea_GetEvalSumKeyMap(ct1->GetKeyTag());

    auto rv = HESea_GetEncryptionAlgorithm()->EvalInnerProduct(ct1, ct2, batchSize,
                                                         evalSumKeys);
    return rv;
}

template<typename Element>
Plaintext CryptoContextImpl<Element>::HESea_GetPlaintextForDecrypt(
        PlaintextEncodings pte, shared_ptr <ParmType> evp, EncodingParams ep) {
    auto vp = std::make_shared<typename NativePoly::Params>(
            evp->GetCyclotomicOrder(), ep->GetPlaintextModulus(), 1);

    if (pte == CKKSPacked) return PlaintextFactory::MakePlaintext(pte, evp, ep);

    return PlaintextFactory::MakePlaintext(pte, vp, ep);
}

template<typename Element>
DecryptResult CryptoContextImpl<Element>::HESea_Decrypt(
        const LPPrivateKey <Element> privateKey, ConstCiphertext <Element> ciphertext,
        Plaintext *plaintext) {
    if (ciphertext == nullptr)
        HESEA_THROW(config_error, "ciphertext passed to Decrypt is empty");
    if (plaintext == nullptr)
        HESEA_THROW(config_error, "plaintext passed to Decrypt is empty");
    if (privateKey == nullptr || Mismatched(privateKey->GetCryptoContext()))
        HESEA_THROW(config_error,
                       "Information passed to Decrypt was not generated with "
                       "this crypto context");

    // determine which type of plaintext that you need to decrypt into
    // Plaintext decrypted =
    // HESea_GetPlaintextForDecrypt(ciphertext->GetEncodingType(),
    // this->GetElementParams(), this->GetEncodingParams());
    Plaintext decrypted = HESea_GetPlaintextForDecrypt(
            ciphertext->GetEncodingType(), ciphertext->GetElements()[0].GetParams(),
            this->HESea_GetEncodingParams());

    DecryptResult result;

    if ((ciphertext->GetEncodingType() == CKKSPacked) &&
        (typeid(Element) != typeid(NativePoly))) {
        result = HESea_GetEncryptionAlgorithm()->Decrypt(privateKey, ciphertext,
                                                   &decrypted->GetElement<Poly>());
    } else {
        result = HESea_GetEncryptionAlgorithm()->Decrypt(
                privateKey, ciphertext, &decrypted->GetElement<NativePoly>());
    }

    if (result.isValid == false) return result;

    if (ciphertext->GetEncodingType() == CKKSPacked) {
        auto decryptedCKKS =
                std::static_pointer_cast<CKKSPackedEncoding>(decrypted);
        decryptedCKKS->SetDepth(ciphertext->GetDepth());
        decryptedCKKS->SetLevel(ciphertext->GetLevel());
        decryptedCKKS->SetScalingFactor(ciphertext->GetScalingFactor());

        const auto cryptoParamsCKKS =
                std::dynamic_pointer_cast < LPCryptoParametersCKKS < DCRTPoly >> (
                        this->HESea_GetCryptoParameters());

        decryptedCKKS->Decode(ciphertext->GetDepth(),
                              ciphertext->GetScalingFactor(),
                              cryptoParamsCKKS->GetRescalingTechnique());

    } else {
        decrypted->Decode();
    }

    *plaintext = std::move(decrypted);
    return result;
}

template<typename Element>
DecryptResult CryptoContextImpl<Element>::HESea_MultipartyDecryptFusion(
        const vector <Ciphertext<Element>> &partialCiphertextVec,
        Plaintext *plaintext) const {
    DecryptResult result;

    // Make sure we're processing ciphertexts.
    size_t last_ciphertext = partialCiphertextVec.size();
    if (last_ciphertext < 1) return result;

    for (size_t i = 0; i < last_ciphertext; i++) {
        if (partialCiphertextVec[i] == nullptr ||
            Mismatched(partialCiphertextVec[i]->GetCryptoContext()))
            HESEA_THROW(config_error,
                           "A ciphertext passed to MultipartyDecryptFusion was not "
                           "generated with this crypto context");
        if (partialCiphertextVec[i]->GetEncodingType() !=
            partialCiphertextVec[0]->GetEncodingType())
            HESEA_THROW(type_error,
                           "Ciphertexts passed to MultipartyDecryptFusion have "
                           "mismatched encoding types");
    }

    // determine which type of plaintext that you need to decrypt into
    Plaintext decrypted = HESea_GetPlaintextForDecrypt(
            partialCiphertextVec[0]->GetEncodingType(),
            partialCiphertextVec[0]->GetElements()[0].GetParams(),
            this->HESea_GetEncodingParams());

    if ((partialCiphertextVec[0]->GetEncodingType() == CKKSPacked) &&
        (typeid(Element) != typeid(NativePoly)))
        result = HESea_GetEncryptionAlgorithm()->MultipartyDecryptFusion(
                partialCiphertextVec, &decrypted->GetElement<Poly>());
    else
        result = HESea_GetEncryptionAlgorithm()->MultipartyDecryptFusion(
                partialCiphertextVec, &decrypted->GetElement<NativePoly>());

    if (result.isValid == false) return result;

    if (partialCiphertextVec[0]->GetEncodingType() == CKKSPacked) {
        auto decryptedCKKS =
                std::static_pointer_cast<CKKSPackedEncoding>(decrypted);
        const auto cryptoParamsCKKS =
                std::dynamic_pointer_cast < LPCryptoParametersCKKS < DCRTPoly >> (
                        this->HESea_GetCryptoParameters());
        decryptedCKKS->Decode(partialCiphertextVec[0]->GetDepth(),
                              partialCiphertextVec[0]->GetScalingFactor(),
                              cryptoParamsCKKS->GetRescalingTechnique());
    } else {
        decrypted->Decode();
    }

    *plaintext = std::move(decrypted);

    return result;
}

}  // namespace lbcrypto
