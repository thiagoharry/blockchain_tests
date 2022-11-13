/**
 * @file signaturecontext.cpp - Implementation file for signature context class
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <signaturecontext.h>
#include "chameleon_hash.h"
#include "context.h"

void test(void){
  printf("OK OK\n");
}

namespace lbcrypto{
  //Method for setting up a GPV context with specific parameters
  template <class Element>
  void ChameleonHashContext<Element>::GenerateGPVContext(usint ringsize,usint bits,usint base){
    
    usint sm = ringsize * 2;
    double stddev = SIGMA;
    typename Element::DggType dgg(stddev);
    typename Element::Integer smodulus;
    typename Element::Integer srootOfUnity;
   
    smodulus = FirstPrime<typename Element::Integer>(bits,sm);
    srootOfUnity = RootOfUnity(sm, smodulus);
    ILParamsImpl<typename Element::Integer> ilParams = ILParamsImpl<typename Element::Integer>(sm, smodulus, srootOfUnity);

    ChineseRemainderTransformFTT<typename Element::Vector>::PreCompute(srootOfUnity, sm, smodulus);
    DiscreteFourierTransform::PreComputeTable(sm);
        
    shared_ptr<ILParamsImpl<typename Element::Integer>> silparams = std::make_shared<ILParamsImpl<typename Element::Integer>>(ilParams);
    shared_ptr<LPSignatureParameters<Element>> signparams(new GPVSignatureParameters<Element>(silparams,dgg,base));
    shared_ptr<ChameleonHashScheme<Element>> scheme(new ChameleonHashScheme<Element>());
    m_params = signparams;
    m_scheme = scheme;
  }
  //Method for setting up a GPV context with desired security level only
  template <class Element>
  void ChameleonHashContext<Element>::GenerateGPVContext(usint ringsize){
    
    usint base, k;
    switch(ringsize){
    case 512:
      k = 24;
      base = 8;
      break;
    case 1024:
      k = 27;
      base = 64;
      break;
    default:
      PALISADE_THROW(config_error, "Unknown ringsize");
    }
    GenerateGPVContext(ringsize,k,base);
  }
  //Method for key generation
  template <class Element>
  void ChameleonHashContext<Element>::KeyGen(LPSignKey<Element>* sk, LPVerificationKey<Element>* vk){
    m_scheme->KeyGen(m_params,sk,vk);
  }

  template <class Element>
  void ChameleonHashContext<Element>::GetRandomParameter(const LPSignKey<Element> & sk, const LPVerificationKey<Element> & vk,LPSignature<Element>* sign){
    m_scheme->GetRandomParameter(m_params,sk,vk,sign);
  }

  template <class Element>
  void ChameleonHashContext<Element>::Preimage(const LPSignPlaintext<Element> & pt, Element digest, const LPSignKey<Element> & sk, const LPVerificationKey<Element> & vk, LPSignature<Element>* r){
    m_scheme->Preimage(m_params,sk,vk,pt,digest,r);
  }
  
  template <class Element>
  void ChameleonHashContext<Element>::Hash(const LPSignPlaintext<Element> & pt,
					       const LPSignature<Element> & signature, const LPVerificationKey<Element> & vk, Element *digest){
    m_scheme->Hash(m_params,vk,signature,pt, digest);
  }

  template class ChameleonHashContext<NativePoly>;
}
