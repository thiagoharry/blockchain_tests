#ifndef _CONTEXT_H
#define _CONTEXT_H

#include "chameleon_hash_ring_sis.h"

namespace lbcrypto{
  template <class Element>
    class ChameleonHashContext{
  public:
    ChameleonHashContext(){}
    void GenerateGPVContext(usint ringsize,usint bitwidth,usint base);
    void GenerateGPVContext(usint ringsize);
    void KeyGen(LPSignKey<Element>* sk, LPVerificationKey<Element>* vk);
    //void Sign(const LPSignPlaintext<Element> & pt,const LPSignKey<Element> & sk, const LPVerificationKey<Element> & vk,LPSignature<Element>* sign);
    void Preimage(const LPSignPlaintext<Element> & pt, Element digest, const LPSignKey<Element> & sk, const LPVerificationKey<Element> & vk, LPSignature<Element>* r);
    void GetRandomParameter(const LPSignKey<Element> & sk, const LPVerificationKey<Element> & vk,LPSignature<Element>* sign);
    void Hash(const LPSignPlaintext<Element> & pt, const LPSignature<Element> & signature, const LPVerificationKey<Element> & vk, Element *digest);
    template<class Archive>
      void serialize(Archive & hk, Archive & pk)
      {
	hk(m_params); // serialize things by passing them to the archive
      }
  private:
    //The signature scheme used
    shared_ptr<ChameleonHashScheme<Element>> m_scheme;
    //Parameters related to the scheme
    shared_ptr<LPSignatureParameters<Element>> m_params;
  };   
}

void test(void);

#endif
