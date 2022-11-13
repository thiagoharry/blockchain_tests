#ifndef _CHAMELEON_HASH_H_
#define _CHAMELEON_HASH_H_

#include <signaturecontext.h>
#include <cmath>
#include <vector>


namespace lbcrypto {
  template <class Element>
    class ChameleonHashScheme{
  public:
    void Preimage(shared_ptr<LPSignatureParameters<Element>> m_params,const LPSignKey<Element> & sk,const LPVerificationKey<Element> &vk, const LPSignPlaintext<Element> & pt, Element digest, LPSignature<Element>* sign);
    
    void GetRandomParameter(shared_ptr<LPSignatureParameters<Element>> sparams,const LPSignKey<Element> & sk,const LPVerificationKey<Element> &vk, LPSignature<Element>* sign);

    void Hash(shared_ptr<LPSignatureParameters<Element>> m_params,const LPVerificationKey<Element> & vk, const LPSignature<Element> & sign, const LPSignPlaintext<Element> & pt, Element *digest);

    void KeyGen(shared_ptr<LPSignatureParameters<Element>> m_params,LPSignKey<Element>* sk, LPVerificationKey<Element>* vk);
  private:
    std::vector<char> seed;
    void forceImplement(){} 
  };
}
#endif
