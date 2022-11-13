#include <iostream>
#include <fstream>
#include "chameleon_hash_ring_sis.h"

using namespace std;

namespace lbcrypto {

  template <class Element>
  void ChameleonHashScheme<Element>::KeyGen(shared_ptr<LPSignatureParameters<Element>> sparams,LPSignKey<Element>* sk, LPVerificationKey<Element>* vk) {
    GPVSignKey<Element>* signKey = dynamic_cast<GPVSignKey<Element>*>(sk);
    GPVVerificationKey<Element>* verificationKey = dynamic_cast<GPVVerificationKey<Element>*>(vk);
    shared_ptr<GPVSignatureParameters<Element>> m_params = std::dynamic_pointer_cast<GPVSignatureParameters<Element>>(sparams);
    //Get parameters from keys
    shared_ptr<typename Element::Params> params = m_params->GetILParams();
    auto stddev = m_params->GetDiscreteGaussianGenerator().GetStd();
    usint base = m_params->GetBase();
    ifstream urandom("/dev/urandom", ios::in|ios::binary);

    //Generate trapdoor based using parameters and 
    std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> keyPair = RLWETrapdoorUtility<Element>::TrapdoorGen(params, stddev, base);
    //Format of vectors are changed to prevent complications in calculations 
    keyPair.second.m_e.SetFormat(EVALUATION);
    keyPair.second.m_r.SetFormat(EVALUATION);
    keyPair.first.SetFormat(EVALUATION);

    //Verification key will be set to the uniformly sampled matrix used in trapdoor
    verificationKey->SetVerificationKey(std::make_shared<Matrix<Element>>(keyPair.first));

    //Signing key will contain public key matrix of the trapdoor and the trapdoor matrices
    signKey->SetSignKey(std::make_shared<RLWETrapdoorPair<Element>>(keyPair.second));
    size_t n = params->GetRingDimension();
    if (n > 32) {
      for (size_t i = 0;i < n - 32;i = i + 4) {
	int r;
	//r = (PseudoRandomNumberGenerator::GetPRNG())(); // Conflicting... :-/
	//r = rand(); // Bad. :-(
	urandom.read(reinterpret_cast<char*>(&r), sizeof(int));
	seed.push_back((r >> 24) & 0xFF);
	seed.push_back((r >> 16) & 0xFF);
	seed.push_back((r >> 8) & 0xFF);
	seed.push_back((r) & 0xFF);
      }
    }
    urandom.close();
  }


  template <class Element>
  void ChameleonHashScheme<Element>::Preimage(shared_ptr<LPSignatureParameters<Element>> sparams,const LPSignKey<Element> & sk,const LPVerificationKey<Element> &vk, const LPSignPlaintext<Element> & pt, Element dgt, LPSignature<Element>* sign){		
    shared_ptr<GPVSignatureParameters<Element>> m_params = std::dynamic_pointer_cast<GPVSignatureParameters<Element>>(sparams);
    const GPVSignKey<Element> & signKey = dynamic_cast<const GPVSignKey<Element> &>(sk);
    const GPVVerificationKey<Element> & verificationKey = dynamic_cast<const GPVVerificationKey<Element> &>(vk);
    const GPVPlaintext<Element> & plainText = dynamic_cast<const GPVPlaintext<Element> &>(pt);
    GPVSignature<Element>* signatureText = dynamic_cast<GPVSignature<Element>*>(sign);

    //Getting parameters for calculations
    size_t n = m_params->GetILParams()->GetRingDimension();
    size_t k = m_params->GetK();
    size_t base = m_params->GetBase();

    EncodingParams ep( new EncodingParamsImpl(PlaintextModulus(512)) );

    //Encode the text into a vector so it can be used in signing process. TODO: Adding some kind of digestion algorithm
    vector<int64_t> digest;
    HashUtil::Hash(plainText.GetPlaintext(), SHA_256, digest);
    if(plainText.GetPlaintext().size() <= n ) {
      for(size_t i = 0;i < n - 32;i = i + 4)
	digest.push_back(seed[i]);
    }
    Plaintext hashedText( new CoefPackedEncoding(m_params->GetILParams(), ep, digest) );
    hashedText->Encode();
    
    Element &u = hashedText->GetElement<Element>();
    u.SwitchFormat();

    u = dgt - u;
    
    //Getting the trapdoor, its public matrix, perturbation matrix and gaussian generator to use in sampling
    const Matrix<Element> & A = verificationKey.GetVerificationKey();
    const RLWETrapdoorPair<Element> & T = signKey.GetSignKey();
    typename Element::DggType & dgg = m_params->GetDiscreteGaussianGenerator();

    typename Element::DggType & dggLargeSigma = m_params->GetDiscreteGaussianGeneratorLargeSigma();
    Matrix<Element> zHat = RLWETrapdoorUtility<Element>::GaussSamp(n,k,A,T,u,dgg,dggLargeSigma,base);
    signatureText->SetSignature(std::make_shared<Matrix<Element>>(zHat));    
  }


  template <class Element>
  void ChameleonHashScheme<Element>::GetRandomParameter(shared_ptr<LPSignatureParameters<Element>> sparams,
							const LPSignKey<Element> & sk,const LPVerificationKey<Element> &vk,
							LPSignature<Element>* sign){
    using ParmType = typename Element::Params;
    GPVSignature<Element>* signatureText = dynamic_cast<GPVSignature<Element>*>(sign);
    shared_ptr<GPVSignatureParameters<Element>> m_params = std::dynamic_pointer_cast<GPVSignatureParameters<Element>>(sparams);
    const GPVVerificationKey<Element> & verificationKey = dynamic_cast<const GPVVerificationKey<Element> &>(vk);
    const Matrix<Element> & A = verificationKey.GetVerificationKey();
    const shared_ptr<ParmType> params = A(0, 0).GetParams();
    auto alloc = Element::MakeDiscreteGaussianCoefficientAllocator(params, Format::EVALUATION, SIGMA);
    Matrix<Element> zHat(alloc, 30, 1);
    signatureText->SetSignature(std::make_shared<Matrix<Element>>(zHat));    
  }

    

  //Method for verifying given object & signature
  template <class Element>
  void ChameleonHashScheme<Element>::Hash(shared_ptr<LPSignatureParameters<Element>> sparams,const LPVerificationKey<Element> & vk,const LPSignature<Element> & sign, const LPSignPlaintext<Element> & pt, Element *dgt) {		
    shared_ptr<GPVSignatureParameters<Element>> m_params = std::dynamic_pointer_cast<GPVSignatureParameters<Element>>(sparams);
    const GPVVerificationKey<Element> & verificationKey = dynamic_cast<const GPVVerificationKey<Element> &>(vk);
    const GPVPlaintext<Element> & plainText = dynamic_cast<const GPVPlaintext<Element> &>(pt);
    const GPVSignature<Element> & signatureText = dynamic_cast<const GPVSignature<Element> &>(sign);
    size_t n = m_params->GetILParams()->GetRingDimension();

    EncodingParams ep( new EncodingParamsImpl(PlaintextModulus(512)) );

    //Encode the text into a vector so it can be used in signing process. TODO: Adding some kind of digestion algorithm
    vector<int64_t> digest;
    Plaintext hashedText;
    HashUtil::Hash(plainText.GetPlaintext(), SHA_256, digest);
    
    if( plainText.GetPlaintext().size() <= n ) {
      for (size_t i = 0;i < n - 32;i = i + 4)
	digest.push_back(seed[i]);
    }

    hashedText.reset( new CoefPackedEncoding(m_params->GetILParams(), ep, digest) );
    hashedText->Encode();

    Element &u = hashedText->GetElement<Element>();
    u.SwitchFormat();
    
    //Multiply signature with the verification key
    const Matrix<Element> & A = verificationKey.GetVerificationKey();
    const Matrix<Element> & z = signatureText.GetSignature();
    
    //Check the verified vector is actually the encoding of the object
    *dgt = u + (A*z)(0, 0);
    return;
  }

  template class ChameleonHashScheme<NativePoly>;
}
