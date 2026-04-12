#ifndef __STATUS_CONVERT_H__
#define __STATUS_CONVERT_H__

#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve_algebra_status.h"
#include "crypto/drng/drng.h"
#include "crypto/paillier/paillier.h"
#include "crypto/commitments/ring_pedersen.h"

ring_pedersen_status algebra_to_ring_pedersen_status(const elliptic_curve_algebra_status status);
zero_knowledge_proof_status convert_drng_to_zkp_status(const drng_status status);
zero_knowledge_proof_status convert_paillier_to_zkp_status(const long status);
zero_knowledge_proof_status convert_ring_pedersen_to_zkp_status(const ring_pedersen_status status);
zero_knowledge_proof_status convert_algebra_to_zkp_status(const elliptic_curve_algebra_status status);


#endif //__STATUS_CONVERT_H__