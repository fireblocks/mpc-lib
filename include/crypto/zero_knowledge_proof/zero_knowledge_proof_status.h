#ifndef __ZERO_KNOWLEDGE_PROOF_STATUS_H__
#define __ZERO_KNOWLEDGE_PROOF_STATUS_H__

typedef enum
{
    ZKP_SUCCESS               =  0,
    ZKP_UNKNOWN_ERROR         = -1,
    ZKP_INVALID_PARAMETER     = -2,
    ZKP_INSUFFICIENT_BUFFER   = -3,
    ZKP_VERIFICATION_FAILED   = -4,
    ZKP_OUT_OF_MEMORY         = -5,
} zero_knowledge_proof_status;

#endif // __ZERO_KNOWLEDGE_PROOF_STATUS_H__