#pragma once

#include "cosigner/types.h"

namespace fireblocks
{
namespace common
{
namespace cosigner
{

struct cmp_signature_preprocessed_data
{
    elliptic_curve_scalar k;
    elliptic_curve_scalar chi;
    elliptic_curve_point R;
};

}
}
}