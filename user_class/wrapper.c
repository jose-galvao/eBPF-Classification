#include <stdint.h>
#include "model500msJANELA.h"

int32_t predict_wrapper(float cur_mean, float cur_var, float prev_mean, float prev_var) {
    
    int64_t features[4];

    features[0] = (int64_t)cur_mean;
    features[1] = (int64_t)cur_var;
    features[2] = (int64_t)prev_mean;
    features[3] = (int64_t)prev_var;

    return model_predict(features, 4);
}