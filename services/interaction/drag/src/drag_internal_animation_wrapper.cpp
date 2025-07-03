/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include "drag_internal_animation_wrapper.h"
 
#include <dlfcn.h>

#include "devicestatus_define.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DragInternalAnimationWrapper"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
const std::string DRAG_INTERNAL_ANIMATION_SO_PATH = "system/lib64/libdrag_internal_animation.z.so";
}

DragInternalAnimationWrapper::~DragInternalAnimationWrapper()
{
    FI_HILOGI("Enter");
    if (dragInternalAnimationHandle_ != nullptr) {
        dlclose(dragInternalAnimationHandle_);
        dragInternalAnimationHandle_ = nullptr;
    }
}

bool DragInternalAnimationWrapper::Init()
{
    FI_HILOGI("Enter");
    if (dragInternalAnimationHandle_ == nullptr) {
        dragInternalAnimationHandle_ = dlopen(DRAG_INTERNAL_ANIMATION_SO_PATH.c_str(), RTLD_LAZY);
        char *error = nullptr;
        if (((error = dlerror()) != nullptr) || (dragInternalAnimationHandle_ == nullptr)) {
            FI_HILOGE("Couldn't load universal drag handler library with dlopen(). Error: %{public}s", error);
            return false;
        }
    }
    return true;
}

int32_t DragInternalAnimationWrapper::EnableInternalDropAnimation(const std::string &animationInfo)
{
    FI_HILOGI("Enter");
    if ((dragInternalAnimationHandle_ == nullptr) && (!Init())) {
        FI_HILOGE("Init internal animation handle fail");
        return RET_ERR;
    }
    if (enableInternalDropAnimationHandle_ == nullptr) {
        enableInternalDropAnimationHandle_ =
            reinterpret_cast<EnableInternalDropAnimationFunc>(dlsym(dragInternalAnimationHandle_,
            "EnableInternalDropAnimation"));
        char *error = nullptr;
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Symbol enableInternalDropAnimation error: %{public}s", error);
            return RET_ERR;
        }
    }
    if (enableInternalDropAnimationHandle_ == nullptr) {
        FI_HILOGE("Symbol enableInternalDropAnimationHandle is null");
        return RET_ERR;
    }
    return enableInternalDropAnimationHandle_(animationInfo.c_str());
}

int32_t DragInternalAnimationWrapper::PerformInternalDropAnimation(IContext* env)
{
    CALL_DEBUG_ENTER;
    if ((dragInternalAnimationHandle_ == nullptr) && (!Init())) {
        FI_HILOGE("Init internal animation handle fail");
        return RET_ERR;
    }
    if (performInternalDropAnimationHandle_ == nullptr) {
        performInternalDropAnimationHandle_ =
            reinterpret_cast<PerformInternalDropAnimationFunc>(dlsym(dragInternalAnimationHandle_,
            "PerformInternalDropAnimation"));
        char *error = nullptr;
        if ((error = dlerror()) != nullptr) {
            FI_HILOGE("Symbol performInternalDropAnimationHandle error: %{public}s", error);
            return RET_ERR;
        }
    }

    if (performInternalDropAnimationHandle_ == nullptr) {
        FI_HILOGE("Symbol performInternalDropAnimationHandle is null");
        return RET_ERR;
    }
    return performInternalDropAnimationHandle_(env);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS