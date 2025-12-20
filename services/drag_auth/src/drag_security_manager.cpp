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

#include "drag_security_manager.h"
#include "devicestatus_define.h"
#include <algorithm>
#include <chrono>

#undef LOG_TAG
#define LOG_TAG "DragSecurityManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

DragSecurityManager& DragSecurityManager::GetInstance()
{
    static DragSecurityManager instance;
    return instance;
}

DragSecurityManager::DragSecurityManager() {}

bool DragSecurityManager::VerifyAndResetNonce(const DragEventData& eventData, const std::string signature)
{
    CALL_INFO_TRACE;
    if (!DRAG_AUTH.VerifySignature(eventData, signature)) {
        FI_HILOGE("Signature verification failed");
        return false;
    }
    DRAG_AUTH.ResetNonce();
    return true;
}
 
int32_t DragSecurityManager::DeliverNonceToInput()
{
    CALL_INFO_TRACE;
    auto nonce = DRAG_AUTH.GenerateNonce();
    if (nonce.empty()) {
        FI_HILOGE("Generate nonce failed");
        return RET_ERR;
    }
    if (MMI::InputManager::GetInstance()->DeliverNonce(nonce) == RET_ERR) {
        FI_HILOGE("Deliver nonce failed");
        return RET_ERR;
    }
    return RET_OK;
}
 
void DragSecurityManager::StoreSecurityPid(int32_t pid)
{
    FI_HILOGI("Store security pid:%{public}d", pid);
    securityPid_ = pid;
}
 
bool DragSecurityManager::VerifySecurityPid(int32_t pid)
{
    if (pid != securityPid_) {
        FI_HILOGE("Verify pid:%{public}d, security pid:%{public}d", pid, securityPid_);
        return false;
    }
    return true;
}
 
void DragSecurityManager::ResetSecurityPid()
{
    securityPid_ = -1;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS