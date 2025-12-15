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

#ifndef DRAG_SECURITY_MANAGER_H
#define DRAG_SECURITY_MANAGER_H

#include <map>
#include <vector>
#include <cstdint>
#include <chrono>
#include <memory>

#include "drag_auth.h"
#include "drag_data.h"
#include "fi_log.h"
#include "input_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class DragSecurityManager {
public:
    DragSecurityManager(const DragSecurityManager&) = delete;
    DragSecurityManager& operator=(const DragSecurityManager&) = delete;
    static DragSecurityManager& GetInstance();

    bool VerifyAndResetNonce(const DragEventData& eventData, const std::string signature);
    int32_t DeliverNonceToInput();
    void StoreSecurityPid(int32_t pid);
    bool VerifySecurityPid(int32_t pid);
    void ResetSecurityPid();

private:
    DragSecurityManager();
    ~DragSecurityManager() = default;

    int32_t securityPid_ { -1 };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#define DRAG_SECURITY_MANAGER OHOS::Msdp::DeviceStatus::DragSecurityManager::GetInstance()
#endif // DRAG_SECURITY_MANAGER_H