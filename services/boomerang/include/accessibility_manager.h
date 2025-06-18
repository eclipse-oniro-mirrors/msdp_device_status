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

#ifndef ACCESSIBILITY_MANAGER_H
#define ACCESSIBILITY_MANAGER_H

#include <vector>

#include <functional>
#include "nocopyable.h"
#include "singleton.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum AccessibilityStatu {
    ABILITY_INVALID_STATU,
    ON_ABILITY_CONNECTED = 1,
    ON_ABILITY_SCROLLED_EVENT,
    ON_ABILITY_DISCONNECTED,
};

using AccessibilityCallback = std::function<void(int32_t)>;

struct DragElementInfo {
    int64_t rsNodeId { -1 };
    int32_t leftTopX { -1 };
    int32_t leftTopY { -1 };
    int32_t targetWindowId { -1 };
    std::string componentType;
    std::string content;
    int64_t accessibilityId { -1};
    void Dump();
};

class AccessibilityManager final {
    DECLARE_SINGLETON(AccessibilityManager);
public:
    DISALLOW_MOVE(AccessibilityManager);

    void AccessibilityConnect(AccessibilityCallback callback);
    void AccessibilityDisconnect();
    int32_t FindElementInfo(const int32_t windowId, DragElementInfo &info);
};

#define ACCESSIBILITY_MANAGER OHOS::Singleton<AccessibilityManager>::GetInstance()
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ACCESSIBILITY_MANAGER_H