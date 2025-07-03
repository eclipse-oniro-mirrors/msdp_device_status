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

#ifndef ONSCREEN_MANAGER_H
#define ONSCREEN_MANAGER_H

#include <functional>
#include <memory>

#include "nocopyable.h"

#include "devicestatus_common.h"
#include "on_screen_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
class OnScreenManager {
public:
    /**
     * @brief Obtains a <b>OnScreenManager</b> instance.
     * @return Returns a <b>OnScreenManager</b> instance.
     * @since 20
     */
    static OnScreenManager &GetInstance();

    /**
     * @brief Get page content.
     * @param option page content option
     * @param pageContent page content obtained by interface
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 20
     */
    int32_t GetPageContent(const ContentOption& option, PageContent& pageContent);

    /**
     * @brief Send control event to control screen action
     * @param event control event
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 20
     */
    int32_t SendControlEvent(const ControlEvent& event);
private:
    OnScreenManager() = default;
    DISALLOW_COPY_AND_MOVE(OnScreenManager);
};
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ON_SCREEN_MANAGER_H