/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef EVENT_HUB_H
#define EVENT_HUB_H

#include <string>
#include <vector>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "iservice_registry.h"
#include "refbase.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

#include "i_context.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum class EventId {
    EVENT_APP_RUN_FRONT = 1,
    EVENT_SCREEN_ON,
    EVENT_SCREEN_OFF,
    EVENT_SCREEN_LOCK,
    EVENT_SCREEN_UNLOCK,
    EVENT_BATTERY_LOW,
    EVENT_BATTERY_OKAY,
    EVENT_MAX,
    EVENT_LOCALE_CHANGED,
};
class EventHub : public OHOS::EventFwk::CommonEventSubscriber {
public:
    EventHub(const OHOS::EventFwk::CommonEventSubscribeInfo &info, IContext* context)
        : CommonEventSubscriber(info), context_(context) {}
    ~EventHub() override = default;

    static std::shared_ptr<EventHub> GetEventHub(IContext* context);
    static void RegisterEvent(std::shared_ptr<EventHub> eventHub);
    static void UnRegisterEvent(std::shared_ptr<EventHub> eventHub);

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &event) override;

private:
    IContext* context_ { nullptr };
};
class DragAbilityStatusChange : public SystemAbilityStatusChangeStub {
public:
    explicit DragAbilityStatusChange(std::shared_ptr<EventHub> eventHub);
    ~DragAbilityStatusChange() = default;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    std::shared_ptr<EventHub> eventHub_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // EVENT_HUB_H