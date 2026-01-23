/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DISPLAY_CHANGE_EVENT_LISTENER_H
#define DISPLAY_CHANGE_EVENT_LISTENER_H

#include "display_manager.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

#include "i_context.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DisplayChangeEventListener : public Rosen::DisplayManager::IDisplayListener {
public:
    explicit DisplayChangeEventListener(IContext *context);
    ~DisplayChangeEventListener() = default;
    void OnCreate(Rosen::DisplayId displayId) override;
    void OnDestroy(Rosen::DisplayId displayId) override;
    void OnChange(Rosen::DisplayId displayId) override;
    void GetAllScreenAngles();
    bool IsRotateDragScreen();
    bool IsFoldPC() const { return isFoldPC_.load(); }
    void SetFoldPC(bool value) { isFoldPC_.store(value); }

private:
    void RotateDragWindow(Rosen::DisplayId displayId, Rosen::Rotation rotation);
    void ScreenRotate(Rosen::Rotation rotation, Rosen::Rotation lastRotation);
    Rosen::Rotation GetRotation(Rosen::DisplayId displayId);
    bool IsRotation(Rosen::DisplayId displayId, Rosen::Rotation CurrentRotation);
    sptr<Rosen::DisplayInfo> GetDisplayInfoById(Rosen::DisplayId displayId);
    sptr<Rosen::DisplayInfo> GetDisplayInfo(Rosen::DisplayId displayId);
    void HandleScreenRotation(Rosen::DisplayId displayId, Rosen::Rotation rotation);

private:
    IContext *context_ { nullptr };
    std::atomic_bool isFoldPC_ { false };
};

class DisplayAbilityStatusChange : public SystemAbilityStatusChangeStub {
public:
    explicit DisplayAbilityStatusChange(IContext *context);
    ~DisplayAbilityStatusChange() = default;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    sptr<DisplayChangeEventListener> displayChangeEventListener_ { nullptr };
    IContext *context_ { nullptr };
};

class AppStateObserverStatusChange : public SystemAbilityStatusChangeStub {
public:
    explicit AppStateObserverStatusChange(IContext *context);
    ~AppStateObserverStatusChange() = default;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    IContext *context_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DISPLAY_CHANGE_EVENT_LISTENER_H