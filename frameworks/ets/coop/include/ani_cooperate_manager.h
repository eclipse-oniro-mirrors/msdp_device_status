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

#ifndef ANI_COOPERATE_MANAGER_H
#define ANI_COOPERATE_MANAGER_H

#include <mutex>
#include <string>

#include "cooperate_common.h"
#include "ani_event_cooperate_target.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class AniCooperateManager final {
public:
    enum class CooperateMessage {
        INFO_START = 0,
        INFO_SUCCESS = 1,
        INFO_FAIL = 2,
        STATE_ON = 3,
        STATE_OFF = 4
    };
    static AniCooperateManager& GetInstance();
    AniCooperateManager();
    DISALLOW_COPY_AND_MOVE(AniCooperateManager);
    ~AniCooperateManager();
    void Enable(bool enable, uintptr_t opq, ani_object& promise);
    void Start(const std::string &remoteNetworkDescriptor,
        int32_t startDeviceId, uintptr_t opq, ani_object& promise);
    void Stop(uintptr_t opq, ani_object& promise);
    void GetState(const std::string &deviceDescriptor, uintptr_t opq, ani_object& promise);
    void OnCooperation(uintptr_t opq);
    void OffCooperation(::taihe::optional_view<uintptr_t> opq);
    void OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg);
    void EmitCoordinationMessageEvent(std::shared_ptr<AniCallbackInfo> cb);
protected:
    void EmitAni(std::shared_ptr<AniCallbackInfo> cb);
    void EmitAniPromise(std::shared_ptr<AniCallbackInfo> cb);
    void EmitAniAsyncCallback(std::shared_ptr<AniCallbackInfo> cb);
    void EmitGetState(std::shared_ptr<AniCallbackInfo> cb);
private:
    std::mutex mutex_;
    std::map<std::string, std::vector<std::shared_ptr<AniCallbackInfo>>>
        coordinationListeners_ {};
    std::atomic_bool isListeningProcess_ { false };
    std::shared_ptr<AniEventCooperateTarget>  listener_ {nullptr};
    inline static std::map<CoordinationMessage, CooperateMessage> messageTransform_ = {
        { CoordinationMessage::PREPARE, CooperateMessage::STATE_ON },
        { CoordinationMessage::UNPREPARE, CooperateMessage::STATE_OFF },
        { CoordinationMessage::ACTIVATE, CooperateMessage::INFO_START },
        { CoordinationMessage::ACTIVATE_SUCCESS, CooperateMessage::INFO_SUCCESS },
        { CoordinationMessage::ACTIVATE_FAIL, CooperateMessage::INFO_FAIL }
    };
};
#define ANI_COOPERATE_MGR AniCooperateManager::GetInstance()
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // JS_COOPERATE_MANAGER_H
