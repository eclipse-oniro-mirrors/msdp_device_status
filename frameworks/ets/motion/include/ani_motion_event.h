/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANI_MOTION_EVENT_H
#define ANI_MOTION_EVENT_H

#include "ohos.multimodalAwareness.motion.proj.hpp"
#include "ohos.multimodalAwareness.motion.impl.hpp"
#include "taihe/runtime.hpp"
#include <stdexcept>
#include "ani.h"
#include <set>
#include <map>
#include "fi_log.h"

#ifdef MOTION_ENABLE
#include "motion_callback_stub.h"
#include "motion_agent_type.h"
#endif

namespace OHOS {
namespace Msdp {
const int32_t RET_OK = 0;
constexpr int32_t PERMISSION_DENIED { 201 };
constexpr int32_t NO_SYSTEM_API { 202 };
constexpr int32_t PARAM_EXCEPTION { 401 };
constexpr int32_t DEVICE_EXCEPTION { 801 };
constexpr int32_t SERVICE_EXCEPTION { 31500001 };
constexpr int32_t SUBSCRIBE_EXCEPTION { 31500002 };
constexpr int32_t UNSUBSCRIBE_EXCEPTION { 31500003 };
constexpr int32_t HOLDING_HAND_FEATURE_DISABLE = 11;
using OperatingHandStatus_t = ohos::multimodalAwareness::motion::OperatingHandStatus;
constexpr int32_t MOTION_TYPE_OPERATING_HAND = 3601;
struct MotionEventListener {
    std::set<ani_ref> onRefSets;
};

#ifdef MOTION_ENABLE
class AniMotionCallback : public MotionCallbackStub {
public:
    AniMotionCallback() = default;
    ~AniMotionCallback() override = default;
    void OnMotionChanged(const MotionEvent& event) override;
    void EmitOnEvent(std::shared_ptr<MotionEvent> data);
};
#endif

class AniMotionEvent {
public:
    static std::shared_ptr<AniMotionEvent> GetInstance();
    AniMotionEvent() = default;
    ~AniMotionEvent() = default;
#ifdef MOTION_ENABLE
    bool CheckEvents(int32_t eventType);
    bool SubscribeCallback(int32_t type);
    bool UnSubscribeCallback(int32_t type);
    bool InsertRef(std::shared_ptr<MotionEventListener> listener, ani_ref onHandlerRef);
    bool AddCallback(int32_t eventType, uintptr_t opq, ani_vm* vm);
    bool RemoveAllCallback(int32_t eventType);
    bool RemoveCallback(int32_t eventType, uintptr_t opq);
    void OnEventOperatingHand(int32_t eventType, size_t argc, const std::shared_ptr<MotionEvent> &event);
    static ani_vm* GetAniVm(ani_env* env);
    static ani_env* GetAniEnv(ani_vm* vm);
    static ani_env* AttachAniEnv(ani_vm* vm);
    ani_enum_item CreateAniHoldingHandStatus(ani_env* env, int32_t status);
    ani_enum_item CreateAniOperatingHandStatus(ani_env* env, int32_t status);
    ani_object CreateAniUndefined(ani_env* env);
#endif

public:
#ifdef MOTION_ENABLE
    std::mutex mutex_;
    std::map<int32_t, sptr<IMotionCallback>> callbacks_;
#endif

private:
    static ani_env* env_;
    static ani_vm* vm_;
    
protected:
    std::map<int32_t, std::shared_ptr<MotionEventListener>> events_;
};
} // namespace Msdp
} // namespace OHOS
#endif // ANI_MOTION_EVNET_H