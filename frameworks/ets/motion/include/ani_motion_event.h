/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ANI_MOTION_EVNET_H
#define ANI_MOTION_EVNET_H

#include "ohos.multimodalAwareness.motion.proj.hpp"
#include "ohos.multimodalAwareness.motion.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "ani.h"
#include <set>
#include <map>

#ifdef MOTION_ENABLE
#include "motion_callback_stub.h"
#endif

namespace OHOS {
namespace Msdp {

constexpr int32_t MOTION_TYPE_OPERATING_HAND = 3601;
struct MotionEventListener {
    std::set<ani_ref> onRefSets;
};
#ifdef MOTION_ENABLE
class AniMotionCallback : public MotionCallbackStub {
public:
    AniMotionCallback() = default;
    ~AniMotionCallback() override {};
    void OnMotionChanged(const MotionEvent& event) override;
    void AniMotionCallback::EmitOnEvent(MotionEvent* data);
};
#endif

class AniMotionEvent {
public:
    static std::shared_ptr<AniMotionEvent> GetInstance();
    AniMotionEvent() = default;
    ~AniMotionEvent();
#ifdef MOTION_ENABLE
    bool CheckEvents(int32_t eventType);
    bool SubscribeCallback(int32_t type);
    bool UnSubscribeCallback(int32_t type);
    bool InsertRef(std::shared_ptr<MotionEventListener> listener, ani_ref onHandlerRef);
    bool AddCallback(int32_t eventType, taihe::callback_view<void(OperatingHandStatus_t)> f, uintptr_t opq);
    bool RemoveAllCallback(int32_t eventType);
    bool RemoveCallback(int32_t eventType, uintptr_t opq);
    void AniMotionEvent::OnEventOperatingHand(int32_t eventType, size_t argc, const MotionEvent &event);
#endif
public:
#ifdef MOTION_ENABLE
    std::mutex mutex_;
    std::map<int32_t, sptr<IMotionCallback>> callbacks_;
#endif
protected:
    std::map<int32_t, std::shared_ptr<MotionEventListener>> events_;
};
} // namespace Msdp
} // namespace OHOS
#endif // ANI_MOTION_EVNET_H