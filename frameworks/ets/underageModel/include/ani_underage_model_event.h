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

#ifndef ANI_UNDERAGE_MODEL_EVENT_H
#define ANI_UNDERAGE_MODEL_EVENT_H

#include "ohos.multimodalAwareness.underageModel.proj.hpp"
#include "ohos.multimodalAwareness.underageModel.impl.hpp"
#include "taihe/runtime.hpp"
#include <stdexcept>
#include "ani.h"
#include <set>
#include <map>
#include "fi_log.h"
#include "ani_error_utils.h"
namespace OHOS {
namespace Msdp {
const int32_t RET_OK = 0;
using UserClassification_t = ohos::multimodalAwareness::underageModel::UserClassification;
constexpr uint32_t UNDERAGE_MODEL_TYPE_KID = 16;
constexpr int32_t PERMISSION_EXCEPTION { 201 };
constexpr int32_t PARAM_EXCEPTION { 401 };
constexpr int32_t DEVICE_EXCEPTION { 801 };
constexpr int32_t SERVICE_EXCEPTION { 33900001 };
constexpr int32_t SUBSCRIBE_EXCEPTION { 33900002 };
constexpr int32_t UNSUBSCRIBE_EXCEPTION { 33900003 };

struct UnderageModelEventListener {
    std::set<ani_ref> onRefSets;
};

class IUnderageModelListener {
public:
    IUnderageModelListener() = default;
    virtual ~IUnderageModelListener() = default;
    virtual void OnUnderageModelListener(uint32_t eventType, int32_t result, float confidence) const = 0;
};

typedef int32_t (*RegisterListenerFunc)(uint32_t feature,
    std::shared_ptr<IUnderageModelListener> listener);
typedef int32_t (*SubscribeFunc)(uint32_t feature);
typedef int32_t (*UnsubscribeFunc)(uint32_t feature);

class UnderageModelListener : public IUnderageModelListener {
public:
    explicit UnderageModelListener() {}
    ~UnderageModelListener() {};
    void OnUnderageModelListener(uint32_t eventType, int32_t result, float confidence) const override;
};

class AniUnderageModelEvent {
public:
    static std::shared_ptr<AniUnderageModelEvent> GetInstance();
    AniUnderageModelEvent() = default;
    ~AniUnderageModelEvent();
    bool CheckEvents(int32_t eventType);
    bool SubscribeCallback(int32_t type);
    bool UnSubscribeCallback(int32_t type);
    bool Subscribe(uint32_t type);
    bool InsertRef(std::shared_ptr<UnderageModelEventListener> listener, ani_ref onHandlerRef);
    bool AddCallback(int32_t eventType, uintptr_t opq);
    bool RemoveAllCallback(int32_t eventType);
    bool RemoveCallback(int32_t eventType, uintptr_t opq);
    void OnEventChanged(uint32_t eventType, int32_t result, float confidence);
    static ani_vm* GetAniVm(ani_env* env);
    static ani_env* GetAniEnv(ani_vm* vm);
    static ani_env* AttachAniEnv(ani_vm* vm);
    ani_object CreateAniUserClassification(ani_env *env, int32_t result, float confidence);
    ani_object CreateAniUndefined(ani_env* env);

public:
    std::mutex mutex_;
    std::map<int32_t, std::shared_ptr<IUnderageModelListener>> callbacks_;
    
private:
    bool LoadLibrary();

private:
    static ani_env* env_;
    static ani_vm* vm_;

protected:
    std::map<int32_t, std::shared_ptr<UnderageModelEventListener>> events_;

public:
    void* g_userStatusHandle { nullptr };
    RegisterListenerFunc g_registerListenerFunc { nullptr };
    SubscribeFunc g_subscribeFunc { nullptr };
    UnsubscribeFunc g_unsubscribeFunc { nullptr };
    std::mutex eventsMutex_;
};
} // namespace Msdp
} // namespace OHOS
#endif // ANI_UNDERAGE_MODEL_EVNET_H