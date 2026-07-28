/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CAR_AWARENESS_NAPI_H
#define CAR_AWARENESS_NAPI_H

#include <vector>

#include "car_awareness_mgr_napi.h"
#include "car_awareness_type.h"

#ifdef CAR_AWARENESS_ENABLE
#include "car_awareness_callback_stub.h"
#endif // CAR_AWARENESS_ENABLE

namespace OHOS {
namespace Msdp {
class CarAwarenessNapi;
#ifdef CAR_AWARENESS_ENABLE
class CarAwarenessCallback : public CarAwarenessCallbackStub {
public:
    CarAwarenessCallback() = default;
    ~CarAwarenessCallback() override = default;
    void OnAwarenessEvent(const CarAwarenessEvent& event) override;
    void AddNapiObject(const std::shared_ptr<CarAwarenessNapi>& object);
    void RemoveNapiObject(const std::shared_ptr<CarAwarenessNapi>& object);
    bool HasNapiObject() const;

private:
    // 保护 objects_ 的互斥锁
    mutable std::mutex mutex_;
    std::vector<std::weak_ptr<CarAwarenessNapi>> objects_;
};

struct AsyncContext {
    napi_env env = nullptr;
    // 异步工作对象
    napi_async_work asyncWork = nullptr;
    // 延迟执行对象（用于promaise方法返回计算结果）
    napi_deferred deferred = nullptr;

    int32_t asyncWorkRet;
    std::vector<std::string> typeVector;
};
#endif // CAR_AWARENESS_ENABLE

class CarAwarenessNapi : public CarAwarenessMgrNapi, public std::enable_shared_from_this<CarAwarenessNapi> {
public:
    CarAwarenessNapi(napi_env env, napi_value thisVar);
    ~CarAwarenessNapi() override;
    
    static napi_value Init(napi_env env, napi_value exports);

#ifdef CAR_AWARENESS_ENABLE
   void PostAwarenessEvent(const CarAwarenessEvent &event);
#endif // CAR_AWARENESS_ENABLE

private:
    static void DefineCapabilityType(napi_env env, napi_value exports);
    static napi_value OnSpatialMotion(napi_env env, napi_callback_info info);
    static napi_value OffSpatialMotion(napi_env env, napi_callback_info info);
    static napi_value OnRealTimeWeather(napi_env env, napi_callback_info info);
    static napi_value OffRealTimeWeather(napi_env env, napi_callback_info info);
    static napi_value OnRefueling(napi_env env, napi_callback_info info);
    static napi_value OffRefueling(napi_env env, napi_callback_info info);
    static napi_value OnCarAwareness(napi_env env, napi_callback_info info);
    static napi_value OffCarAwareness(napi_env env, napi_callback_info info);
    static napi_value GetAllCapabilityList(napi_env env, napi_callback_info info);
    static napi_value UpdateSpatialActionEnableStatus(napi_env env, napi_callback_info info);
    static napi_value UpdateSpatialActionZone(napi_env env, napi_callback_info info);

    static napi_value SubscribeCapEx(napi_env env, napi_callback_info info);
    static napi_value UnSubscribeCapEx(napi_env env, napi_callback_info info);
    static napi_value SubscribeCap(napi_env env, napi_callback_info info, int32_t type);
    static napi_value UnSubscribeCap(napi_env env, napi_callback_info info, int32_t type);
    static int32_t GetCapType(napi_env env, napi_value value);
    static bool IsArgAllValid(napi_env env, napi_value *args, size_t argc,
        const std::vector<std::string> &expectedTypes);
    static bool CheckSystemApiArgument(napi_env env, napi_value *args, size_t argc);
    static bool GetCarAwarenessOption(napi_env env, napi_value awarenessOption, CarAwarenessOption &option);
    static void SaveJsClassWeakRef(napi_env env, napi_value exports);
#ifdef CAR_AWARENESS_ENABLE
    static void DeleteJsClassRef(napi_env env);
    static napi_value GetJsClassRef(napi_env env, napi_value jsThis);
    static std::shared_ptr<CarAwarenessNapi> GetInstanceByRef(napi_env env, napi_value jsThis);
    static std::shared_ptr<CarAwarenessNapi> GetExistingInstanceLocked(napi_env env);
    static void RollbackInstancesLocked(napi_env env, const std::shared_ptr<CarAwarenessNapi> &sp);
    static napi_value ExecuteAsyncTask(napi_env env);
    static void ExecuteCompleteFuc(napi_env env, napi_status status, void *data);
    static void ThrowIpcExcuteErr(napi_env env, int32_t errCode);
    static napi_value SubScribeCarAwareness(napi_env env, napi_value jsThis, napi_value callback,
        int32_t type, const CarAwarenessOption &option);
    static napi_value UnSubScribeCarAwareness(napi_env env, napi_value callback,
        int32_t type, const CarAwarenessOption &option);

    bool SubscribeToSa(napi_env env, int32_t type, const CarAwarenessOption &option, bool &hasSubscribed);
    bool DoSubscription(napi_env env, int32_t type,
        const CarAwarenessOption &option, const sptr<CarAwarenessCallback> cb);
    bool UnSubscribeToSa(napi_env env, int32_t type, const CarAwarenessOption &option);
    bool DoUnSubscription(napi_env env, int32_t type,
        const CarAwarenessOption &option, const sptr<CarAwarenessCallback> cb);
#endif // CAR_AWARENESS_ENABLE
};
} // namespace Msdp
} // namespace OHOS

#endif // CAR_AWARENESS_NAPI_H