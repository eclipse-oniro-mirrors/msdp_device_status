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

#include "car_awareness_napi.h"
#include "car_awareness_napi_utils.h"

#ifdef CAR_AWARENESS_ENABLE
#include "car_awareness_mgr.h"
#endif // CAR_AWARENESS_ENABLE

#include <unordered_map>
#include <unordered_set>

#undef LOG_TAG
#define LOG_TAG "CarAwarenessNapi"

namespace OHOS {
namespace Msdp {
namespace {
    std::mutex g_jsClassMutex;
    std::unordered_map<napi_env, napi_ref> g_jsClassRefs;

#ifdef CAR_AWARENESS_ENABLE
auto &g_carAwarenessMgr = DeviceStatus::CarAwarenessMgr::GetInstance();

    std::mutex g_instancesMutex;
    std::unordered_map<napi_env, std::weak_ptr<CarAwarenessNapi>> g_instances;

    std::mutex g_callbacksMutex;
    std::unordered_map<int32_t, sptr<CarAwarenessCallback>> g_typeCallbacks;
#endif // CAR_AWARENESS_ENABLE

    // 定义静态常量
    static constexpr uint8_t ARG_0 = 0;
    static constexpr uint8_t ARG_1 = 1;
    static constexpr uint8_t ARG_2 = 2;
    static constexpr uint8_t ARG_3 = 3;

    const std::map<const std::string, int32_t> CAP_TYPE_MAP = {
        { "SpatialMotion", TYPE_SPATIAL_MOTION },
        { "RealTimeWeather", TYPE_REALTIME_WEATHER },
        { "Refueling", TYPE_REFUELING },
        { "SpatialPoint", TYPE_SPATIAL_POINT },
        { "SpatialGesture", TYPE_SPATIAL_GESTURE },
        { "CarStatus", TYPE_CAR_STATUS },
        { "CarCfg", TYPE_CAR_CFG },
        { "HabitRecommendation", TYPE_HABIT_RECOMMENDATION }
    };

    const std::vector<std::string> EXPECTED_TYPE_NUMBER_ARG_1 = { "number" };
    const std::vector<std::string> EXPECTED_TYPE_STRING_ARG_1 = { "string" };
    const std::vector<std::string> EXPECTED_TYPE_FUNCTION_ARG_1 = { "function" };
    const std::vector<std::string> EXPECTED_TYPE_FUNCTION_ARG_2 = { "string", "function" };
    const std::vector<std::string> EXPECTED_TYPE_OBJECT_ARG_2 = { "string", "object" };
    const std::vector<std::string> EXPECTED_TYPE_ARG_3 = { "string", "function", "object" };
}

CarAwarenessNapi::CarAwarenessNapi(napi_env env, napi_value thisVar) : CarAwarenessMgrNapi(env, thisVar)
{
    env_ = env;
}

CarAwarenessNapi::~CarAwarenessNapi()
{
    FI_HILOGI("Enter");
}

void CarAwarenessNapi::SaveJsClassWeakRef(napi_env env, napi_value exports)
{
    // 增强并发同时能够有效防范死锁
    {
        std::lock_guard<std::mutex> lock(g_jsClassMutex);
        auto it = g_jsClassRefs.find(env);
        if (it != g_jsClassRefs.end() && it->second != nullptr) {
            FI_HILOGD("JsClass Ref Exist.");
            return;
        }
    }

    napi_ref newRef = nullptr;
    napi_status st = napi_create_reference(env, exports, 0, &newRef);
    if (st != napi_ok || newRef == nullptr) {
        FI_HILOGE("Create JsClass ref fail");
        return;
    }

    napi_ref deleteRef = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_jsClassMutex);
        auto it = g_jsClassRefs.find(env);
        if (it != g_jsClassRefs.end() && it->second != nullptr) {
            // 其他线程已写入, 已创建的新引用对象需要释放
            deleteRef = newRef;
        } else {
            g_jsClassRefs[env] = newRef;
            newRef = nullptr;
        }
    }

    // 锁外释放掉冗余的ref对象
    if (deleteRef != nullptr) {
        napi_delete_reference(env, deleteRef);
    }
}

#ifdef CAR_AWARENESS_ENABLE
void CarAwarenessNapi::DeleteJsClassRef(napi_env env)
{
    napi_ref ref = nullptr;
    // 锁内在Map中执行遍历删除操作
    {
        std::lock_guard<std::mutex> lock(g_jsClassMutex);
        auto it = g_jsClassRefs.find(env);
        if (it == g_jsClassRefs.end()) {
            return;
        }
        ref = it->second;
        g_jsClassRefs.erase(it);
    }
    // 锁外删除具体的C++侧carAwareness对象引用,
    if (ref != nullptr) {
        napi_delete_reference(env, ref);
    }
}

// 优先使用已经创建/存在的carAwareness对象引用, 如果未找到, 使用当前调用链中获取的JS对象引用代替
napi_value CarAwarenessNapi::GetJsClassRef(napi_env env, napi_value jsThis)
{
    napi_ref ref = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_jsClassMutex);
        auto it = g_jsClassRefs.find(env);
        if (it != g_jsClassRefs.end()) {
            ref = it->second;
        }
    }

    if (ref != nullptr) {
        napi_value jsClassRef = nullptr;
        napi_status status = napi_get_reference_value(env, ref, &jsClassRef);
        if (status == napi_ok && jsClassRef != nullptr) {
            return jsClassRef;
        }
    }
    return jsThis;
}

std::shared_ptr<CarAwarenessNapi> CarAwarenessNapi::GetInstanceByRef(napi_env env, napi_value jsThis)
{
    napi_value jsRef = GetJsClassRef(env, jsThis);
    // g_instancesMutex 只用于保护 g_instances 读写(不在持锁状态下调用 N-API).
    if (auto exist = GetExistingInstanceLocked(env)) {
        return exist;
    }
    auto sp_caNapi = std::make_shared<CarAwarenessNapi>(env, jsRef);
    {
        std::lock_guard<std::mutex> lock(g_instancesMutex);
        auto it = g_instances.find(env);
        if (it != g_instances.end()) {
            auto exist = it->second.lock();
            if (exist) {
                return exist;
            }
            // 旧指针已释放, 写入新值
            it->second = sp_caNapi;
        } else {
            g_instances.emplace(env, sp_caNapi);
        }
    }
    // new 一个 holder（nothrow），holder 内持有 shared_ptr
    struct InstanceHolder {
        std::shared_ptr<CarAwarenessNapi> sp_caNapi;
    };
    auto *holder = new (std::nothrow) InstanceHolder{sp_caNapi};
    if (holder == nullptr) {
        FI_HILOGE("faild to alloc InstanceHolder");
        // 回滚 g_instances 的emplace 操作
        RollbackInstancesLocked(env, sp_caNapi);
        return nullptr;
    }

    napi_status status = napi_wrap(env, jsRef, reinterpret_cast<void *>(holder),
        [](napi_env env, void *data, void *hint) {
            (void)hint;
            auto *holder = reinterpret_cast<InstanceHolder *>(data);
            {
                std::lock_guard<std::mutex> lock(g_instancesMutex);
                g_instances.erase(env);
            }
            DeleteJsClassRef(env);
            // 释放holder 触发 CarAwarenessNapi 析构
            delete holder;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        FI_HILOGE("napi_wrap failed");
        // 原生 C/C++ 对象与 JS 对象关联失败, 释放内存同时回滚g_instances 的emplace 操作
        delete holder;
        RollbackInstancesLocked(env, sp_caNapi);
        return nullptr;
    }
    return sp_caNapi;
}

std::shared_ptr<CarAwarenessNapi> CarAwarenessNapi::GetExistingInstanceLocked(napi_env env)
{
    std::lock_guard<std::mutex> lock(g_instancesMutex);
    auto it = g_instances.find(env);
    if (it == g_instances.end()) {
        return nullptr;
    }
    return it->second.lock();
}

void CarAwarenessNapi::RollbackInstancesLocked(napi_env env, const std::shared_ptr<CarAwarenessNapi> &sp)
{
    std::lock_guard<std::mutex> lock(g_instancesMutex);
    auto it = g_instances.find(env);
    if (it == g_instances.end()) {
        return;
    }

    auto current = it->second.lock();
    if (current && current.get() == sp.get()) {
        g_instances.erase(it);
    }
}
#endif // CAR_AWARENESS_ENABLE

napi_value CarAwarenessNapi::Init(napi_env env, napi_value exports)
{
    FI_HILOGD("Enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("onSpatialMotion", OnSpatialMotion),
        DECLARE_NAPI_STATIC_FUNCTION("offSpatialMotion", OffSpatialMotion),
        DECLARE_NAPI_STATIC_FUNCTION("onRealTimeWeather", OnRealTimeWeather),
        DECLARE_NAPI_STATIC_FUNCTION("offRealTimeWeather", OffRealTimeWeather),
        DECLARE_NAPI_STATIC_FUNCTION("onRefueling", OnRefueling),
        DECLARE_NAPI_STATIC_FUNCTION("offRefueling", OffRefueling),
        DECLARE_NAPI_STATIC_FUNCTION("onCarAwareness", OnCarAwareness),
        DECLARE_NAPI_STATIC_FUNCTION("offCarAwareness", OffCarAwareness),
        DECLARE_NAPI_STATIC_FUNCTION("getAllCapabilityList", GetAllCapabilityList),
        DECLARE_NAPI_STATIC_FUNCTION("updateSpatialActionEnableStatus", UpdateSpatialActionEnableStatus),
        DECLARE_NAPI_STATIC_FUNCTION("updateSpatialActionZone", UpdateSpatialActionZone),
        DECLARE_NAPI_STATIC_FUNCTION("getCarAwareness", GetCarAwareness)
    };
    MSDP_CALL(napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    // 以 env 为key(虚拟机上下文, 标识NAPI调用的有效范围), 保存 carAwareness JS 对象的弱引用.
    // 便于生命周期管理、线程隔离、内存分配与回收正确等.
    SaveJsClassWeakRef(env, exports);
    DefineCapabilityType(env, exports);
    FI_HILOGD("Exit");
    return exports;
}

void CarAwarenessNapi::DefineCapabilityType(napi_env env, napi_value exports)
{
    napi_value capability;
    napi_status status = napi_create_object(env, &capability);
    if (status != napi_ok) {
        FI_HILOGE("Failed create object");
        return;
    }

    SetStringProperty(env, capability, "SpatialMotion", "SPATIAL_MOTION");
    SetStringProperty(env, capability, "SpatialPoint", "SPATIAL_POINT");
    SetStringProperty(env, capability, "SpatialGesture", "SPATIAL_GESTURE");
    SetStringProperty(env, capability, "RealTimeWeather", "REALTIME_WEATHER");
    SetStringProperty(env, capability, "Refueling", "REFUELING");
    SetStringProperty(env, capability, "CarStatus", "CAR_STATUS");
    SetStringProperty(env, capability, "CarCfg", "CAR_CFG");
    SetStringProperty(env, capability, "HabitRecommendation", "HABIT_RECOMMENDATION");
    SetPropertyName(env, exports, "Capability", capability);
}

bool CarAwarenessNapi::CheckSystemApiArgument(napi_env env, napi_value *args, size_t argc)
{
    if (argc < ARG_1 || argc > ARG_3) {
        FI_HILOGE("wrong number of arguments");
        return false;
    }
    std::vector<std::string> expected_sub_args = (argc == ARG_1) ? EXPECTED_TYPE_STRING_ARG_1
        : (argc == ARG_2 ? EXPECTED_TYPE_FUNCTION_ARG_2 : EXPECTED_TYPE_ARG_3);
    if (!IsArgAllValid(env, args, argc, expected_sub_args)) {
        FI_HILOGE("Arguments is illegal");
        return false;
    }
    return true;
}

bool CarAwarenessNapi::IsArgAllValid(napi_env env, napi_value *args, size_t argc,
    const std::vector<std::string> &expectedTypes)
{
    FI_HILOGD("Enter");
    napi_status status = napi_ok;
    napi_valuetype valueType = napi_undefined;

    if (argc != expectedTypes.size()) {
        FI_HILOGE("Wrong number of arguments");
        return false;
    }

    for (size_t i = 0; i < argc; ++i) {
        status = napi_typeof(env, args[i], &valueType);
        if (status != napi_ok) {
            FI_HILOGE("Error while checking arguments types");
            return false;
        }
        std::string expectedType = expectedTypes[i];
        if ((expectedType == "string" && valueType != napi_string) ||
            (expectedType == "function" && valueType != napi_function) ||
            (expectedType == "object" && valueType != napi_object) ||
            (expectedType == "number" && valueType != napi_number)) {
                FI_HILOGE("Wrong argument type");
                return false;
        }
    }
    return true;
}

bool CarAwarenessNapi::GetCarAwarenessOption(napi_env env, napi_value awarenessOption, CarAwarenessOption &option)
{
    // 预留参数解析逻辑, 待手势识别明确参数后处理
    return true;
}

#ifdef CAR_AWARENESS_ENABLE
void CarAwarenessNapi::ExecuteGetCapCompleteFunc(napi_env env, napi_status status, void *data)
{
    auto *context = static_cast<CapabilityContext *>(data);
    if (context == nullptr || context->env == nullptr) {
        return;
    }
        if (context->asyncWorkRet != RES_SUCCESS) {
            ThrowIpcExcuteErr(context->env, context->asyncWorkRet);
            napi_reject_deferred(context->env, context->deferred,
                CreateNapiError(context->env, context->asyncWorkRet, "GetSupportCap Err"));
        } else {
            napi_value result;
            napi_create_array(context->env, &result);
            for (size_t i = 0; i < context->typeVector.size(); i++) {
                napi_value str;
                napi_create_string_utf8(context->env, context->typeVector[i].c_str(), NAPI_AUTO_LENGTH, &str);
                napi_set_element(context->env, result, i, str);
            }
            napi_resolve_deferred(context->env, context->deferred, result);
        }
    if (context->env != nullptr && context->asyncWork != nullptr) {
        napi_delete_async_work(context->env, context->asyncWork);
    }
    delete context;
}

void CarAwarenessNapi::ExecuteGetEventCompleteFunc(napi_env env, napi_status status, void *data)
{
    auto *context = static_cast<AwarenessEventContext *>(data);
    if (context == nullptr || context->env == nullptr) {
        return;
    }
    // 预留数据采集实现，当前返回空
    if (context->asyncWorkRet != RES_SUCCESS) {
        ThrowIpcExcuteErr(context->env, context->asyncWorkRet);
        napi_reject_deferred(context->env, context->deferred,
            CreateNapiError(context->env, context->asyncWorkRet, "GetCarAwareness Err"));
    } else {
        napi_value result;
        napi_create_array(context->env, &result);
        napi_resolve_deferred(context->env, context->deferred, result);
    }

    if (context->env != nullptr && context->asyncWork != nullptr) {
        napi_delete_async_work(context->env, context->asyncWork);
    }
    delete context;
}

napi_value CarAwarenessNapi::ExecuteAsyncTask(AsyncContext *context, const char *taskName,
    napi_async_execute_callback executeFunc, napi_async_complete_callback completeFunc)
{
    napi_value promise = nullptr;
    if (napi_create_promise(context->env, &context->deferred, &promise) != napi_ok) {
        ThrowErrToJs(context->env, SERVICE_ERR, "napi_create_promise failed");
        delete context;
        return nullptr;
    }
    napi_value resourceName = nullptr;
    if (napi_create_string_utf8(context->env, taskName, NAPI_AUTO_LENGTH, &resourceName) != napi_ok) {
        ThrowErrToJs(context->env, SERVICE_ERR, "napi_create_string_utf8 failed");
        delete context;
        return nullptr;
    }
    if (napi_create_async_work(context->env, nullptr, resourceName, executeFunc, completeFunc,
        static_cast<void*>(context), &context->asyncWork) != napi_ok) {
        ThrowErrToJs(context->env, SERVICE_ERR, "napi_create_async_work failed");
        delete context;
        return nullptr;
    }
    if (napi_queue_async_work(context->env, context->asyncWork) != napi_ok) {
        ThrowErrToJs(context->env, SERVICE_ERR, "napi_queue_async_work failed");
        napi_delete_async_work(context->env, context->asyncWork);
        delete context;
        return nullptr;
    }
    return promise;
}

void CarAwarenessNapi::ThrowIpcExcuteErr(napi_env env, int32_t errCode)
{
    if (errCode == PERMISSION_ERR) {
        FI_HILOGE("Permission deinied");
        ThrowErrToJs(env, PERMISSION_ERR, "Permission denied");
    } else if (errCode == NOT_SYSTEM_APP_ERR) {
        FI_HILOGE("Not system application");
        ThrowErrToJs(env, NOT_SYSTEM_APP_ERR, "Not system application");
    } else if (errCode == DEVICE_ERR) {
        FI_HILOGE("Device not support");
        ThrowErrToJs(env, DEVICE_ERR, "Device not support");
    } else if (errCode == SPECIFIC_ERR) {
        FI_HILOGE("Specific capability not support");
        ThrowErrToJs(env, SPECIFIC_ERR, "Specific capability not support");
    } else {
        FI_HILOGE("Ipc Failed");
        ThrowErrToJs(env, SERVICE_ERR, "Ipc Failed");
    }
}

bool CarAwarenessNapi::DoSubscription(napi_env env, int32_t type,
    const CarAwarenessOption &option, const sptr<CarAwarenessCallback> cb)
{
    int32_t ret = g_carAwarenessMgr.SubscribeCapability(type, option, cb);
    if (ret == RES_SUCCESS) {
        FI_HILOGI("Subscribe success: %{public}d", type);
        return true;
    }
    cb->RemoveNapiObject(weak_from_this());

        auto it = g_typeCallbacks.find(type);
        if (it != g_typeCallbacks.end() && it->second == cb) {
            g_typeCallbacks.erase(it);
    }
    ThrowIpcExcuteErr(env, ret);
    return false;
}

bool CarAwarenessNapi::SubscribeToSa(napi_env env, int32_t type,
    const CarAwarenessOption &option, bool &hasSubscribed)
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> lock(g_callbacksMutex);

    sptr<CarAwarenessCallback> cb;
    hasSubscribed = false;

        auto it = g_typeCallbacks.find(type);
        if (it != g_typeCallbacks.end()) {
            cb = it->second;
            hasSubscribed = true;
        } else {
            cb = sptr<CarAwarenessCallback>(new (std::nothrow) CarAwarenessCallback());
            if (cb == nullptr) {
                FI_HILOGE("Failed to create MotionCallback");
                ThrowErrToJs(env, SERVICE_ERR, "Subscribe failed");
                return false;
            }

            // 避免并发线程重复对同一type 进行订阅
            g_typeCallbacks.emplace(type, cb);
    }
    FI_HILOGI("%{public}d has subscribe: %{public}d", type, hasSubscribed);

    cb->AddNapiObject(weak_from_this());

    if (hasSubscribed) {
        return true;
    }

    return DoSubscription(env, type, option, cb);
}

napi_value CarAwarenessNapi::SubScribeCarAwareness(napi_env env, napi_value jsThis, napi_value callback,
    int32_t type, const CarAwarenessOption &option)
{
    FI_HILOGD("Enter");
    auto instance = GetInstanceByRef(env, jsThis);
    if (instance == nullptr) {
        ThrowErrToJs(env, SERVICE_ERR, "Failed to get napi instance");
        return nullptr;
    }
    bool hasSubscribed = false;
    if (!instance->SubscribeToSa(env, type, option, hasSubscribed)) {
        return nullptr;
    }
    bool isNewHandler = false;
    if (!instance->AddCallbackEx(type, callback, isNewHandler)) {
        ThrowErrToJs(env, SERVICE_ERR, "AddCallback failed");
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value CarAwarenessNapi::UnSubScribeCarAwareness(napi_env env, napi_value callback,
    int32_t type, const CarAwarenessOption &option)
{
    auto instance = GetExistingInstanceLocked(env);
    if (instance == nullptr) {
        ThrowErrToJs(env, SERVICE_ERR, "Failed to get napi instance");
        return nullptr;
    }
    bool remove_res = false;
    if (callback == nullptr) {
        remove_res = instance->RemoveAllCallbackEx(type);
    } else {
        remove_res = instance->RemoveCallbackEx(type, callback);
    }
    if (!remove_res) {
        FI_HILOGW("RemoveCallback failed");
        return nullptr;
    }
    if (!instance->HasCapListener(type)) {
        if (!instance->UnSubscribeToSa(env, type, option)) {
            return nullptr;
        }
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}
#endif // CAR_AWARENESS_ENABLE

napi_value CarAwarenessNapi::SubscribeCapEx(napi_env env, napi_callback_info info)
{
    size_t argc = ARG_3;
    napi_value args[ARG_3] = { nullptr };
    napi_value jsThis = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok) {
        ThrowErrToJs(env, PARAM_ERR, "napi_get_cb_info failed");
        return nullptr;
    }
    if (!CheckSystemApiArgument(env, args, argc)) {
        ThrowErrToJs(env, PARAM_ERR, "Subscribe Arguments is illegal");
        return nullptr;
    }
    int32_t type = GetCapType(env, args[ARG_0]);
    // On off 接口仅允许system类型api
    if (type == INVALID_CAP_TYPE || type < SYSTEM_API_TYPES_START) {
        FI_HILOGE("Capability is illegal, type:%{public}d", type);
        ThrowErrToJs(env, SPECIFIC_ERR, "Capability is illegal");
        return nullptr;
    }
    CarAwarenessOption option;
    if (argc == ARG_3 && !GetCarAwarenessOption(env, args[ARG_2], option)) {
        ThrowErrToJs(env, PARAM_ERR, "option param is invalid");
        return nullptr;
    }
#ifdef CAR_AWARENESS_ENABLE
    return SubScribeCarAwareness(env, jsThis, args[ARG_1], type, option);
#else
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
#endif // CAR_AWARENESS_ENABLE
}

napi_value CarAwarenessNapi::SubscribeCap(napi_env env, napi_callback_info info, int32_t type)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    napi_value jsThis = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok) {
        ThrowErrToJs(env, PARAM_ERR, "napi_get_cb_info failed");
        return nullptr;
    }
    if (argc > ARG_1 || (argc == ARG_1 && !IsArgAllValid(env, args, argc, EXPECTED_TYPE_FUNCTION_ARG_1))) {
        ThrowErrToJs(env, PARAM_ERR, "Arguments is illegal");
        return nullptr;
    }
#ifdef CAR_AWARENESS_ENABLE
    return SubScribeCarAwareness(env, jsThis, args[0], type, CarAwarenessOption());
#else
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
#endif // CAR_AWARENESS_ENABLE
}

int32_t CarAwarenessNapi::GetCapType(napi_env env, napi_value value)
{
    FI_HILOGD("Enter");
    std::string typeStr;
    if (!TransJsToStr(env, value, typeStr)) {
        return INVALID_CAP_TYPE;
    }
    auto iter = CAP_TYPE_MAP.find(typeStr);
    if (iter == CAP_TYPE_MAP.end()) {
        FI_HILOGD("Not find this type");
        return INVALID_CAP_TYPE;
    }
    FI_HILOGD("Exit");
    return iter->second;
}

napi_value CarAwarenessNapi::UnSubscribeCapEx(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_3;
    napi_value args[ARG_3] = { nullptr };
    napi_value jsThis = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok) {
        ThrowErrToJs(env, PARAM_ERR, "napi_get_cb_info failed");
        return nullptr;
    }
    if (!CheckSystemApiArgument(env, args, argc)) {
        ThrowErrToJs(env, PARAM_ERR, "UnSubscribe Arguments is illegal");
        return nullptr;
    }
    int32_t type = GetCapType(env, args[ARG_0]);
    // On off 接口仅允许system类型api
    if (type == INVALID_CAP_TYPE || type < SYSTEM_API_TYPES_START) {
        FI_HILOGE("Capability is illegal, type:%{public}d", type);
        ThrowErrToJs(env, SPECIFIC_ERR, "Capability is illegal");
        return nullptr;
    }
    CarAwarenessOption option;
    if (argc == ARG_3 && !GetCarAwarenessOption(env, args[ARG_2], option)) {
        ThrowErrToJs(env, PARAM_ERR, "option param is invalid");
        return nullptr;
    }
#ifdef CAR_AWARENESS_ENABLE
    napi_value callback = (argc == ARG_1) ? nullptr : args[ARG_1];
    return UnSubScribeCarAwareness(env, callback, type, option);
#else
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
#endif // CAR_AWARENESS_ENABLE
}

napi_value CarAwarenessNapi::UnSubscribeCap(napi_env env, napi_callback_info info, int32_t type)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    napi_value jsThis = nullptr;
    if (napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr) != napi_ok) {
        ThrowErrToJs(env, PARAM_ERR, "napi_get_cb_info failed");
        return nullptr;
    }
    if (argc > ARG_1) {
        ThrowErrToJs(env, PARAM_ERR, "Arguments is illegal");
        return nullptr;
    }
    if (argc == ARG_1 && !IsArgAllValid(env, args, argc, EXPECTED_TYPE_FUNCTION_ARG_1)) {
        ThrowErrToJs(env, PARAM_ERR, "Arguments is illegal");
        return nullptr;
    }
#ifdef CAR_AWARENESS_ENABLE
    napi_value callback = (argc == ARG_1) ? args[ARG_0] : nullptr;
    return UnSubScribeCarAwareness(env, callback, type, CarAwarenessOption());
#else
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
#endif // CAR_AWARENESS_ENABLE
}

#ifdef CAR_AWARENESS_ENABLE
bool CarAwarenessNapi::UnSubscribeToSa(napi_env env, int32_t type, const CarAwarenessOption &option)
{
    FI_HILOGD("Enter");
    sptr<CarAwarenessCallback> callback;
    {
        std::lock_guard<std::mutex> lock(g_callbacksMutex);
        auto it = g_typeCallbacks.find(type);
        if (it == g_typeCallbacks.end()) {
            FI_HILOGE("faild to find callback");
            return false;
        }
        callback = it->second;
        callback->RemoveNapiObject(weak_from_this());
        // 若仍有其它 env(线程) 在监听: 不真正触发 sa unsubscribe
        if (callback->HasNapiObject()) {
            FI_HILOGI("Still has listener on other thread");
            return true;
        }
        g_typeCallbacks.erase(it);
        FI_HILOGI("erase type: %{public}d", type);
    }
    return DoUnSubscription(env, type, option, callback);
}

// 此处的sptr<CarAwarenessCallback>参数非必选, NAPI已严格管控同一进程同一type仅一个Stub对象
bool CarAwarenessNapi::DoUnSubscription(napi_env env, int32_t type,
    const CarAwarenessOption &option, const sptr<CarAwarenessCallback> cb)
{
    int32_t ret = g_carAwarenessMgr.UnSubscribeCapability(type, option, cb);
    if (ret == RES_SUCCESS) {
        FI_HILOGI("UnSubscribe success: %{public}d", type);
        return true;
    } else {
        ThrowIpcExcuteErr(env, ret);
        return false;
    }
}
#endif // CAR_AWARENESS_ENABLE

napi_value CarAwarenessNapi::OnSpatialMotion(napi_env env, napi_callback_info info)
{
    return SubscribeCap(env, info, TYPE_SPATIAL_MOTION);
}

napi_value CarAwarenessNapi::OffSpatialMotion(napi_env env, napi_callback_info info)
{
    return UnSubscribeCap(env, info, TYPE_SPATIAL_MOTION);
}

napi_value CarAwarenessNapi::OnRealTimeWeather(napi_env env, napi_callback_info info)
{
    return SubscribeCap(env, info, TYPE_REALTIME_WEATHER);
}

napi_value CarAwarenessNapi::OffRealTimeWeather(napi_env env, napi_callback_info info)
{
    return UnSubscribeCap(env, info, TYPE_REALTIME_WEATHER);
}

napi_value CarAwarenessNapi::OnRefueling(napi_env env, napi_callback_info info)
{
    return SubscribeCap(env, info, TYPE_REFUELING);
}

napi_value CarAwarenessNapi::OffRefueling(napi_env env, napi_callback_info info)
{
    return UnSubscribeCap(env, info, TYPE_REFUELING);
}

napi_value CarAwarenessNapi::OnCarAwareness(napi_env env, napi_callback_info info)
{
    return SubscribeCapEx(env, info);
}

napi_value CarAwarenessNapi::OffCarAwareness(napi_env env, napi_callback_info info)
{
    return UnSubscribeCapEx(env, info);
}

napi_value CarAwarenessNapi::GetAllCapabilityList(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok) {
        ThrowErrToJs(env, PARAM_ERR, "napi_get_cb_info failed");
        return nullptr;
    }
    if (argc != ARG_0) {
        ThrowErrToJs(env, PARAM_ERR, "Arguments is illegal");
        return nullptr;
    }
#ifdef CAR_AWARENESS_ENABLE
    CapabilityContext *capContext = new (std::nothrow) CapabilityContext();
    if (capContext == nullptr) {
        FI_HILOGE("create context failed");
        ThrowErrToJs(env, SERVICE_ERR, "create context failed");
        return nullptr;
    }
    capContext->env = env;
    auto execute = [](napi_env, void *data) {
        CapabilityContext *context = (CapabilityContext *)data;
        if (context == nullptr) {
            FI_HILOGE("context is nullptr");
            return;
        }
        context->asyncWorkRet = g_carAwarenessMgr.GetSupportCapabilityList(context->typeVector);
    };
    return ExecuteAsyncTask(capContext, "GetAllCapability", execute, ExecuteGetCapCompleteFunc);
#else
    ThrowErrToJs(env, DEVICE_ERR, "Device not support");
    return nullptr;
#endif // CAR_AWARENESS_ENABLE
}

napi_value CarAwarenessNapi::UpdateSpatialActionEnableStatus(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok) {
        ThrowErrToJs(env, PARAM_ERR, "napi_get_cb_info failed");
        return nullptr;
    }
    if (argc != ARG_1 || !IsArgAllValid(env, args, argc, EXPECTED_TYPE_NUMBER_ARG_1)) {
        ThrowErrToJs(env, PARAM_ERR, "Arguments is illegal");
        return nullptr;
    }
    int32_t event;
    napi_status status = napi_get_value_int32(env, args[ARG_0], &event);
    if (status != napi_ok) {
        ThrowErrToJs(env, SERVICE_ERR, "napi_get_value_int32 failed");
        return nullptr;
    }
#ifdef CAR_AWARENESS_ENABLE
    int32_t ret = g_carAwarenessMgr.UpdateSpatialActionStatus(event);
    if (ret != RES_SUCCESS) {
        ThrowIpcExcuteErr(env, ret);
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
#else
    ThrowErrToJs(env, DEVICE_ERR, "Device not support");
    return nullptr;
#endif // CAR_AWARENESS_ENABLE
}

napi_value CarAwarenessNapi::UpdateSpatialActionZone(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_1;
    napi_value args[ARG_1] = { nullptr };
    if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok) {
        ThrowErrToJs(env, PARAM_ERR, "napi_get_cb_info failed");
        return nullptr;
    }
    if (argc != ARG_1 || !IsArgAllValid(env, args, argc, EXPECTED_TYPE_NUMBER_ARG_1)) {
        ThrowErrToJs(env, PARAM_ERR, "Arguments is illegal");
        return nullptr;
    }
    int32_t zoneId;
    napi_status status = napi_get_value_int32(env, args[ARG_0], &zoneId);
    if (status != napi_ok) {
        ThrowErrToJs(env, SERVICE_ERR, "napi_get_value_int32 failed");
        return nullptr;
    }
#ifdef CAR_AWARENESS_ENABLE
    int32_t ret = g_carAwarenessMgr.UpdateSpatialActionZone(zoneId);
    if (ret != RES_SUCCESS) {
        ThrowIpcExcuteErr(env, ret);
        return nullptr;
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
#else
    ThrowErrToJs(env, DEVICE_ERR, "Device not support");
    return nullptr;
#endif // CAR_AWARENESS_ENABLE
}

napi_value CarAwarenessNapi::GetCarAwareness(napi_env env, napi_callback_info info)
{
    FI_HILOGD("Enter");
    size_t argc = ARG_2;
    napi_value args[ARG_2] = { nullptr };
    if (napi_get_cb_info(env, info, &argc, args, nullptr, nullptr) != napi_ok) {
        ThrowErrToJs(env, PARAM_ERR, "napi_get_cb_info failed");
        return nullptr;
    }
    if (argc < ARG_1 || argc > ARG_2) {
        ThrowErrToJs(env, PARAM_ERR, "Arguments num is illegal");
        return nullptr;
    }
    if (argc == ARG_1 && !IsArgAllValid(env, args, argc, EXPECTED_TYPE_STRING_ARG_1)) {
        ThrowErrToJs(env, PARAM_ERR, "Arguments is illegal");
        return nullptr;
    }
    int32_t type = GetCapType(env, args[ARG_0]);
    if (type == INVALID_CAP_TYPE) {
        ThrowErrToJs(env, SPECIFIC_ERR, "Capability is illegal");
        return nullptr;
    }
    CarAwarenessOption option;
    if (argc == ARG_2 && !GetCarAwarenessOption(env, args[ARG_1], option)) {
        ThrowErrToJs(env, PARAM_ERR, "option param is invalid");
        return nullptr;
    }
#ifdef CAR_AWARENESS_ENABLE
    AwarenessEventContext *eventContext = new (std::nothrow) AwarenessEventContext();
    if (eventContext == nullptr) {
        ThrowErrToJs(env, SERVICE_ERR, "create context failed");
        return nullptr;
    }
    eventContext->env = env;
    eventContext->type = type;
    eventContext->option = option;
    auto execute = [](napi_env, void *data) {
        AwarenessEventContext *context = (AwarenessEventContext *)data;
        if (context == nullptr) {
            FI_HILOGE("AsyncContext obj get failed");
            return;
        }
        context->asyncWorkRet = g_carAwarenessMgr.GetCarAwareness(context->type, context->option, context->events);
    };
    return ExecuteAsyncTask(eventContext, "GetCarAwareness", execute, ExecuteGetEventCompleteFunc);
#else
    ThrowErrToJs(env, DEVICE_ERR, "Device not support");
    return nullptr;
#endif  // CAR_AWARENESS_ENABLE
}

#ifdef CAR_AWARENESS_ENABLE
void CarAwarenessNapi::PostAwarenessEvent(const CarAwarenessEvent &event)
{
    auto self_ptr = weak_from_this();
    int32_t type = event.type;
    std::string data = event.eventData;
    auto task = [self_ptr, type, data]() {
        auto self = self_ptr.lock();
        if (!self) {
            return;
        }
        self->TriggerEvent(type, data);
    };
    if (napi_send_event(env_, task, napi_eprio_immediate, "carAwareness.postEvent") != napi_ok) {
        FI_HILOGE("Failed to postEvent");
    }
}

void CarAwarenessCallback::OnAwarenessEvent(const CarAwarenessEvent& event)
{
    FI_HILOGD("Enter");
    std::vector<std::shared_ptr<CarAwarenessNapi>> snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = objects_.begin(); it != objects_.end();) {
            auto sp = it->lock();
            if (!sp) {
                it = objects_.erase(it);
                continue;
            }
            snapshot.push_back(std::move(sp));
            ++it;
        }
    }

    // 再次去重, 防止异常情况下weak_ptr重复极
    std::unordered_set<CarAwarenessNapi*> seen;
    seen.reserve(snapshot.size());
    std::vector<std::shared_ptr<CarAwarenessNapi>> uniqueTargets;
    uniqueTargets.reserve(snapshot.size());
    for (auto &t : snapshot) {
        if (!t) {
            continue;
        }
        if (seen.insert(t.get()).second) {
            uniqueTargets.push_back(std::move(t));
        }
    }

    for (auto &tmp : uniqueTargets) {
        tmp->PostAwarenessEvent(event);
    }
    FI_HILOGD("Exit");
}

void CarAwarenessCallback::AddNapiObject(const std::weak_ptr<CarAwarenessNapi> object)
{
    FI_HILOGD("Enter");
    auto napi_sp = object.lock();
    if (!napi_sp) {
        FI_HILOGE("object is null");
        return;
    }
    // 对 objects_ 进行清理和去重, 确保当前 napi object 一定被加入.
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_set<CarAwarenessNapi*> uniq;
    uniq.reserve(objects_.size() + 1);
    std::vector<std::weak_ptr<CarAwarenessNapi>> compact;
    compact.reserve(objects_.size() + 1);
    bool exists = false;
    for (auto &w : objects_) {
        auto sp = w.lock();
        if (!sp) {
            // 过期清理
            continue;
        }
        CarAwarenessNapi* key = sp.get();
        if (!uniq.insert(key).second) {
            // 去重：相同对象只保留第一次
            continue;
        }
        if (key == napi_sp.get()) {
            exists = true;
        }
        // shared_ptr -> weak_ptr
        compact.push_back(sp);
    }
    if (!exists) {
        compact.push_back(object);
    }
    objects_.swap(compact);
}

void CarAwarenessCallback::RemoveNapiObject(const std::weak_ptr<CarAwarenessNapi> object)
{
    FI_HILOGD("Enter");
    auto napi_sp = object.lock();
    if (!napi_sp) {
        FI_HILOGE("object is null");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    objects_.erase(std::remove_if(objects_.begin(), objects_.end(),
        [&napi_sp](const std::weak_ptr<CarAwarenessNapi>& it) {
            auto sp = it.lock();
            return sp && sp.get() == napi_sp.get();
        }), objects_.end());
}

bool CarAwarenessCallback::HasNapiObject() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &it : objects_) {
        if (!it.expired()) {
            return true;
        }
    }
    return false;
}
#endif // CAR_AWARENESS_ENABLE
} // namespace Msdp
} // namespace OHOS