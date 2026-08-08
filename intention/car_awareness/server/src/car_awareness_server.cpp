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

#include "car_awareness_server.h"

#include <dlfcn.h>
#include <string>
#include "devicestatus_define.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "privacy_kit.h"
#include "tokenid_kit.h"

#undef LOG_TAG
#define LOG_TAG "CarAwarenessServer"

using OHOS::Security::AccessToken::AccessTokenKit;
using OHOS::Security::AccessToken::ATokenTypeEnum;
using OHOS::Security::AccessToken::PermissionState;
using OHOS::Security::AccessToken::TokenIdKit;

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
const std::string SPATIALACTION_PERMISSION = "ohos.permission.vehicle.MMA_SPATIALACTION";
const std::string WEATHER_PERMISSION = "ohos.permission.vehicle.MMA_WEATHER";
const std::string ENERGYREFILL_PERMISSION = "ohos.permission.vehicle.MMA_ENERGYREFILL";
const std::string CAR_AWARENESS_LIB_PATH = "/system/lib64/libcar_awareness_service.z.so";

constexpr int32_t CAR_AWARENESS_SPECIFIC_ERR = 34000002;

constexpr int32_t TYPE_SPATIAL_MOTION = 101;
constexpr int32_t TYPE_REALTIME_WEATHER = 102;
constexpr int32_t TYPE_REFULING = 103;
constexpr int32_t TYPE_SPATIAL_POINT = 201;
constexpr int32_t TYPE_SPATIAL_GESTURE = 202;
constexpr int32_t TYPE_CAR_STATUS = 203;
constexpr int32_t TYPE_CAR_CFG = 204;
constexpr int32_t TYPE_HABIT_RECOMMENDATION = 205;

constexpr int32_t SYSTEM_API_TYPES_START = 200;

const std::map<int32_t, std::string> FEATURE_TYPE_TO_NAME = {
    {TYPE_SPATIAL_MOTION, "SpatialMotion"},
    {TYPE_REALTIME_WEATHER, "RealTimeWeather"},
    {TYPE_REFULING, "Refueling"},
    {TYPE_SPATIAL_POINT, "SpatialPoint"},
    {TYPE_SPATIAL_GESTURE, "SpatialGesture"},
    {TYPE_CAR_STATUS, "CarStatus"},
    {TYPE_CAR_CFG, "CarCfg"},
    {TYPE_HABIT_RECOMMENDATION, "HabitRecommendation"}
};

const std::map<std::string, int32_t> FEATURE_NAME_TO_TYPE = {
    {"SpatialMotion", TYPE_SPATIAL_MOTION},
    {"RealTimeWeather", TYPE_REALTIME_WEATHER},
    {"Refueling", TYPE_REFULING},
    {"SpatialPoint", TYPE_SPATIAL_POINT},
    {"SpatialGesture", TYPE_SPATIAL_GESTURE},
    {"CarStatus", TYPE_CAR_STATUS},
    {"CarCfg", TYPE_CAR_CFG},
    {"HabitRecommendation", TYPE_HABIT_RECOMMENDATION}
};
}  // namespace

CarAwarenessServer::CarAwarenessServer()
{}

CarAwarenessServer::~CarAwarenessServer()
{
    UnloadAlgoLib();
}

int32_t CarAwarenessServer::CheckPermission(const CallingContext &context, const std::string &requiredPermission)
{
    if (AccessTokenKit::VerifyAccessToken(context.fullTokenId, requiredPermission) !=
        PermissionState::PERMISSION_GRANTED) {
        FI_HILOGI("Permission denied : %{public}s", requiredPermission.c_str());
        return COMMON_PERMISSION_CHECK_ERROR;
    }
    return RET_OK;
}

bool CarAwarenessServer::CheckSystemCall(const CallingContext &context)
{
    auto flag = AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    if ((flag == ATokenTypeEnum::TOKEN_NATIVE) || (flag == ATokenTypeEnum::TOKEN_SHELL)) {
        FI_HILOGI("system service calling, flag:%{public}u", flag);
        return true;
    }

    // 对于HAP校验是否system
    return TokenIdKit::IsSystemAppByFullTokenID(context.fullTokenId);
}

int32_t CarAwarenessServer::CheckSubPermissionByType(const CallingContext &context, int32_t type)
{
    if (type >= SYSTEM_API_TYPES_START) {  // 200 以上类型仅校验是否系统调用
        return CheckSystemCall(context) ? RET_OK : COMMON_NOT_SYSTEM_APP;
    } else if (CheckSystemCall(context)) {  // 200 以下如果是系统应用直接放行
        return RET_OK;
    }

    // 三方调用，public 类型校验权限
    switch (type) {
        case TYPE_SPATIAL_MOTION:
            return CheckPermission(context, SPATIALACTION_PERMISSION);
        case TYPE_REALTIME_WEATHER:
            return CheckPermission(context, WEATHER_PERMISSION);
        case TYPE_REFULING:
            return CheckPermission(context, ENERGYREFILL_PERMISSION);
        default:
            FI_HILOGE("unhandled type:%{public}d", type);
            return CAR_AWARENESS_SPECIFIC_ERR;
    }
    return CAR_AWARENESS_SPECIFIC_ERR;
}

void CarAwarenessServer::OnResultFromAlgo(const std::string &featureName, const std::string &result)
{
    std::lock_guard<std::mutex> lock(callbackMtx_);
    auto cbIt = callbacks_.find(featureName);
    if (cbIt == callbacks_.end()) {
        FI_HILOGW("No callback found for featureName:%{public}s", featureName.c_str());
        return;
    }
    auto callbacks = cbIt->second;

    if (FEATURE_NAME_TO_TYPE.find(featureName) == FEATURE_NAME_TO_TYPE.end()) {
        FI_HILOGE("unknown feature name: %{public}s", featureName.c_str());
        return;
    }

    CarAwarenessEvent event;
    event.type = FEATURE_NAME_TO_TYPE.at(featureName);
    event.eventData = result;
    std::thread t([callbacks, result, event]() {
        for (auto const &clientInfo : callbacks) {
            clientInfo.cb->OnAwarenessEvent(event);
        }
    });
    t.detach();
}

int32_t CarAwarenessServer::AddClientToCallbacks(const std::string &featureName, CarAwarenessClientInfo &info)
{
    auto &callbacks = callbacks_[featureName];

    // 理论上一个pid只能对一个type的特性做一个订阅，如果重复了，不允许订阅
    for (auto &clientInfo : callbacks) {
        if (clientInfo.pid == info.pid) {  // pid 相同
            FI_HILOGW("duplicate subscribe ignored, featureName:%{public}s", featureName.c_str());
            return RET_ERR;
        }
    }
    if (!AddDeathRecipient(info.cb)) {
        FI_HILOGE("AddDeathRecipient failed");
        return RET_ERR;
    }
    callbacks.push_back(info);
    return RET_OK;
}

int32_t CarAwarenessServer::SubscribeAlgo(const std::string &featureName)
{
    std::lock_guard<std::mutex> lockGrd(algoMtx_);
    if (LoadAlgoLib() != RET_OK) {
        FI_HILOGE("LoadAlgoLib failed");
        return RET_ERR;
    }
    if (algoHandle_.pAlgorithm == nullptr) {
        FI_HILOGE("algoHandle_.pAlgorithm is nullptr");
        return RET_ERR;
    }

    // 所有算法使用同一个回调，featureName做区分
    if (algoCb_ == nullptr) {
        algoCb_ = [this](const std::string &featureName, const std::string &result) {
            this->OnResultFromAlgo(featureName, result);
        };
    }

    return algoHandle_.pAlgorithm->OnCarAwareness(featureName, algoCb_);
}

int32_t CarAwarenessServer::SubscribeCapability(const CallingContext &context, int32_t type,
                                                const CarAwarenessOption &option, const sptr<ICarAwarenessCallback> &cb)
{
    (void)option;  // option预留

    if (cb == nullptr) {
        FI_HILOGE("cb is nullptr");
        return RET_ERR;
    }

    // permission
    int32_t permissionCheckResult = CheckSubPermissionByType(context, type);
    if (permissionCheckResult != RET_OK) {
        return permissionCheckResult;
    }

    if (FEATURE_TYPE_TO_NAME.find(type) == FEATURE_TYPE_TO_NAME.end()) {
        FI_HILOGE("unknown feature type:%{public}d", type);
        return CAR_AWARENESS_SPECIFIC_ERR;
    }

    std::string featureName = FEATURE_TYPE_TO_NAME.at(type);
    pid_t callingPid = context.pid;

    CarAwarenessClientInfo clientInfo = {.pid = callingPid, .cb = cb};
    FI_HILOGI("callingpid:%{public}d", callingPid);
    {
        std::lock_guard<std::mutex> lock(callbackMtx_);
        auto it = callbacks_.find(featureName);
        if (it != callbacks_.end()) { // 算法已订阅，把client添加到callback列表
            return AddClientToCallbacks(featureName, clientInfo);
        }

        // 算法未订阅，把client添加到callback列表，然后启动算法
        FI_HILOGI("Add new client and start algo type:%{public}d", type);
        callbacks_[featureName] = std::vector<CarAwarenessClientInfo>();
        if (AddClientToCallbacks(featureName, clientInfo) != RET_OK) {
            callbacks_.erase(featureName);
            return RET_ERR;
        }
    }

    // 启动算法并订阅结果
    int32_t algoRet = SubscribeAlgo(featureName);
    if (algoRet != RET_OK) { // 订阅失败的时候删除添加的client回调
        std::lock_guard<std::mutex> lock(callbackMtx_);
        EraseCallback(featureName, callingPid);
    }

    FI_HILOGI("start algo result:%{public}d, type:%{public}d", algoRet, type);
    return algoRet;
}

int32_t CarAwarenessServer::UnSubscribeCapability(const CallingContext &context, int32_t type,
                                                  const CarAwarenessOption &option,
                                                  const sptr<ICarAwarenessCallback> &cb)
{
    (void)option;  // option预留

    // permission
    int32_t permissionCheckResult = CheckSubPermissionByType(context, type);
    if (permissionCheckResult != RET_OK) {
        return permissionCheckResult;
    }

    std::lock_guard<std::mutex> lock(callbackMtx_);
    pid_t callingPid = context.pid;
    FI_HILOGI("callingpid:%{public}d type:%{public}d", callingPid, type);

    if (FEATURE_TYPE_TO_NAME.find(type) == FEATURE_TYPE_TO_NAME.end()) {
        FI_HILOGW("unknown feature type:%{public}d", type);
        return RET_OK;
    }
    EraseCallback(FEATURE_TYPE_TO_NAME.at(type), callingPid);
    return RET_OK;
}

int32_t CarAwarenessServer::UpdateSpatialActionStatus(const CallingContext &context, int32_t eventId)
{
    std::lock_guard<std::mutex> lockGrd(algoMtx_);

    // permission
    if (!CheckSystemCall(context)) {
        FI_HILOGE("not system calling");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (CheckPermission(context, SPATIALACTION_PERMISSION) != RET_OK) {
        FI_HILOGE("no permission");
        return COMMON_PERMISSION_CHECK_ERROR;
    }

    if (LoadAlgoLib() != RET_OK) {
        FI_HILOGE("LoadAlgoLib failed");
        return RET_ERR;
    }
    if (algoHandle_.pAlgorithm == nullptr) {
        FI_HILOGE("algoHandle_.pAlgorithm is nullptr");
        return RET_ERR;
    }

    bool isEnable = (eventId != 0);
    int32_t result = algoHandle_.pAlgorithm->UpdateSpatialActionStatus(isEnable);
    FI_HILOGI("eventId:%{public}d, result:%{public}d", eventId, result);
    return result;
}

int32_t CarAwarenessServer::UpdateSpatialActionZone(const CallingContext &context, int32_t zoneId)
{
    // permission
    if (!CheckSystemCall(context)) {
        FI_HILOGE("not system calling");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (CheckPermission(context, SPATIALACTION_PERMISSION) != RET_OK) {
        FI_HILOGE("no permission");
        return COMMON_PERMISSION_CHECK_ERROR;
    }

    std::lock_guard<std::mutex> lockGrd(algoMtx_);
    if (LoadAlgoLib() != RET_OK) {
        FI_HILOGE("LoadAlgoLib failed");
        return RET_ERR;
    }
    if (algoHandle_.pAlgorithm == nullptr) {
        FI_HILOGE("algoHandle_.pAlgorithm is nullptr");
        return RET_ERR;
    }

    int32_t result = algoHandle_.pAlgorithm->UpdateSpatialActionZone(zoneId);
    FI_HILOGI("zoneId:%{public}d ,result:%{public}d", zoneId, result);
    return result;
}

int32_t CarAwarenessServer::GetSupportCapabilityList(const CallingContext &context,
                                                     std::vector<std::string> &capabilities)
{
    (void)context;
    std::lock_guard<std::mutex> lockGrd(algoMtx_);

    if (LoadAlgoLib() != RET_OK) {
        FI_HILOGE("LoadAlgoLib failed");
        return RET_ERR;
    }
    if (algoHandle_.pAlgorithm == nullptr) {
        FI_HILOGE("algoHandle_.pAlgorithm is nullptr");
        return RET_ERR;
    }

    algoHandle_.pAlgorithm->GetAllCapability(capabilities);
    FI_HILOGI("get support capabilities success, size:%{public}zu", capabilities.size());
    return RET_OK;
}

int32_t CarAwarenessServer::GetCarAwareness(const CallingContext &context, int32_t type,
                                            const CarAwarenessOption &option, std::vector<CarAwarenessEvent> &events)
{
    // permission
    if (!CheckSystemCall(context)) {
        FI_HILOGE("not system calling");
        return COMMON_NOT_SYSTEM_APP;
    }

    if (LoadAlgoLib() != RET_OK) {
        FI_HILOGE("LoadAlgoLib failed");
        return RET_ERR;
    }
    if (algoHandle_.pAlgorithm == nullptr) {
        FI_HILOGE("algoHandle_.pAlgorithm is nullptr");
        return RET_ERR;
    }

    // 数据采集预留
    CarAwarenessEvent event;
    event.type = TYPE_HABIT_RECOMMENDATION;
    event.eventData = "";
    events.push_back(event);
    return RET_OK;
}

bool CarAwarenessServer::AddDeathRecipient(const sptr<ICarAwarenessCallback> &cb)
{
    auto remoteObj = cb ? cb->AsObject() : nullptr;
    if (remoteObj == nullptr) {
        FI_HILOGE("remoteObj is nullptr");
        return false;
    }

    if (deathRecipient_ == nullptr) {
        auto diedFunc = [this](const wptr<IRemoteObject> &remote) { this->OnCarAwarenessCallbackDied(remote); };
        deathRecipient_ = new (std::nothrow) CarAwarenessRemoteDeathRecipient(diedFunc);
        if (deathRecipient_ == nullptr) {
            FI_HILOGE("new CarAwarenessRemoteDeathRecipient failed");
            return false;
        }
    }

    if (!remoteObj->AddDeathRecipient(deathRecipient_)) {
        FI_HILOGE("AddDeathRecipient failed");
        return false;
    }

    return true;
}

void CarAwarenessServer::RemoveDeathRecipient(const sptr<ICarAwarenessCallback> &cb)
{
    auto remoteObj = cb ? cb->AsObject() : nullptr;
    if (remoteObj == nullptr || deathRecipient_ == nullptr) {
        FI_HILOGE("remoteObj or deathRecipient_ is nullptr");
        return;
    }

    remoteObj->RemoveDeathRecipient(deathRecipient_);
    FI_HILOGI("death recipient removed");
}

void CarAwarenessServer::UnSubscribeAlgo(const std::string &featureName)
{
    std::lock_guard<std::mutex> lockGrd(algoMtx_);
    if (LoadAlgoLib() != RET_OK) {
        FI_HILOGE("LoadAlgoLib failed");
        return;
    }
    if (algoHandle_.pAlgorithm == nullptr) {
        FI_HILOGE("algoHandle_.pAlgorithm is nullptr");
        return;
    }
    algoHandle_.pAlgorithm->OffCarAwareness(featureName);
    FI_HILOGI("unsubscribe algo success, capability=%{public}s", featureName.c_str());
}

bool CarAwarenessServer::EraseCallback(const std::string &featureName, pid_t clientPid)
{
    FI_HILOGI("featureName:%{public}s, clientPid:%{public}d", featureName.c_str(), clientPid);
    auto it = callbacks_.find(featureName);
    if (it == callbacks_.end()) {
        FI_HILOGI("feature name %{public}s do not have any callbacks", featureName.c_str());
        return false;
    }
    auto &callbacks = it->second;
    for (auto pos = callbacks.begin(); pos != callbacks.end();) {
        if (pos->pid == clientPid) {
            RemoveDeathRecipient(pos->cb);
            pos = callbacks.erase(pos);
        } else {
            ++pos;
        }
    }

    // 一类算法无cb之后，向服务端取消订阅
    if (callbacks.empty()) {
        UnSubscribeAlgo(featureName);
        callbacks_.erase(it);
    }
    return true;
}

void CarAwarenessServer::OnCarAwarenessCallbackDied(const wptr<IRemoteObject> &remote)
{
    FI_HILOGI("recv death notice");
    auto client = remote.promote();
    if (client == nullptr) {
        FI_HILOGE("promote failed");
        return;
    }

    std::lock_guard<std::mutex> lock(callbackMtx_);
    for (auto it = callbacks_.begin(); it != callbacks_.end();) {
        auto &callbacks = it->second;
        for (auto cb = callbacks.begin(); cb != callbacks.end();) {
            if (cb->cb && cb->cb->AsObject() == client) {
                cb = callbacks.erase(cb);
            } else {
                ++cb;
            }
        }

        // 一类算法无cb之后，向服务端取消订阅
        if (callbacks.empty()) {
            UnSubscribeAlgo(it->first);
            it = callbacks_.erase(it);
        } else {
            ++it;
        }
    }

    client->RemoveDeathRecipient(deathRecipient_);
    FI_HILOGW("clean up dead callback");
}

int32_t CarAwarenessServer::LoadAlgoLib()
{
    if (algoHandle_.pAlgorithm != nullptr) {
        return RET_OK;
    }

    char realCanonicalPath[PATH_MAX] = { 0 };
    if (realpath(CAR_AWARENESS_LIB_PATH.data(), realCanonicalPath) == nullptr) {
        FI_HILOGE("not canonical path");
        return RET_ERR;
    }

    algoHandle_.handle = dlopen(realCanonicalPath, RTLD_LAZY);
    if (algoHandle_.handle == nullptr) {
        FI_HILOGE("dlopen failed, errmsg: %{public}s", dlerror());
        return RET_ERR;
    }

    algoHandle_.create =
        reinterpret_cast<CarAwareness::CreateCarAwarenessMgrFuncPtr>(dlsym(algoHandle_.handle, "CreateInstance"));
    if (algoHandle_.create == nullptr) {
        FI_HILOGE("get create fail");
        dlclose(algoHandle_.handle);
        algoHandle_.Clear();
        return RET_ERR;
    }

    algoHandle_.destroy = reinterpret_cast<void (*)()>(dlsym(algoHandle_.handle, "Destroy"));
    if (algoHandle_.destroy == nullptr) {
        FI_HILOGE("get destroy fail");
        dlclose(algoHandle_.handle);
        algoHandle_.Clear();
        return RET_ERR;
    }

    algoHandle_.pAlgorithm = algoHandle_.create();
    if (algoHandle_.pAlgorithm == nullptr) {
        FI_HILOGE("get pAlgorithm fail");
        dlclose(algoHandle_.handle);
        algoHandle_.Clear();
        return RET_ERR;
    }

    int32_t ret = algoHandle_.pAlgorithm->Initialize();
    if (ret != RET_OK) {
        algoHandle_.destroy();
        dlclose(algoHandle_.handle);
        algoHandle_.Clear();
        FI_HILOGE("Initialize failed with code:%{public}d", ret);
    }
    FI_HILOGI("Initialize success");
    return ret;
}

int32_t CarAwarenessServer::UnloadAlgoLib()
{
    if (algoHandle_.pAlgorithm != nullptr && algoHandle_.destroy != nullptr) {
        algoHandle_.destroy();
    }
    if (algoHandle_.handle != nullptr) {
        dlclose(algoHandle_.handle);
    }
    algoHandle_.Clear();
    return RET_OK;
}
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS