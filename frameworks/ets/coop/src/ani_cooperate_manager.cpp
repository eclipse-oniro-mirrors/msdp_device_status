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

#include "ani_cooperate_manager.h"

#include "devicestatus_define.h"
#include "interaction_manager.h"


#undef LOG_TAG
#define LOG_TAG "AniCooperateManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

namespace {
const std::string COORDINATION = "cooperation";
}

AniCooperateManager::AniCooperateManager()
{
    CALL_DEBUG_ENTER;
    auto ret = coordinationListeners_.insert({ COORDINATION,
    std::vector<std::shared_ptr<AniCallbackInfo>>()});
    if (!ret.second) {
        FI_HILOGW("Failed to add listener, errCode:%{public}d", static_cast<int32_t>(DeviceStatus::VAL_NOT_EXP));
    }
}

AniCooperateManager::~AniCooperateManager()
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    coordinationListeners_.clear();
    if (isListeningProcess_) {
        isListeningProcess_ = false;
        if (listener_) {
            INTERACTION_MGR->UnregisterCoordinationListener(listener_);
            listener_ = nullptr;
        }
    }
}

AniCooperateManager& AniCooperateManager::GetInstance()
{
    static AniCooperateManager instance;
    return instance;
}

void AniCooperateManager::EmitAniPromise(std::shared_ptr<AniCallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    if (cb == nullptr) {
        FI_HILOGE("cb is nullptr");
        return;
    }
    if (cb->promise_ != nullptr) {
        FI_HILOGE("promise is nullptr");
        return;
    }
    auto env = cb->envT_;
    if (cb->result_) {
        CooperateCommon::ExecAsyncCallbackPromise(env, cb->deferred_, nullptr, nullptr);
        return;
    }
    std::string errMsg;
    if (!CooperateCommon::GetErrMsg(cb->msgInfo_, errMsg)) {
        FI_HILOGE("GetErrMsg failed");
        return;
    }
    int32_t errorCode = CooperateCommon::GetErrCode(cb->msgInfo_);
    FI_HILOGD("errorCode:%{public}d, msg:%{public}s", errorCode, errMsg.c_str());
    auto callResult = CooperateCommon::CreateBusinessError(env, static_cast<ani_int>(errorCode), errMsg);
    if (callResult == nullptr) {
        FI_HILOGE("The callResult is nullptr");
        return;
    }
    CooperateCommon::ExecAsyncCallbackPromise(env, cb->deferred_, callResult, nullptr);
    return;
}

void AniCooperateManager::EmitAniAsyncCallback(std::shared_ptr<AniCallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    if (cb == nullptr) {
        FI_HILOGE("cb is nullptr");
        return;
    }
    if (cb->funObject_ != nullptr) {
        FI_HILOGE("promise is nullptr");
        return;
    }
    auto env = cb->envT_;
    ani_ref  aniUndefined;
    ani_ref  aniNull;
    ani_status status;
    if ((status = env->GetUndefined(&aniUndefined)) != ANI_OK) {
        FI_HILOGE("get undefined value failed, status = %{public}d", status);
        return;
    }
    if ((status = env->GetNull(&aniNull)) != ANI_OK) {
        FI_HILOGE("get undefined value failed, status = %{public}d", status);
        return;
    }
    if (cb->result_) {
        CooperateCommon::ExecAsyncCallBack(env, static_cast<ani_object>(aniNull),
            static_cast<ani_object>(aniUndefined), cb->funObject_);
        return;
    }
    std::string errMsg;
    if (!CooperateCommon::GetErrMsg(cb->msgInfo_, errMsg)) {
        FI_HILOGE("GetErrMsg failed");
        return;
    }
    int32_t errorCode = CooperateCommon::GetErrCode(cb->msgInfo_);
    FI_HILOGD("errorCode:%{public}d, msg:%{public}s", errorCode, errMsg.c_str());
    auto callResult = CooperateCommon::CreateBusinessError(env, static_cast<ani_int>(errorCode), errMsg);
    if (callResult == nullptr) {
        FI_HILOGE("The callResult is nullptr");
        return;
    }
    CooperateCommon::ExecAsyncCallBack(env, static_cast<ani_object>(callResult),
        static_cast<ani_object>(aniUndefined), cb->funObject_);
    return;
}

void AniCooperateManager::EmitAni(std::shared_ptr<AniCallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    if (cb == nullptr) {
        FI_HILOGE("cb is nullptr");
        return;
    }
    if (cb->promise_ != nullptr) {
        EmitAniPromise(cb);
        return;
    }
    EmitAniAsyncCallback(cb);
}

void AniCooperateManager::EmitGetState(std::shared_ptr<AniCallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    if (cb == nullptr) {
        FI_HILOGE("cb is nullptr");
        return;
    }
    auto env = cb->envT_;
    ani_ref  aniNull;
    ani_status status;
    ani_object aniResult = CooperateCommon::CreateBooleanObject(env, cb->result_);
    if (aniResult == nullptr) {
        FI_HILOGE("create boolean object is null");
        return;
    }
    if ((status = env->GetNull(&aniNull)) != ANI_OK) {
        FI_HILOGE("get undefined value failed, status = %{public}d", status);
        return;
    }
    if (cb->promise_ != nullptr) {
        CooperateCommon::ExecAsyncCallbackPromise(env, cb->deferred_, static_cast<ani_object>(aniNull), nullptr);
        return;
    }
    CooperateCommon::ExecAsyncCallBack(env, static_cast<ani_object>(aniNull), aniResult, cb->funObject_);
    return;
}

void AniCooperateManager::Enable(bool enable, uintptr_t opq, ani_object& promise)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<AniCallbackInfo> cb = std::make_shared<AniCallbackInfo>(CallbackType::ENABLE);
    if (nullptr == cb) {
        FI_HILOGE("cbInfo is null");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    if (!cb->init(opq)) {
        FI_HILOGE("init err");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    promise = cb->promise_;
    auto callback = [this, cb](const std::string &networkId, const CoordinationMsgInfo &msgInfo) {
        CALL_DEBUG_ENTER;
        cb->result_ = (msgInfo.msg == CoordinationMessage::PREPARE ||
            msgInfo.msg == CoordinationMessage::UNPREPARE);
        cb->msgInfo_ = msgInfo;
        cb->AttachThread();
        EmitAni(cb);
        cb->DetachThread();
    };
    int32_t errCode = 0;
    if (enable) {
        errCode = INTERACTION_MGR->PrepareCoordination(callback);
    } else {
        errCode = INTERACTION_MGR->UnprepareCoordination(callback);
    }
    if (errCode != RET_OK) {
        CooperateCommon::HandleExecuteResult(errCode, "enable", COOPERATE_PERMISSION);
    }
    return;
}

void AniCooperateManager::Start(const std::string &remoteNetworkDescriptor,
    int32_t startDeviceId, uintptr_t opq, ani_object& promise)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<AniCallbackInfo> cb = std::make_shared<AniCallbackInfo>(CallbackType::START);
    if (nullptr == cb) {
        FI_HILOGE("cbInfo is null");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    if (!cb->init(opq)) {
        FI_HILOGE("init err");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    promise = cb->promise_;
    auto callback = [this, cb](const std::string &networkId, const CoordinationMsgInfo &msgInfo) {
        CALL_DEBUG_ENTER;
        cb->result_ = (msgInfo.msg == CoordinationMessage::ACTIVATE_SUCCESS);
        cb->msgInfo_ = msgInfo;
        cb->AttachThread();
        EmitAni(cb);
        cb->DetachThread();
    };
    int32_t errCode = 0;
    errCode = INTERACTION_MGR->ActivateCoordination(remoteNetworkDescriptor, startDeviceId, callback);
    if (errCode != RET_OK) {
        CooperateCommon::HandleExecuteResult(errCode, "start", COOPERATE_PERMISSION);
    }
    return;
}

void AniCooperateManager::Stop(uintptr_t opq, ani_object& promise)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<AniCallbackInfo> cb = std::make_shared<AniCallbackInfo>(CallbackType::STOP);
    if (nullptr == cb) {
        FI_HILOGE("cbInfo is null");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    if (!cb->init(opq)) {
        FI_HILOGE("init err");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    promise = cb->promise_;
    auto callback = [this, cb](const std::string &networkId, const CoordinationMsgInfo &msgInfo) {
        CALL_DEBUG_ENTER;
        cb->result_ = (msgInfo.msg == CoordinationMessage::DEACTIVATE_SUCCESS);
        cb->msgInfo_ = msgInfo;
        cb->AttachThread();
        EmitAni(cb);
        cb->DetachThread();
    };
    bool isUnchained = false;
    int32_t errCode = 0;
    errCode = INTERACTION_MGR->DeactivateCoordination(isUnchained, callback);
    if (errCode != RET_OK) {
        CooperateCommon::HandleExecuteResult(errCode, "stop", COOPERATE_PERMISSION);
    }
    return;
}

void AniCooperateManager::GetState(const std::string &deviceDescriptor, uintptr_t opq, ani_object& promise)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<AniCallbackInfo> cb = std::make_shared<AniCallbackInfo>(CallbackType::GETSTATE);
    if (nullptr == cb) {
        FI_HILOGE("cbInfo is null");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    if (!cb->init(opq)) {
        FI_HILOGE("init err");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    promise = cb->promise_;
    auto callback = [this, cb](bool state) {
        CALL_DEBUG_ENTER;
        cb->result_ = state;
        cb->AttachThread();
        EmitGetState(cb);
        cb->DetachThread();
    };
    int32_t errCode = 0;
    errCode = INTERACTION_MGR->GetCoordinationState(deviceDescriptor, callback);
    if (errCode != RET_OK) {
        CooperateCommon::HandleExecuteResult(errCode, "getState", COOPERATE_PERMISSION);
    }
    return;
}

void AniCooperateManager::OnCooperation(uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    std::shared_ptr<AniCallbackInfo> cb = std::make_shared<AniCallbackInfo>(CallbackType::ON);
    if (nullptr == cb) {
        FI_HILOGE("cbInfo is null");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    if (!cb->init(opq)) {
        FI_HILOGE("init err");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "internal Error");
        return;
    }
    std::string type = COORDINATION;
    auto iter = coordinationListeners_.find(type);
    if (iter == coordinationListeners_.end()) {
        FI_HILOGE("Failed to add listener, type:%{public}s", type.c_str());
        return;
    }
    for (const auto &item : iter->second) {
        CHKPC(item);
        if (CooperateCommon::IsSameHandle(cb->env_, item->ref_, cb->ref_)) {
            FI_HILOGE("The handle already exists");
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "The handle already exists");
            return;
        }
    }
    iter->second.push_back(cb);
    if (!isListeningProcess_) {
        isListeningProcess_ = true;
        listener_ = std::make_shared<AniEventCooperateTarget>();
        INTERACTION_MGR->RegisterCoordinationListener(listener_);
    }
}

void AniCooperateManager::OffCooperation(::taihe::optional_view<uintptr_t> opq)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto type = COORDINATION;
    auto iter = coordinationListeners_.find(type);
    if (iter == coordinationListeners_.end()) {
        FI_HILOGE("Failed to remove listener, type:%{public}s", type.c_str());
        return;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        FI_HILOGE("ani_env is nullptr!");
        return;
    }
    if (!opq.has_value()) {
        iter->second.clear();
    } else {
        GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
        if (!guard) {
            FI_HILOGE("GlobalRefGuard is false!");
            return;
        }
        for (auto it = iter->second.begin(); it != iter->second.end();) {
            bool isSame = CooperateCommon::IsSameHandle(env, (*it)->ref_, guard.get());
            if (isSame) {
                FI_HILOGD("Successfully removed the listener");
                it = iter->second.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (isListeningProcess_ && iter->second.empty()) {
        isListeningProcess_ = false;
        if (listener_) {
            INTERACTION_MGR->UnregisterCoordinationListener(listener_);
            listener_ = nullptr;
        }
    }
}

void AniCooperateManager::EmitCoordinationMessageEvent(std::shared_ptr<AniCallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    if (cb == nullptr) {
        FI_HILOGE("The data is nullptr");
        return;
    }
    CHKPV(cb->env_);
    CHKPV(cb->envT_);
    CHKPV(cb->funObject_);
    auto env = cb->envT_;
    auto iter = messageTransform_.find(cb->msgInfo_.msg);
    if (iter == messageTransform_.end()) {
            FI_HILOGE("Failed to find the message code");
            return;
    }
    using AniCoopInfo = ::ohos::multimodalInput::inputDeviceCooperate::Coopinfo;
    using AniEvnetMsg = ::ohos::multimodalInput::inputDeviceCooperate::EventMsg;
    AniCoopInfo info {
        .deviceDescriptor = cb->deviceDescriptor_,
        .eventMsg = AniEvnetMsg::from_value(static_cast<int32_t>(iter->second))
    };
    info.deviceDescriptor = cb->deviceDescriptor_;
    auto param = ::taihe::into_ani<AniCoopInfo>(env, info);
    ani_ref  aniNull;
    ani_status status;
    if ((status = env->GetNull(&aniNull)) != ANI_OK) {
        FI_HILOGE("get undefined value failed, status = %{public}d", status);
        return;
    }
    CooperateCommon::ExecAsyncCallBack(env, static_cast<ani_object>(aniNull),
        param, cb->funObject_);
}

void AniCooperateManager::OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> guard(mutex_);
    auto changeEvent = coordinationListeners_.find(COORDINATION);
    if (changeEvent == coordinationListeners_.end()) {
        FI_HILOGE("Failed to find the %{public}s", std::string(COORDINATION).c_str());
        return;
    }
    for (auto &item : changeEvent->second) {
        CHKPC(item);
        CHKPC(item->env_);
        item->msgInfo_.msg = msg;
        item->deviceDescriptor_ = networkId;
        item->AttachThread();
        EmitCoordinationMessageEvent(item);
        item->DetachThread();
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
