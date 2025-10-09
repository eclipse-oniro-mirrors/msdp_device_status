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

#include "ohos.deviceStatus.dragInteraction.impl.h"

#undef LOG_TAG
#define LOG_TAG "ohos.deviceStatus.dragInteraction"

namespace {
static DragState ConverDragState(DeviceStatus::DragState state)
{
    switch (state) {
        case DeviceStatus::DragState::ERROR:
            return DragState::key_t::MSG_DRAG_STATE_ERROR;
        case DeviceStatus::DragState::START:
            return DragState::key_t::MSG_DRAG_STATE_START;
        case DeviceStatus::DragState::STOP:
            return DragState::key_t::MSG_DRAG_STATE_STOP;
        case DeviceStatus::DragState::CANCEL:
            return DragState::key_t::MSG_DRAG_STATE_CANCEL;
        case DeviceStatus::DragState::MOTION_DRAGGING:
            return DragState::key_t::MSG_DRAG_STATE_MOTION_DRAGGING;
    }
}

std::shared_ptr<EtsDragManager> EtsDragManager::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<EtsDragManager> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<EtsDragManager>();
    });
    return instance_;
}

void EtsDragManager::registerListener(callback_view<void(DragState)> callback, uintptr_t opq)
{
    std::lock_guard<std::mutex> lock(mutex_);
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        FI_HILOGE("ani_env is nullptr or GlobalReference_Create failed");
        return;
    }
    auto &cbVec = jsCbMap_["drag"];
    bool isDuplicate = std::any_of(cbVec.begin(), cbVec.end(), [env, callbackRef](
        std::shared_ptr<CallbackObject> &obj) {
        ani_boolean isEqual = false;
        return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
    });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        FI_HILOGD("callback already registered");
        return;
    }
    cbVec.emplace_back(std::make_shared<CallbackObject>(callback, callbackRef));
    FI_HILOGI("register callback success");
    if (!hasRegistered_) {
        FI_HILOGI("  drag listener to server");
        hasRegistered_ = true;
        INTERACTION_MGR->AddDraglistener(shared_from_this(), true);
    }
}

void EtsDragManager::unRegisterListener(optional_view<uintptr_t> opq)
{
    std::lock_guard<std::mutex> lock(mutex_);
    const auto iter = jsCbMap_.find("drag");
    if (iter == jsCbMap_.end()) {
        FI_HILOGE("Already unRegistered!");
        return;
    }
    if (!opq.has_value()) {
        jsCbMap_.erase(iter);
        FI_HILOGD("callback is nullptr!");
        return;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        FI_HILOGE("ani_env is nullptr!");
        return;
    }
    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (!guard) {
        FI_HILOGE("GlobalRefGuard is false!");
        return;
    }
    const auto pred = [env, targetRef = guard.get()](std::shared_ptr<CallbackObject> &obj) {
        ani_boolean isEqual = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &isEqual)) && isEqual;
    };
    auto &callbacks = iter->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        FI_HILOGI("unRegister callback success");
        callbacks.erase(it);
    }
    if (callbacks.empty()) {
        jsCbMap_.erase(iter);
    }
    if (hasRegistered_ && jsCbMap_.empty()) {
        FI_HILOGI(" Remove drag listener to server");
        hasRegistered_ = false;
        INTERACTION_MGR->RemoveDraglistener(shared_from_this(), true);
    }
}

void EtsDragManager::OnDragMessage(DeviceStatus::DragState state)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(mutex_);
    if (jsCbMap_.empty()) {
        FI_HILOGE("The listener list is empty");
        return;
    }
    const auto iter = jsCbMap_.find("drag");
    if (iter == jsCbMap_.end()) {
        FI_HILOGE("not found listeners!");
        return;
    }
    for (const auto &cb : iter->second) {
        auto &func = std::get<taihe::callback<void(DragState)>>(cb->callback);
        func(ConverDragState(state));
    }
}

array<Summary> EtsDragManager::getDataSummary()
{
    std::map<std::string, int64_t> summarys;
    if (INTERACTION_MGR->GetDragSummary(summarys, true) != RET_OK) {
        FI_HILOGE("Failed to GetDragSummary");
        return array<Summary>(nullptr, 0);
    }
    if (summarys.empty()) {
        FI_HILOGE("Summarys is empty");
        return array<Summary>(nullptr, 0);
    }
    std::vector<Summary> arr;
    for (const auto &summary : summarys) {
        Summary object{};
        object.dataType = summary.first;
        object.dataSize = summary.second;
        arr.push_back(object);
    }
    return array<Summary>(arr);
}

void registerListener(callback_view<void(DragState)> callback, uintptr_t opq)
{
    return EtsDragManager::GetInstance()->registerListener(callback, opq);
}

void unRegisterListener(optional_view<uintptr_t> opq)
{
    return EtsDragManager::GetInstance()->unRegisterListener(opq);
}

array<Summary> getDataSummary()
{
    return EtsDragManager::GetInstance()->getDataSummary();
}
} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_registerListener(registerListener);
TH_EXPORT_CPP_API_unRegisterListener(unRegisterListener);
TH_EXPORT_CPP_API_getDataSummary(getDataSummary);
// NOLINTEND