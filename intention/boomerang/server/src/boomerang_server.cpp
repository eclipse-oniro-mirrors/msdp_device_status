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

#include "boomerang_server.h"

#include "hisysevent.h"
#include "hitrace_meter.h"
#include "tokenid_kit.h"
#include "accesstoken_kit.h"

#include "default_params.h"
#include "devicestatus_define.h"
#include "devicestatus_dumper.h"
#include "devicestatus_hisysevent.h"
#include "boomerang_params.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

BoomerangServer::BoomerangServer()
{
    manager_.Init();
}

int32_t BoomerangServer::Enable(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t BoomerangServer::Disable(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t BoomerangServer::Start(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t BoomerangServer::Stop(CallingContext &context, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

int32_t BoomerangServer::AddWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    switch (id) {
        case BoomerangRequestID::ADD_BOOMERAMG_LISTENER: {
            return Subscribe(context, data);
        }
        case BoomerangRequestID::NOTIFY_METADATA: {
            return NotifyMetadataBindingEvent(context, data);
        }
        case BoomerangRequestID::ENCODE_IMAGE: {
            return BoomerangEncodeImage(context, data);
        }
        case BoomerangRequestID::DECODE_IMAGE: {
            return BoomerangDecodeImage(context, data);
        }
        default: {
            FI_HILOGE("Unexpected request ID (%{public}u)", id);
            return RET_ERR;
        }
    }
}

int32_t BoomerangServer::RemoveWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    switch (id) {
        case BoomerangRequestID::REMOVE_BOOMERAMG_LISTENER: {
            return Unsubscribe(context, data);
        }
        default: {
            FI_HILOGE("Unexpected request ID (%{public}u)", id);
            return RET_ERR;
        }
    }
}

int32_t BoomerangServer::SetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    switch (id) {
        case BoomerangRequestID::SUBMIT_METADATA: {
            return SubmitMetadata(context, data);
        }
        default: {
            FI_HILOGE("Unexpected request ID (%{public}u)", id);
            return RET_ERR;
        }
    }
    return RET_ERR;
}

int32_t BoomerangServer::GetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_OK;
}

int32_t BoomerangServer::Control(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply)
{
    CALL_DEBUG_ENTER;
    return RET_ERR;
}

void BoomerangServer::DumpDeviceStatusSubscriber(int32_t fd) const
{
    DS_DUMPER->DumpDeviceStatusSubscriber(fd);
}

void BoomerangServer::DumpDeviceStatusChanges(int32_t fd) const
{
    DS_DUMPER->DumpDeviceStatusChanges(fd);
}

void BoomerangServer::DumpCurrentDeviceStatus(int32_t fd)
{
    std::vector<Data> datas;

    for (auto type = TYPE_ABSOLUTE_STILL; type <= TYPE_LID_OPEN; type = static_cast<Type>(type + 1)) {
        Data data = manager_.GetLatestDeviceStatusData(type);
        if (data.value != OnChangedValue::VALUE_INVALID) {
            datas.emplace_back(data);
        }
    }
    DS_DUMPER->DumpDeviceStatusCurrentStatus(fd, datas);
}

int32_t BoomerangServer::Subscribe(CallingContext &context, MessageParcel &data)
{
    SubscribeBoomerangParam param {};
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("SubscribeStationaryParam::Unmarshalling fail");
        return RET_ERR;
    }
    auto appInfo = std::make_shared<BoomerangAppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    manager_.GetPackageName(appInfo->tokenId, appInfo->packageName);
    appInfo->type = param.type_;
    appInfo->boomerangCallback = param.callback_;
    DS_DUMPER->SaveBoomerangAppInfo(appInfo);
    manager_.Subscribe(param.type_, param.bundleName_, param.callback_);
    return RET_OK;
}

int32_t BoomerangServer::Unsubscribe(CallingContext &context, MessageParcel &data)
{
    SubscribeBoomerangParam param {};
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("UnsubscribeStationaryParam::Unmarshalling fail");
        return RET_ERR;
    }
    auto appInfo = std::make_shared<BoomerangAppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    appInfo->packageName = DS_DUMPER->GetPackageName(appInfo->tokenId);
    appInfo->type = param.type_;
    appInfo->boomerangCallback = param.callback_;
    DS_DUMPER->RemoveBoomerangAppInfo(appInfo);
    manager_.Unsubscribe(param.type_, param.bundleName_, param.callback_);
    return RET_OK;
}

int32_t BoomerangServer::NotifyMetadataBindingEvent(CallingContext &context, MessageParcel &data)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    NotifyMetadataParam param {};
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("GetNotifyMetadataParam::Unmarshalling fail");
        return RET_ERR;
    }
    auto appInfo = std::make_shared<BoomerangAppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    appInfo->packageName = DS_DUMPER->GetPackageName(appInfo->tokenId);
    appInfo->boomerangCallback = param.callback_;
    DS_DUMPER->SetNotifyMetadatAppInfo(appInfo);
    return manager_.NotifyMedata(param.bundleName_, param.callback_);
}

int32_t BoomerangServer::BoomerangEncodeImage(CallingContext &context, MessageParcel &data)
{
    EncodeImageParam param {};
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("GetNotifyMetadataParam::Unmarshalling fail");
        return RET_ERR;
    }
    auto appInfo = std::make_shared<BoomerangAppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    appInfo->packageName = DS_DUMPER->GetPackageName(appInfo->tokenId);
    appInfo->boomerangCallback = param.callback_;
    DS_DUMPER->SetNotifyMetadatAppInfo(appInfo);
    manager_.BoomerangEncodeImage(param.pixelMap_, param.metadata_, param.callback_);
    return RET_OK;
}

int32_t BoomerangServer::BoomerangDecodeImage(CallingContext &context, MessageParcel &data)
{
    DecodeImageParam param {};
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("GetNotifyMetadataParam::Unmarshalling fail");
        return RET_ERR;
    }
    auto appInfo = std::make_shared<BoomerangAppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    appInfo->packageName = DS_DUMPER->GetPackageName(appInfo->tokenId);
    appInfo->boomerangCallback = param.callback_;
    DS_DUMPER->SetNotifyMetadatAppInfo(appInfo);
    manager_.BoomerangDecodeImage(param.pixelMap_, param.callback_);
    return RET_OK;
}

int32_t BoomerangServer::SubmitMetadata(CallingContext &context, MessageParcel &data)
{
    MetadataParam param {};
    if (!param.Unmarshalling(data)) {
        FI_HILOGE("GetNotifyMetadataParam::Unmarshalling fail");
        return RET_ERR;
    }
    manager_.SubmitMetadata(param.metadata_);
    return RET_OK;
}

Data BoomerangServer::GetCache(CallingContext &context, const Type &type)
{
    return manager_.GetLatestDeviceStatusData(type);
}

void BoomerangServer::ReportSensorSysEvent(CallingContext &context, int32_t type, bool enable)
{
    std::string packageName;
    manager_.GetPackageName(context.tokenId, packageName);
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::MSDP,
        std::string(enable ? "Subscribe" : "Unsubscribe"),
        OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "UID", context.uid,
        "PKGNAME", packageName,
        "TYPE", type);
    if (ret != 0) {
        FI_HILOGE("HiviewDFX write failed, error:%{public}d", ret);
    }
}

bool BoomerangServer::IsSystemServiceCalling(CallingContext &context)
{
    auto flag = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(context.tokenId);
    if ((flag == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) ||
        (flag == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL)) {
        FI_HILOGI("system service calling, flag:%{public}u", flag);
        return true;
    }
    return false;
}

bool BoomerangServer::IsSystemHAPCalling(CallingContext &context)
{
    if (IsSystemServiceCalling(context)) {
        return true;
    }
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(context.fullTokenId);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS