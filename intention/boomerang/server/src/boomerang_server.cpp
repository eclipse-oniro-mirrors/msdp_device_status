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

#include "boomerang_server.h"

#include "hisysevent.h"
#include "hitrace_meter.h"
#include "tokenid_kit.h"
#include "accesstoken_kit.h"

#include "boomerang_params.h"
#include "default_params.h"
#include "devicestatus_define.h"
#include "devicestatus_dumper.h"
#include "devicestatus_hisysevent.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangServer"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

BoomerangServer::BoomerangServer()
{
    manager_.Init();
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

int32_t BoomerangServer::SubscribeCallback(CallingContext &context, int32_t type, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& subCallback)
{
    if (subCallback == nullptr) {
        FI_HILOGE("The subCallback is null.");
        return RET_ERR;
    }
    BoomerangType boomerangType = static_cast<BoomerangType>(type);
    auto appInfo = std::make_shared<BoomerangAppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    manager_.GetPackageName(appInfo->tokenId, appInfo->packageName);
    appInfo->type = boomerangType;
    appInfo->boomerangCallback = subCallback;
    DS_DUMPER->SaveBoomerangAppInfo(appInfo);
    manager_.Subscribe(boomerangType, bundleName, subCallback);
    return RET_OK;
}

int32_t BoomerangServer::UnsubscribeCallback(CallingContext &context, int32_t type, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& unsubCallback)
{
    if (unsubCallback == nullptr) {
        FI_HILOGE("The unsubCallback is null.");
        return RET_ERR;
    }
    BoomerangType boomerangType = static_cast<BoomerangType>(type);
    auto appInfo = std::make_shared<BoomerangAppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    appInfo->packageName = DS_DUMPER->GetPackageName(appInfo->tokenId);
    appInfo->type = boomerangType;
    appInfo->boomerangCallback = unsubCallback;
    DS_DUMPER->RemoveBoomerangAppInfo(appInfo);
    manager_.Unsubscribe(boomerangType, bundleName, unsubCallback);
    return RET_OK;
}

int32_t BoomerangServer::NotifyMetadataBindingEvent(CallingContext &context, const std::string& bundleName,
    const sptr<IRemoteBoomerangCallback>& notifyCallback)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (notifyCallback == nullptr) {
        FI_HILOGE("The notifyCallback is null.");
        return RET_ERR;
    }
    auto appInfo = std::make_shared<BoomerangAppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    appInfo->packageName = DS_DUMPER->GetPackageName(appInfo->tokenId);
    appInfo->boomerangCallback = notifyCallback;
    DS_DUMPER->SetNotifyMetadatAppInfo(appInfo);
    return manager_.NotifyMedata(bundleName, notifyCallback);
}

int32_t BoomerangServer::SubmitMetadata(CallingContext &context, const std::string& metaData)
{
    if (metaData.empty()) {
        FI_HILOGE("The metaData is empty.");
        return RET_ERR;
    }
    manager_.SubmitMetadata(metaData);
    return RET_OK;
}

int32_t BoomerangServer::BoomerangEncodeImage(CallingContext &context, const std::shared_ptr<Media::PixelMap>& pixelMap,
    const std::string& metaData, const sptr<IRemoteBoomerangCallback>& encodeCallback)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (encodeCallback == nullptr) {
        FI_HILOGE("The encodeCallback is null.");
        return RET_ERR;
    }
    auto appInfo = std::make_shared<BoomerangAppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    appInfo->packageName = DS_DUMPER->GetPackageName(appInfo->tokenId);
    appInfo->boomerangCallback = encodeCallback;
    DS_DUMPER->SetNotifyMetadatAppInfo(appInfo);
    manager_.BoomerangEncodeImage(pixelMap, metaData, encodeCallback);
    return RET_OK;
}

int32_t BoomerangServer::BoomerangDecodeImage(CallingContext &context, const std::shared_ptr<Media::PixelMap>& pixelMap,
    const sptr<IRemoteBoomerangCallback>& decodeCallback)
{
    if (!IsSystemHAPCalling(context)) {
        FI_HILOGE("The caller is not system hap");
        return COMMON_NOT_SYSTEM_APP;
    }
    if (decodeCallback == nullptr) {
        FI_HILOGE("The decodeCallback is null.");
        return RET_ERR;
    }
    auto appInfo = std::make_shared<BoomerangAppInfo>();
    appInfo->uid = context.uid;
    appInfo->pid = context.pid;
    appInfo->tokenId = context.tokenId;
    appInfo->packageName = DS_DUMPER->GetPackageName(appInfo->tokenId);
    appInfo->boomerangCallback = decodeCallback;
    DS_DUMPER->SetNotifyMetadatAppInfo(appInfo);
    manager_.BoomerangDecodeImage(pixelMap, decodeCallback);
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