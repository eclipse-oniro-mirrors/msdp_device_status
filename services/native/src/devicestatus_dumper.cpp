/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "devicestatus_dumper.h"

#include <cinttypes>
#include <cstring>
#include <getopt.h>
#include <iomanip>
#include <map>
#include <sstream>

#include <ipc_skeleton.h>
#include "securec.h"
#include "string_ex.h"
#include "unique_fd.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "include/util.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusDumper"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t MAX_DEVICE_STATUS_SIZE { 10 };
} // namespace

DeviceStatusDumper::DeviceStatusDumper() {}
DeviceStatusDumper::~DeviceStatusDumper() {}

int32_t DeviceStatusDumper::Init(IContext *context)
{
    CALL_DEBUG_ENTER;
    CHKPR(context, RET_ERR);
    context_ = context;
    return RET_OK;
}

void DeviceStatusDumper::ParseCommand(int32_t fd, const std::vector<std::string> &args, const std::vector<Data> &datas)
{
    constexpr size_t BUFSIZE { 1024 };
    char buf[BUFSIZE] { "hidumper" };

    std::vector<char *> argv(args.size() + 1);
    argv[0] = buf;

    size_t len = std::strlen(buf) + 1;
    char *pbuf = buf + len;
    size_t bufLen = sizeof(buf) - len;

    for (size_t index = 0, cnt = args.size(); index < cnt; ++index) {
        len = args[index].size() + 1;
        if (len > bufLen) {
            FI_HILOGE("Buffer overflow");
            return;
        }
        args[index].copy(pbuf, args[index].size());
        pbuf[args[index].size()] = '\0';

        argv[index + 1] = pbuf;
        pbuf += len;
        bufLen -= len;
    }

    struct option dumpOptions[] {
        { "help", no_argument, nullptr, 'h' },
        { "subscribe", no_argument, nullptr, 's' },
        { "list", no_argument, nullptr, 'l' },
        { "current", no_argument, nullptr, 'c' },
        { "coordination", no_argument, nullptr, 'o' },
        { "drag", no_argument, nullptr, 'd' },
        { "macroState", no_argument, nullptr, 'm' },
        { nullptr, 0, nullptr, 0 }
    };
    optind = 0;

    for (;;) {
        int32_t opt = getopt_long(argv.size(), argv.data(), "+hslcodm", dumpOptions, nullptr);
        if (opt < 0) {
            break;
        }
        ExecutDump(fd, datas, opt);
    }
}

void DeviceStatusDumper::ExecutDump(int32_t fd, const std::vector<Data> &datas, int32_t opt)
{
    switch (opt) {
        case 'h': {
            DumpHelpInfo(fd);
            break;
        }
        case 's': {
            DumpDeviceStatusSubscriber(fd);
            break;
        }
        case 'l': {
            DumpDeviceStatusChanges(fd);
            break;
        }
        case 'c': {
            DumpDeviceStatusCurrentStatus(fd, datas);
            break;
        }
        case 'o': {
#ifdef OHOS_BUILD_ENABLE_COORDINATION
            dprintf(fd, "device coordination is not supported\n");
#endif // OHOS_BUILD_ENABLE_COORDINATION
            break;
        }
        case 'd': {
            CHKPV(context_);
            context_->GetDragManager().Dump(fd);
            break;
        }
        case 'm': {
            DumpCheckDefine(fd);
            break;
        }
        default: {
            dprintf(fd, "cmd param is error\n");
            DumpHelpInfo(fd);
            break;
        }
    }
}

void DeviceStatusDumper::DumpDeviceStatusSubscriber(int32_t fd)
{
    CALL_DEBUG_ENTER;
    std::unique_lock lock(mutex_);
    if (appInfos_.empty()) {
        FI_HILOGE("appInfos_ is empty");
        return;
    }
    std::string startTime;
    GetTimeStamp(startTime);
    dprintf(fd, "Current time:%s \n", startTime.c_str());
    for (const auto &item : appInfos_) {
        for (const auto &appInfo : item.second) {
            dprintf(fd, "startTime:%s | uid:%d | pid:%d | type:%s | packageName:%s\n",
                appInfo->startTime.c_str(), appInfo->uid, appInfo->pid, GetStatusType(appInfo->type).c_str(),
                appInfo->packageName.c_str());
        }
    }
}

void DeviceStatusDumper::DumpDeviceStatusChanges(int32_t fd)
{
    CALL_DEBUG_ENTER;
    std::unique_lock lock(mutex_);
    if (deviceStatusQueue_.empty()) {
        FI_HILOGI("deviceStatusQueue_ is empty");
        return;
    }
    std::string startTime;
    GetTimeStamp(startTime);
    dprintf(fd, "Current time:%s\n", startTime.c_str());
    size_t length = deviceStatusQueue_.size() > MAX_DEVICE_STATUS_SIZE ?
        MAX_DEVICE_STATUS_SIZE : deviceStatusQueue_.size();
    for (size_t i = 0; i < length; ++i) {
        auto record = deviceStatusQueue_.front();
        CHKPC(record);
        deviceStatusQueue_.push(record);
        deviceStatusQueue_.pop();
        dprintf(fd, "startTime:%s | type:%s | value:%s\n",
            record->startTime.c_str(), GetStatusType(record->data.type).c_str(),
            GetDeviceState(record->data.value).c_str());
    }
}

void DeviceStatusDumper::DumpDeviceStatusCurrentStatus(int32_t fd, const std::vector<Data> &datas) const
{
    CALL_DEBUG_ENTER;
    std::string startTime;
    GetTimeStamp(startTime);
    dprintf(fd, "Current time:%s\n", startTime.c_str());
    dprintf(fd, "Current device status:\n");
    if (datas.empty()) {
        dprintf(fd, "No device status available\n");
        return;
    }
    for (auto it = datas.begin(); it != datas.end(); ++it) {
        if (it->value == VALUE_INVALID) {
            continue;
        }
        dprintf(fd, "type:%s | state:%s\n",
            GetStatusType(it->type).c_str(), GetDeviceState(it->value).c_str());
    }
}

std::string DeviceStatusDumper::GetDeviceState(OnChangedValue value) const
{
    std::string state;
    switch (value) {
        case VALUE_ENTER: {
            state = "enter";
            break;
        }
        case VALUE_EXIT: {
            state = "exit";
            break;
        }
        case VALUE_INVALID: {
            state = "invalid";
            break;
        }
        default: {
            state = "unknown";
            break;
        }
    }
    return state;
}

std::string DeviceStatusDumper::GetStatusType(Type type) const
{
    std::string stateType;
    switch (type) {
        case TYPE_ABSOLUTE_STILL: {
            stateType = "absolute still";
            break;
        }
        case TYPE_HORIZONTAL_POSITION: {
            stateType = "horizontal position";
            break;
        }
        case TYPE_VERTICAL_POSITION: {
            stateType = "vertical position";
            break;
        }
        case TYPE_LID_OPEN: {
            stateType = "lid open";
            break;
        }
        default: {
            stateType = "unknown";
            break;
        }
    }
    return stateType;
}

void DeviceStatusDumper::DumpHelpInfo(int32_t fd) const
{
    dprintf(fd, "Usage:\n");
    dprintf(fd, "      -h: dump help\n");
    dprintf(fd, "      -s: dump the subscribers\n");
    dprintf(fd, "      -l: dump the last 10 device status change\n");
    dprintf(fd, "      -c: dump the current device status\n");
    dprintf(fd, "      -o: dump the coordination status\n");
    dprintf(fd, "      -d: dump the drag status\n");
    dprintf(fd, "      -m, dump the macro state\n");
}

void DeviceStatusDumper::SaveAppInfo(std::shared_ptr<AppInfo> appInfo)
{
    CALL_DEBUG_ENTER;
    CHKPV(appInfo);
    GetTimeStamp(appInfo->startTime);
    std::set<std::shared_ptr<AppInfo>> appInfos;
    std::unique_lock lock(mutex_);
    auto iter = appInfos_.find(appInfo->type);
    if (iter == appInfos_.end()) {
        if (appInfos.insert(appInfo).second) {
            auto [_, ret] = appInfos_.insert(std::make_pair(appInfo->type, appInfos));
            if (!ret) {
                FI_HILOGW("type is duplicated");
            }
        }
    } else {
        if (!appInfos_[iter->first].insert(appInfo).second) {
            FI_HILOGW("appInfo is duplicated");
        }
    }
}

void DeviceStatusDumper::RemoveAppInfo(std::shared_ptr<AppInfo> appInfo)
{
    CALL_DEBUG_ENTER;
    CHKPV(appInfo);
    CHKPV(appInfo->callback);
    std::unique_lock lock(mutex_);
    auto appInfoSetIter = appInfos_.find(appInfo->type);
    if (appInfoSetIter == appInfos_.end()) {
        FI_HILOGE("Not exist %{public}d type appInfo", appInfo->type);
        return;
    }
    FI_HILOGI("callbacklist type:%{public}d, size:%{public}zu, appInfoMap size:%{public}zu",
        appInfo->type, appInfos_[appInfoSetIter->first].size(), appInfos_.size());
    auto iter = appInfos_.find(appInfo->type);
    if (iter == appInfos_.end()) {
        FI_HILOGW("Remove app info is not exists");
        return;
    }
    for (const auto &item : iter->second) {
        if (item->pid == appInfo->pid) {
            iter->second.erase(item);
            break;
        }
    }
}

void DeviceStatusDumper::SaveBoomerangAppInfo(std::shared_ptr<BoomerangAppInfo> appInfo)
{
    CALL_DEBUG_ENTER;
    CHKPV(appInfo);
    GetTimeStamp(appInfo->startTime);
    std::set<std::shared_ptr<BoomerangAppInfo>> appInfos;
    std::unique_lock lock(mutex_);
    auto iter = boomerangAppInfos_.find(appInfo->type);
    if (iter == boomerangAppInfos_.end()) {
        if (appInfos.insert(appInfo).second) {
            auto [_, ret] = boomerangAppInfos_.insert(std::make_pair(appInfo->type, appInfos));
            if (!ret) {
                FI_HILOGW("type is duplicated");
            }
        }
    } else {
        if (!boomerangAppInfos_[iter->first].insert(appInfo).second) {
            FI_HILOGW("appInfo is duplicated");
        }
    }
}
 
void DeviceStatusDumper::SetNotifyMetadatAppInfo(std::shared_ptr<BoomerangAppInfo> appInfo)
{
    CALL_DEBUG_ENTER;
    notifyMetadatAppInfo_ = appInfo;
}
 
void DeviceStatusDumper::RemoveBoomerangAppInfo(std::shared_ptr<BoomerangAppInfo> appInfo)
{
    CALL_DEBUG_ENTER;
    CHKPV(appInfo);
    CHKPV(appInfo->boomerangCallback);
    std::unique_lock lock(mutex_);
    auto appInfoSetIter = boomerangAppInfos_.find(appInfo->type);
    if (appInfoSetIter == boomerangAppInfos_.end()) {
        FI_HILOGE("Not exist %{public}d type boomerangAppInfo", appInfo->type);
        return;
    }
    FI_HILOGI("callbacklist type:%{public}d, size:%{public}zu, boomerangAppInfoMap size:%{public}zu",
        appInfo->type, boomerangAppInfos_[appInfoSetIter->first].size(), boomerangAppInfos_.size());
    auto iter = boomerangAppInfos_.find(appInfo->type);
    if (iter == boomerangAppInfos_.end()) {
        FI_HILOGW("Remove boomerang app info is not exists");
        return;
    }
    for (const auto &item : iter->second) {
        if (item->pid == appInfo->pid) {
            iter->second.erase(item);
            break;
        }
    }
}

void DeviceStatusDumper::PushDeviceStatus(const Data &data)
{
    CALL_DEBUG_ENTER;
    std::unique_lock lock(mutex_);
    auto record = std::make_shared<DeviceStatusRecord>();
    GetTimeStamp(record->startTime);
    record->data = data;
    deviceStatusQueue_.push(record);
    if (deviceStatusQueue_.size() > MAX_DEVICE_STATUS_SIZE) {
        deviceStatusQueue_.pop();
    }
}

std::string DeviceStatusDumper::GetPackageName(Security::AccessToken::AccessTokenID tokenId)
{
    CALL_DEBUG_ENTER;
    std::string packageName = "unknown";
    int32_t tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    switch (tokenType) {
        case Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE: {
            Security::AccessToken::NativeTokenInfo tokenInfo;
            if (Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo) != 0) {
                FI_HILOGE("Get native token info fail");
                return packageName;
            }
            packageName = tokenInfo.processName;
            break;
        }
        case Security::AccessToken::ATokenTypeEnum::TOKEN_HAP: {
            Security::AccessToken::HapTokenInfo hapInfo;
            if (Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapInfo) != RET_OK) {
                FI_HILOGE("Get hap token info fail");
                return packageName;
            }
            packageName = hapInfo.bundleName;
            break;
        }
        default: {
            FI_HILOGW("token type not match");
            break;
        }
    }
    return packageName;
}

void DeviceStatusDumper::DumpCheckDefine(int32_t fd)
{
    ChkDefineOutput(fd);
}

void DeviceStatusDumper::ChkDefineOutput(int32_t fd)
{
    CheckDefineOutput(fd, "Macro switch state:\n");
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    CheckDefineOutput(fd, "%-40s", "OHOS_BUILD_ENABLE_COORDINATION");
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

template<class ...Ts>
void DeviceStatusDumper::CheckDefineOutput(int32_t fd, const char* fmt, Ts... args)
{
    CALL_DEBUG_ENTER;
    CHKPV(fmt);
    char buf[MAX_PACKET_BUF_SIZE] = { 0 };
    int32_t ret = snprintf_s(buf, MAX_PACKET_BUF_SIZE, MAX_PACKET_BUF_SIZE - 1, fmt, args...);
    if (ret == -1) {
        FI_HILOGE("Call snprintf_s failed, ret:%{public}d", ret);
        return;
    }
    dprintf(fd, "%s", buf);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
