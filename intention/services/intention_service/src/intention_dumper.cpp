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

#include "intention_dumper.h"

#include <getopt.h>
#include <securec.h>

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "IntentionDumper"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
void IntentionDumper::Dump(int32_t fd, const std::vector<std::string> &args)
{
    constexpr size_t bufSize { 1024 };
    char buf[bufSize] { "hidumper" };

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
        { "drag", no_argument, nullptr, 'd' },
        { "macroState", no_argument, nullptr, 'm' },
        { nullptr, 0, nullptr, 0 }
    };
    optind = 0;
    int32_t opt = -1;

    while ((opt = getopt_long(argv.size(), argv.data(), "+hslcdm", dumpOptions, nullptr)) >= 0) {
        DumpOnce(fd, opt);
    }
}

void IntentionDumper::DumpOnce(int32_t fd, int32_t option)
{
    switch (option) {
        case 's': {
            DumpDeviceStatusSubscriber(fd);
            break;
        }
        case 'l': {
            DumpDeviceStatusChanges(fd);
            break;
        }
        case 'c': {
            DumpCurrentDeviceStatus(fd);
            break;
        }
        case 'd': {
            DumpDrag(fd);
            break;
        }
        case 'm': {
            DumpCheckDefine(fd);
            break;
        }
        default: {
            DumpHelpInfo(fd);
            break;
        }
    }
}

void IntentionDumper::DumpHelpInfo(int32_t fd) const
{
    dprintf(fd, "Usage:\n");
    dprintf(fd, "\t-h\t\tdump help\n");
    dprintf(fd, "\t-s\t\tdump the subscribers\n");
    dprintf(fd, "\t-l\t\tdump the last 10 device status change\n");
    dprintf(fd, "\t-c\t\tdump the current device status\n");
    dprintf(fd, "\t-d\t\tdump the drag status\n");
    dprintf(fd, "\t-m\t\tdump the macro state\n");
}

void IntentionDumper::DumpDeviceStatusSubscriber(int32_t fd) const
{
    CHKPV(env_);
    FI_HILOGI("Dump subscribers of device status");
    int32_t ret = env_->GetDelegateTasks().PostSyncTask([this, fd] {
        stationary_.DumpDeviceStatusSubscriber(fd);
        return RET_OK;
    });
    if (ret != RET_OK) {
        FI_HILOGE("IDelegateTasks::PostSyncTask fail, error:%{public}d", ret);
    }
}

void IntentionDumper::DumpDeviceStatusChanges(int32_t fd) const
{
    CHKPV(env_);
    FI_HILOGI("Dump changes of device status");
    int32_t ret = env_->GetDelegateTasks().PostSyncTask([this, fd] {
        stationary_.DumpDeviceStatusChanges(fd);
        return RET_OK;
    });
    if (ret != RET_OK) {
        FI_HILOGE("IDelegateTasks::PostSyncTask fail, error:%{public}d", ret);
    }
}

void IntentionDumper::DumpCurrentDeviceStatus(int32_t fd)
{
    CHKPV(env_);
    FI_HILOGI("Dump current device status");
    int32_t ret = env_->GetDelegateTasks().PostSyncTask([this, fd] {
        stationary_.DumpDeviceStatusChanges(fd);
        return RET_OK;
    });
    if (ret != RET_OK) {
        FI_HILOGE("IDelegateTasks::PostSyncTask fail, error:%{public}d", ret);
    }
}

void IntentionDumper::DumpDrag(int32_t fd) const
{
    CHKPV(env_);
    FI_HILOGI("Dump drag information");
    int32_t ret = env_->GetDelegateTasks().PostSyncTask([env = env_, fd] {
        env->GetDragManager().Dump(fd);
        return RET_OK;
    });
    if (ret != RET_OK) {
        FI_HILOGE("IDelegateTasks::PostSyncTask fail, error:%{public}d", ret);
    }
}

void IntentionDumper::DumpCheckDefine(int32_t fd) const
{
    CheckDefineOutput(fd, "Macro switch state:\n");
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    CheckDefineOutput(fd, "\t%s\n", "OHOS_BUILD_ENABLE_COORDINATION");
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

template<class ...Ts>
void IntentionDumper::CheckDefineOutput(int32_t fd, const char* fmt, Ts... args) const
{
    char buf[MAX_PACKET_BUF_SIZE] {};
    int32_t ret = snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, fmt, args...);
    if (ret < 0) {
        FI_HILOGE("snprintf_s fail, error:%{public}d", ret);
        return;
    }
    dprintf(fd, "%s", buf);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
