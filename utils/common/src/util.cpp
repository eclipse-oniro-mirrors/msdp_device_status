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

#include "include/util.h"

#include <regex>
#include <string>

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#include <sys/prctl.h>
#endif // OHOS_BUILD_ENABLE_ARKUI_X
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#include "parameters.h"
#endif // OHOS_BUILD_ENABLE_ARKUI_X
#include "securec.h"

#include "devicestatus_define.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "Util"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t BUF_TID_SIZE { 10 };
constexpr size_t PROGRAM_NAME_SIZE { 256 };
constexpr size_t BUF_CMD_SIZE { 512 };
constexpr uint32_t BASE_YEAR { 1900 };
constexpr uint32_t BASE_MON { 1 };
constexpr uint32_t MS_NS { 1000000 };
constexpr int32_t FILE_SIZE_MAX { 0x5000 };
constexpr size_t SHORT_KEY_LENGTH { 20 };
constexpr size_t PLAINTEXT_LENGTH { 4 };
constexpr int32_t ROTATE_POLICY_WINDOW_ROTATE { 0 };
constexpr int32_t ROTATE_POLICY_SCREEN_ROTATE { 1 };
constexpr int32_t ROTATE_POLICY_FOLD_MODE { 2 };
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
const int32_t ROTATE_POLICY = OHOS::system::GetIntParameter("const.window.device.rotate_policy", 0);
const std::string FOLD_ROTATE_POLICY = OHOS::system::GetParameter("const.window.foldabledevice.rotate_policy", "0,0");
const std::string FOLD_SCREEN_TYPE = OHOS::system::GetParameter("const.window.foldscreen.type", "0,0,0,0");
const std::string SECONDARY_FOLD_DISPLAY = "6";
#endif // OHOS_BUILD_ENABLE_ARKUI_X
const std::string SVG_PATH { "/system/etc/device_status/drag_icon/" };
} // namespace

int32_t GetPid()
{
    return static_cast<int32_t>(getpid());
}

static std::string GetThisThreadIdOfString()
{
    thread_local std::string threadLocalId;
    if (threadLocalId.empty()) {
        long tid = syscall(SYS_gettid);
        char buf[BUF_TID_SIZE] = { 0 };
        const int32_t ret = sprintf_s(buf, BUF_TID_SIZE, "%06d", tid);
        if (ret < 0) {
            FI_HILOGE("Call sprintf_s failed, ret:%{public}d", ret);
            return threadLocalId;
        }
        buf[BUF_TID_SIZE - 1] = '\0';
        threadLocalId = buf;
    }
    return threadLocalId;
}

uint64_t GetThisThreadId()
{
    std::string threadId = GetThisThreadIdOfString();
    uint64_t tid = std::stoull(threadId);
    return tid;
}

int64_t GetMillisTime()
{
    auto timeNow = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(timeNow.time_since_epoch());
    return tmp.count();
}

void GetTimeStamp(std::string &startTime)
{
    timespec curTime;
    clock_gettime(CLOCK_REALTIME, &curTime);
    struct tm *timeinfo = localtime(&(curTime.tv_sec));
    CHKPV(timeinfo);
    startTime.append(std::to_string(timeinfo->tm_year + BASE_YEAR)).append("-")
        .append(std::to_string(timeinfo->tm_mon + BASE_MON)).append("-").append(std::to_string(timeinfo->tm_mday))
        .append(" ").append(std::to_string(timeinfo->tm_hour)).append(":").append(std::to_string(timeinfo->tm_min))
        .append(":").append(std::to_string(timeinfo->tm_sec)).append(".")
        .append(std::to_string(curTime.tv_nsec / MS_NS));
}

void SetThreadName(const std::string &name)
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    prctl(PR_SET_NAME, name.c_str());
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}

static size_t StringToken(std::string &strs, const std::string &sep, std::string &token)
{
    token = "";
    if (strs.empty()) {
        return strs.npos;
    }
    size_t seat = strs.npos;
    size_t temp = 0;
    for (auto &item : sep) {
        temp = strs.find(item);
        if (strs.npos != temp) {
            seat = (std::min)(seat, temp);
        }
    }
    if (strs.npos != seat) {
        token = strs.substr(0, seat);
        if (strs.npos != seat + 1) {
            strs = strs.substr(seat + 1, strs.npos);
        }
        if (seat == 0) {
            return StringToken(strs, sep, token);
        }
    } else {
        token = strs;
        strs = "";
    }
    return token.size();
}

size_t StringSplit(const std::string &str, const std::string &sep, std::vector<std::string> &vecList)
{
    size_t size = 0;
    auto strs = str;
    std::string token;
    while (str.npos != (size = StringToken(strs, sep, token))) {
        vecList.push_back(token);
    }
    return vecList.size();
}

std::string StringPrintf(const char *format, ...)
{
    char space[1024] { 0 };

    va_list ap;
    va_start(ap, format);
    std::string result;
    int32_t ret = vsnprintf_s(space, sizeof(space), sizeof(space) - 1, format, ap);
    if (ret >= RET_OK && static_cast<size_t>(ret) < sizeof(space)) {
        result = space;
    } else {
        FI_HILOGE("The buffer is overflow");
    }
    va_end(ap);
    return result;
}

std::string GetAnonyString(const std::string &value)
{
    if (value.empty()) {
        return "empty";
    }
    std::string anonyStr = "******";
    std::string str;
    size_t strLen = value.length();
    if (strLen == 0) {
        FI_HILOGE("strLen is 0, value will overflow");
        return "empty";
    } else if (strLen <= SHORT_KEY_LENGTH) {
        str += value[0];
        str += anonyStr;
        str += value[strLen - 1];
    } else {
        str.append(value, 0, PLAINTEXT_LENGTH);
        str += anonyStr;
        str.append(value, strLen - PLAINTEXT_LENGTH, PLAINTEXT_LENGTH);
    }
    return str;
}

static std::string GetFileName(const std::string &path)
{
    size_t nPos = path.find_last_of('/');
    if (path.npos == nPos) {
        nPos = path.find_last_of('\\');
    }
    if (path.npos == nPos) {
        return path;
    }
    return path.substr(nPos + 1, path.npos);
}

const char* GetProgramName()
{
    static char programName[PROGRAM_NAME_SIZE] = { 0 };
    if (programName[0] != '\0') {
        return programName;
    }

    char buf[BUF_CMD_SIZE] = { 0 };
    int32_t ret = sprintf_s(buf, BUF_CMD_SIZE, "/proc/%d/cmdline", static_cast<int32_t>(getpid()));
    if (ret == -1) {
        FI_HILOGE("GetProcessInfo sprintf_s cmdline error");
        return "";
    }
    FILE *fp = fopen(buf, "rb");
    if (fp == nullptr) {
        FI_HILOGE("The fp is nullptr, filename:%{public}s", buf);
        return "";
    }
    static constexpr size_t bufLineSize = 512;
    char bufLine[bufLineSize] = { 0 };
    if ((fgets(bufLine, bufLineSize, fp) == nullptr)) {
        FI_HILOGE("fgets failed");
        if (fclose(fp) != 0) {
            FI_HILOGW("Close file failed");
        }
        fp = nullptr;
        return "";
    }
    if (fclose(fp) != 0) {
        FI_HILOGW("Close file:%{public}s failed", buf);
    }
    fp = nullptr;

    std::string tempName(bufLine);
    tempName = GetFileName(tempName);
    if (tempName.empty()) {
        FI_HILOGE("tempName is empty");
        return "";
    }
    size_t copySize = std::min(tempName.size(), PROGRAM_NAME_SIZE - 1);
    if (copySize == 0) {
        FI_HILOGE("The copySize is 0");
        return "";
    }
    errno_t result = memcpy_s(programName, PROGRAM_NAME_SIZE, tempName.c_str(), copySize);
    if (result != EOK) {
        FI_HILOGE("memcpy_s failed");
        return "";
    }
    FI_HILOGI("Get program name success, programName:%{public}s", programName);

    return programName;
}

bool CheckFileExtendName(const std::string &filePath, const std::string &checkExtension)
{
    std::string::size_type pos = filePath.find_last_of('.');
    if (pos == std::string::npos) {
        FI_HILOGE("File is not found extension");
        return false;
    }
    return (filePath.substr(pos + 1, filePath.npos) == checkExtension);
}

bool IsValidPath(const std::string &rootDir, const std::string &filePath)
{
    return (filePath.compare(0, rootDir.size(), rootDir) == 0);
}

bool IsValidSvgPath(const std::string &filePath)
{
    return IsValidPath(SVG_PATH, filePath);
}

bool IsValidSvgFile(const std::string &filePath)
{
    CALL_DEBUG_ENTER;
    if (filePath.empty()) {
        FI_HILOGE("FilePath is empty");
        return false;
    }
    char realPath[PATH_MAX] = { 0 };
    if (realpath(filePath.c_str(), realPath) == nullptr) {
        FI_HILOGE("Realpath return nullptr, realPath:%{private}s", realPath);
        return false;
    }
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (!IsValidSvgPath(realPath)) {
        FI_HILOGE("File path invalid");
        return false;
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    if (!Utility::DoesFileExist(realPath)) {
        FI_HILOGE("File not exist");
        return false;
    }
    if (!CheckFileExtendName(realPath, "svg")) {
        FI_HILOGE("Unable to parse files other than svg format");
        return false;
    }
    int32_t fileSize = Utility::GetFileSize(realPath);
    if ((fileSize <= 0) || (fileSize > FILE_SIZE_MAX)) {
        FI_HILOGE("File size out of read range");
        return false;
    }
    return true;
}

bool IsNum(const std::string &str)
{
    std::istringstream sin(str);
    double num = 0.0;
    return (sin >> num) && sin.eof();
}

void GetRotatePolicy(bool &isScreenRotation, std::vector<std::string> &foldRotatePolicys)
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    if (ROTATE_POLICY == ROTATE_POLICY_WINDOW_ROTATE) {
        isScreenRotation = false;
        return;
    }
    if (ROTATE_POLICY == ROTATE_POLICY_SCREEN_ROTATE) {
        isScreenRotation = true;
        return;
    }
    if (ROTATE_POLICY == ROTATE_POLICY_FOLD_MODE) {
        isScreenRotation = false;
        StringSplit(FOLD_ROTATE_POLICY, ",", foldRotatePolicys);
        return;
    }
#endif // OHOS_BUILD_ENABLE_ARKUI_X
}

std::vector<std::string> StringSplit(const std::string& str, char delim)
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    std::size_t previous = 0;
    std::size_t current = str.find(delim);
    std::vector<std::string> elems;
    while (current != std::string::npos) {
        if (current > previous) {
            elems.push_back(str.substr(previous, current - previous));
        }
        previous = current + 1;
        current = str.find(delim, previous);
    }
    if (previous != str.size()) {
        elems.push_back(str.substr(previous));
    }
    return elems;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    return {};
}

bool IsSecondaryDevice()
{
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
    std::regex reg("^([0-9],){3}[0-9]{1}$");
    if (!std::regex_match(FOLD_SCREEN_TYPE, reg)) {
        return false;
    }
    std::vector<std::string> foldTypes = StringSplit(FOLD_SCREEN_TYPE, ',');
    if (foldTypes.empty()) {
        return false;
    }
    return foldTypes[0] == SECONDARY_FOLD_DISPLAY;
#endif // OHOS_BUILD_ENABLE_ARKUI_X
    return false;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS