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

#include "virtual_device_builder.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <map>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <securec.h>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "if_stream_wrap.h"
#include "napi_constants.h"
#include "utility.h"
#include "virtual_mouse.h"
#include "virtual_touchscreen.h"

#undef LOG_TAG
#define LOG_TAG "VirtualDeviceBuilder"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t MAXIMUM_WAIT_TIME_ALLOWED { 3000 };
constexpr int32_t MINIMUM_WAIT_TIME_ALLOWED { 5 };
constexpr ssize_t MAXIMUM_FILESIZE_ALLOWED { 0x100000 };
constexpr uint64_t DOMAIN_ID { 0xD002220 };
} // namespace

VirtualDeviceBuilder::VirtualDeviceBuilder(const std::string &name, uint16_t bustype,
                                           uint16_t vendor, uint16_t product)
    : uinputDev_ {
        .id = {
            .bustype = bustype,
            .vendor = vendor,
            .product = product,
            .version = 1
        }
    }
{
    if (strcpy_s(uinputDev_.name, sizeof(uinputDev_.name), name.c_str()) != EOK) {
        FI_HILOGE("Invalid device name:\'%{public}s\'", name.c_str());
    }
}

VirtualDeviceBuilder::VirtualDeviceBuilder(const std::string &name, std::shared_ptr<VirtualDevice> vDev) : vDev_(vDev)
{
    CopyProperties(name, vDev);
}

VirtualDeviceBuilder::~VirtualDeviceBuilder()
{
    Close();
}

void VirtualDeviceBuilder::Daemonize()
{
    int32_t fd = fork();
    if (fd < 0) {
        exit(EXIT_FAILURE);
    } else if (fd > 0) {
        exit(EXIT_SUCCESS);
    }
    if (setsid() < 0) {
        exit(EXIT_SUCCESS);
    }
    fd = fork();
    if (fd < 0) {
        exit(EXIT_FAILURE);
    } else if (fd > 0) {
        exit(EXIT_SUCCESS);
    }
    close(STDIN_FILENO);
    fd = open("/dev/null", O_RDWR);
    if (fd != STDIN_FILENO) {
        exit(EXIT_FAILURE);
    }
    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) {
        exit(EXIT_FAILURE);
    }
    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) {
        exit(EXIT_FAILURE);
    }
}

void VirtualDeviceBuilder::ConcatenationName(std::string &sLine)
{
    auto s = sLine.begin();
    while (s != sLine.end() && (isspace(*s) || (*s == '\0'))) {
        s = sLine.erase(s);
    }
    while (s != sLine.end()) {
        while (s != sLine.end() && !isspace(*s) && *s != '\0') {
            ++s;
        }
        auto t = s;
        while (t != sLine.end() && (isspace(*t) || (*t == '\0'))) {
            ++t;
        }
        if (t != sLine.end()) {
            *s++ = '_';
        }
        while (s != sLine.end() && (isspace(*s) || (*s == '\0'))) {
            s = sLine.erase(s);
        }
    }
}

bool VirtualDeviceBuilder::ExecuteUnmount(const char *id, const char *name, const std::string &direntName)
{
    std::ostringstream sPattern;
    sPattern << "^vdevadm_(mount|clone)_-t_?" << id;
    std::regex pattern { sPattern.str() };
    if (!Utility::IsInteger(direntName)) {
        return false;
    }

    std::ostringstream spath;
    spath << "/proc/" << direntName;
    struct stat statBuf;
    if (stat(spath.str().c_str(), &statBuf) != 0) {
        std::cout << "stat \'" << spath.str() << "\' failed: " << strerror(errno) << std::endl;
        return false;
    }
    if (!S_ISDIR(statBuf.st_mode)) {
        return false;
    }
    spath << "/cmdline";
    char realPath[PATH_MAX] = { 0 };
    if (realpath(spath.str().c_str(), realPath) == nullptr) {
        std::cout << "Invalid path" << spath.str().c_str() << std::endl;
        return false;
    }
    IfStreamWrap fileStream;
    fileStream.ifStream = std::ifstream(spath.str(), std::ios::in);
    if (!fileStream.IsOpen()) {
        return false;
    }
    std::string sLine;
    while (std::getline(fileStream.ifStream, sLine)) {
        ConcatenationName(sLine);
        if (std::regex_search(sLine, pattern)) {
            std::cout << "\tfound: \'" << direntName << "\'" << std::endl;
            int32_t pid = std::atoi(direntName.c_str());
            if (kill(static_cast<pid_t>(pid), SIGTERM) != 0) {
                std::cout << "Failed to stop backing process [" << pid << "]: " << strerror(errno) << std::endl;
            } else {
                std::cout << "Unmount virtual " << name << " successfully." << std::endl;
            }
            return true;
        }
    }
    return false;
}

void VirtualDeviceBuilder::Unmount(const char *name, const char *id)
{
    std::cout << "Start to unmount virtual " << name << " ..." << std::endl;
    DIR *procDir = opendir("/proc");
    if (procDir == nullptr) {
        std::cout << "Failed to unmount virtual " << name << ": " << strerror(errno) << std::endl;
        return;
    }

    struct dirent *dent;
    while ((dent = readdir(procDir)) != nullptr) {
        std::string direntName { dent->d_name };
        if (ExecuteUnmount(id, name, direntName)) {
            goto EXIT;
        }
    }
    std::cout << "The backing process for virtual " << name << "can't be found." << std::endl;
EXIT:
    if (closedir(procDir) != 0) {
        FI_HILOGE("closedir error:%{public}s", strerror(errno));
    }
}

void VirtualDeviceBuilder::SetSupportedEvents()
{
    static const std::map<int32_t, std::function<std::vector<uint32_t>()>> uinputTypes {
        { UI_SET_EVBIT, [this] { return this->GetEventTypes(); } },
        { UI_SET_KEYBIT, [this] { return this->GetKeys(); } },
        { UI_SET_PROPBIT, [this] { return this->GetProperties(); } },
        { UI_SET_ABSBIT, [this] { return this->GetAbs(); } },
        { UI_SET_RELBIT, [this] { return this->GetRelBits(); } },
        { UI_SET_MSCBIT, [this] { return this->GetMiscellaneous(); } },
        { UI_SET_LEDBIT, [this] { return this->GetLeds(); } },
        { UI_SET_SWBIT, [this] { return this->GetSwitches(); } },
        { UI_SET_FFBIT, [this] { return this->GetRepeats(); } }
    };

    for (const auto &setEvents : uinputTypes) {
        const auto &events = setEvents.second();
        for (const auto &e : events) {
            if (ioctl(fd_, setEvents.first, e) < 0) {
                FI_HILOGE("Failed while setting event type:%{public}s", strerror(errno));
            }
        }
    }
}

void VirtualDeviceBuilder::SetAbsResolution()
{
    for (const auto &item : absInit_) {
        if (ioctl(fd_, UI_ABS_SETUP, &item) < 0) {
            FI_HILOGE("Failed while setting abs info:%{public}s", strerror(errno));
        }
    }
}

void VirtualDeviceBuilder::SetPhys()
{
    std::string phys;

    if (vDev_ != nullptr) {
        phys = vDev_->GetPhys();
    } else {
        static const std::map<std::string, std::string> mapNames {
            { "Virtual Mouse", "mouse" },
            { "Virtual TouchScreen", "touchscreen" },
            { "Virtual Keyboard", "Keyboard" },
        };
        auto tIter = mapNames.find(std::string(uinputDev_.name));
        if (tIter == mapNames.cend()) {
            FI_HILOGE("Unrecognized device name");
            return;
        }
        phys = tIter->second;
        phys.append("/").append(std::to_string(getpid()));
    }

    if (ioctl(fd_, UI_SET_PHYS, phys.c_str()) < 0) {
        FI_HILOGE("Failed while setting phys:%{public}s", strerror(errno));
    }
}

void VirtualDeviceBuilder::SetIdentity()
{
    if (write(fd_, &uinputDev_, sizeof(uinputDev_)) < 0) {
        FI_HILOGE("Unable to set uinput device info:%{public}s", strerror(errno));
    }
}

bool VirtualDeviceBuilder::SetUp()
{
    CALL_DEBUG_ENTER;
    fd_ = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd_ < 0) {
        FI_HILOGE("Unable to open uinput");
        return false;
    }
    fdsan_exchange_owner_tag(fd_, 0, DOMAIN_ID);
    SetAbsResolution();
    SetPhys();
    SetSupportedEvents();
    SetIdentity();

    if (ioctl(fd_, UI_DEV_CREATE) < 0) {
        FI_HILOGE("Failed to setup uinput device");
        fdsan_close_with_tag(fd_, DOMAIN_ID);
        fd_ = -1;
        return false;
    }
    return true;
}

void VirtualDeviceBuilder::Close()
{
    if (fd_ >= 0) {
        if (ioctl(fd_, UI_DEV_DESTROY) < 0) {
            FI_HILOGE("ioctl error:%{public}s", strerror(errno));
        }
        fdsan_close_with_tag(fd_, DOMAIN_ID);
        fd_ = -1;
    }
}

void VirtualDeviceBuilder::SetResolution(const ResolutionInfo &resolutionInfo)
{
    uinputAbs_.code = resolutionInfo.axisCode;
    uinputAbs_.absinfo.resolution = resolutionInfo.absResolution;
    absInit_.push_back(uinputAbs_);
}

void VirtualDeviceBuilder::SetAbsValue(const AbsInfo &absInfo)
{
    uinputDev_.absmin[absInfo.code] = absInfo.minValue;
    uinputDev_.absmax[absInfo.code] = absInfo.maxValue;
    uinputDev_.absfuzz[absInfo.code] = absInfo.fuzz;
    uinputDev_.absflat[absInfo.code] = absInfo.flat;
}

const std::vector<uint32_t> &VirtualDeviceBuilder::GetEventTypes() const
{
    return eventTypes_;
}

const std::vector<uint32_t> &VirtualDeviceBuilder::GetKeys() const
{
    return keys_;
}

const std::vector<uint32_t> &VirtualDeviceBuilder::GetProperties() const
{
    return properties_;
}

const std::vector<uint32_t> &VirtualDeviceBuilder::GetAbs() const
{
    return abs_;
}

const std::vector<uint32_t> &VirtualDeviceBuilder::GetRelBits() const
{
    return relBits_;
}

const std::vector<uint32_t> &VirtualDeviceBuilder::GetLeds() const
{
    return leds_;
}

const std::vector<uint32_t> &VirtualDeviceBuilder::GetRepeats() const
{
    return repeats_;
}

const std::vector<uint32_t> &VirtualDeviceBuilder::GetMiscellaneous() const
{
    return miscellaneous_;
}

const std::vector<uint32_t> &VirtualDeviceBuilder::GetSwitches() const
{
    return switches_;
}

void VirtualDeviceBuilder::WaitFor(const char *path, const char *name)
{
    CALL_DEBUG_ENTER;
    CHKPV(path);
    if (!Utility::IsInteger(std::string(path))) {
        std::cout << "Invalid argument to \'-w\', time duration of integer type is expected." << std::endl;
        return;
    }
    WaitFor(name, std::atoi(path));
}

void VirtualDeviceBuilder::WaitFor(const char *name, int32_t timeout)
{
    CHKPV(name);
    if (timeout < MINIMUM_WAIT_TIME_ALLOWED) {
        std::cout << "Minimum wait time is " << MINIMUM_WAIT_TIME_ALLOWED << ", no wait." << std::endl;
        return;
    }
    if (timeout > MAXIMUM_WAIT_TIME_ALLOWED) {
        std::cout << "Maximum wait time is " << MAXIMUM_WAIT_TIME_ALLOWED << ", set wait time to this." << std::endl;
        timeout = MAXIMUM_WAIT_TIME_ALLOWED;
    }
    std::cout << "[" << name << "] wait for " << timeout << " milliseconds." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
}

int32_t VirtualDeviceBuilder::ReadFile(const char *path, json &model)
{
    CALL_DEBUG_ENTER;
    CHKPR(path, RET_ERR);
    char realPath[PATH_MAX] {};

    if (realpath(path, realPath) == nullptr) {
        std::cout << "Invalid path: " << path << std::endl;
        return RET_ERR;
    }
    if (Utility::GetFileSize(realPath) > MAXIMUM_FILESIZE_ALLOWED) {
        std::cout << "File is too large" << std::endl;
        return RET_ERR;
    }
    std::cout << "Read input data from \'" << realPath << "\'" << std::endl;
    IfStreamWrap fileStream;
    fileStream.ifStream = std::ifstream(std::string(realPath));
    if (!fileStream.IsOpen()) {
        FI_HILOGE("Could not open the file");
        return RET_ERR;
    }
    model = nlohmann::json::parse(fileStream.ifStream, nullptr, false);
    if (model.is_discarded()) {
        FI_HILOGE("model parse failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t VirtualDeviceBuilder::ScanFor(std::function<bool(std::shared_ptr<VirtualDevice>)> pred,
    std::vector<std::shared_ptr<VirtualDevice>> &vDevs)
{
    CALL_DEBUG_ENTER;
    DIR *dir = opendir(DEV_INPUT_PATH.c_str());
    if (dir == nullptr) {
        FI_HILOGE("Failed to open directory \'%{public}s\':%{public}s", DEV_INPUT_PATH.c_str(), strerror(errno));
        return RET_ERR;
    }
    struct dirent *dent;

    while ((dent = readdir(dir)) != nullptr) {
        const std::string devNode { dent->d_name };
        const std::string devPath { DEV_INPUT_PATH + devNode };
        struct stat statbuf;

        if ((std::strcmp(dent->d_name, ".") == 0) || (std::strcmp(dent->d_name, "..") == 0)) {
            continue;
        }
        if (stat(devPath.c_str(), &statbuf) != 0) {
            continue;
        }
        if (!S_ISCHR(statbuf.st_mode)) {
            continue;
        }
        auto vdev = std::make_shared<VirtualDevice>(devPath);
        if (pred(vdev)) {
            vDevs.push_back(vdev);
        }
    }
    if (closedir(dir) != 0) {
        FI_HILOGE("closedir error:%{public}s", strerror(errno));
    }
    return RET_OK;
}

std::shared_ptr<VirtualDevice> VirtualDeviceBuilder::Select(
    std::vector<std::shared_ptr<VirtualDevice>> &vDevs, const char *name)
{
    CALL_DEBUG_ENTER;
    if (vDevs.empty()) {
        std::cout << "No " << name << "." << std::endl;
        return nullptr;
    }
    auto vDev = vDevs.front();

    if (vDevs.size() > 1) {
        std::cout << "More than one " << name << " were found, please select one to clone:" << std::endl;
        size_t index = 0;

        for (const auto &v : vDevs) {
            std::cout << "[" << index << "]\t" << v->GetName() << std::endl;
            ++index;
        }
        std::cout << "[>=" << index << "]\tQuit" << std::endl;
        std::cin >> index;
        if (index >= vDevs.size()) {
            std::cout << "Selected index is out of range, quit." << std::endl;
            return nullptr;
        }
        vDev = vDevs[index];
    }
    return vDev;
}

void VirtualDeviceBuilder::CopyProperties(const std::string &name, std::shared_ptr<VirtualDevice> vDev)
{
    CHKPV(vDev);
    CopyIdentity(name, vDev);
    CopyAbsInfo(vDev);
    CopyEvents(vDev);
}

void VirtualDeviceBuilder::CopyIdentity(const std::string &name, std::shared_ptr<VirtualDevice> vDev)
{
    CALL_DEBUG_ENTER;
    CHKPV(vDev);
    uinputDev_.id = vDev->GetInputId();
    if (strcpy_s(uinputDev_.name, sizeof(uinputDev_.name), name.c_str()) != EOK) {
        FI_HILOGE("Invalid device name:\'%{public}s\'", name.c_str());
    }
}

void VirtualDeviceBuilder::CopyAbsInfo(std::shared_ptr<VirtualDevice> vDev)
{
    CALL_DEBUG_ENTER;
    CHKPV(vDev);
    for (size_t abs = ABS_X; abs < ABS_CNT; ++abs) {
        struct uinput_abs_setup absSetup {
            .code = static_cast<__u16>(abs),
        };
        if (!vDev->QueryAbsInfo(abs, absSetup.absinfo)) {
            FI_HILOGE("Failed to get abs info for axis %{public}zu", abs);
            continue;
        }
        if (absSetup.absinfo.value == 0 && absSetup.absinfo.minimum == 0 &&
            absSetup.absinfo.maximum <= absSetup.absinfo.minimum && absSetup.absinfo.fuzz == 0 &&
            absSetup.absinfo.flat == 0 && absSetup.absinfo.resolution == 0) {
            continue;
        }
        absInit_.push_back(absSetup);
        uinputDev_.absmin[abs] = absSetup.absinfo.minimum;
        uinputDev_.absmax[abs] = absSetup.absinfo.maximum;
        uinputDev_.absfuzz[abs] = absSetup.absinfo.fuzz;
        uinputDev_.absflat[abs] = absSetup.absinfo.flat;
    }
}

void VirtualDeviceBuilder::CopyEvents(std::shared_ptr<VirtualDevice> vDev)
{
    CALL_DEBUG_ENTER;
    CHKPV(vDev);
    for (uint32_t ev = EV_SYN; ev < EV_MAX; ++ev) {
        if (vDev->SupportEventType(ev)) {
            eventTypes_.push_back(ev);
        }
    }
    for (uint32_t key = KEY_ESC; key < KEY_MAX; ++key) {
        if (vDev->SupportKey(key)) {
            keys_.push_back(key);
        }
    }
    for (uint32_t abs = ABS_X; abs < ABS_MAX; ++abs) {
        if (vDev->SupportAbs(abs)) {
            abs_.push_back(abs);
        }
    }
    for (uint32_t rel = REL_X; rel < REL_MAX; ++rel) {
        if (vDev->SupportRel(rel)) {
            relBits_.push_back(rel);
        }
    }
    for (uint32_t msc = MSC_SERIAL; msc < MSC_MAX; ++msc) {
        if (vDev->SupportMsc(msc)) {
            miscellaneous_.push_back(msc);
        }
    }
    for (uint32_t led = LED_NUML; led < LED_MAX; ++led) {
        if (vDev->SupportLed(led)) {
            leds_.push_back(led);
        }
    }
    for (uint32_t rep = REP_DELAY; rep < REP_MAX; ++rep) {
        if (vDev->SupportRep(rep)) {
            repeats_.push_back(rep);
        }
    }
    for (uint32_t prop = INPUT_PROP_POINTER; prop < INPUT_PROP_MAX; ++prop) {
        if (vDev->SupportProperty(prop)) {
            properties_.push_back(prop);
        }
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS